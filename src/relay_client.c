#include "main.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#include <curl/curl.h>
#include <curl/easy.h>

// Per-request context — replaces former static globals to support concurrent sessions.
typedef struct {
    char *req_handle;
    http_sse_s *hssi;
    char *user_token;
    char *bucket_id;
    FIOBJ session_container;
    volatile intptr_t fd;
} relay_context_t;

fio_lock_i lock, redis_lock, dwn_lock, tool_call_lock;

void is_tool_header_present(http_s *h, char **toolname)
{
    FIOBJ headers = h->headers;
    FIOBJ r = http_req2str(h);
    log_debug("TOOL-REQ: %s", fiobj_obj2cstr(r).data);
    FIOBJ tool_header_key = fiobj_str_new("x-tool", 6);
    int is_present = fiobj_hash_haskey(headers, tool_header_key);
    log_debug("TOOL-HDR: %d", is_present);
    if (is_present)
    {
        FIOBJ tool_header_value = fiobj_hash_get(headers, tool_header_key);
        if (fiobj_type_is(tool_header_value, FIOBJ_T_STRING) == 1)
        {
            char *tool_header_value_str = fiobj_obj2cstr(tool_header_value).data;
            log_debug("TOOL-HDR-VAL: %s", tool_header_value_str);
            *toolname = malloc(strlen(tool_header_value_str) + 1);
            if (*toolname != NULL)
            {
                strcpy(*toolname, tool_header_value_str);
                log_debug("TOOL-NAME-R: %s", *toolname);
            }
            else
            {
                log_error("MEM-ALLOC-FAIL");
            }
        }
        // Don't free tool_header_value — it's a reference into the headers hash (not dup'd)
    }
    fiobj_free(tool_header_key);
}

static bool handle_tool_calls_from_response(const char *response_data, size_t response_len, relay_context_t *ctx);
char* extract_header(http_s *h, char *header_name, size_t header_name_len);

static relay_context_t *ctx_from_udata(http_s *h) {
    FIOBJ container = *((FIOBJ *)h->udata);
    return (relay_context_t *)fiobj_ptr_unwrap(
        fiobj_hash_get(container, fiobj_str_new("ctx", 3)));
}

void *parse_chunked_response(void *arg)
{
    relay_context_t *ctx = (relay_context_t *)arg;
    char *ptid = malloc(16);
    sprintf(ptid, "%s", "chunked_handler");
    ssize_t safe_gauge = 0;
    char *buffer = calloc(CHUNK_BUFFER_SIZE, 1);
    if (!buffer) {
        log_error("Failed to allocate chunk buffer");
        return ptid;
    }
    ssize_t len = 0;

    while (true)
    {
        len = fio_read(ctx->fd, buffer, CHUNK_BUFFER_SIZE);
        if (len > 0)
        {
            char *buffcpy = malloc(len + 1);
            memcpy(buffcpy, buffer, len);
            buffcpy[len] = '\0';
            char *buffcpy_orig = buffcpy;
            safe_gauge = len;
            if (ctx->hssi != NULL)
            {
                char *read = NULL;
                while ((read = read_until_delim(&buffcpy, '{', '\r')) != NULL)
                {
                    log_debug("HTTP-RELAY::STREAM::READ: %s", read);

                    if (1 == contains_substring(read, "\"tool_calls\""))
                    {
                        log_debug("HTTP-RELAY::STREAM::TOOL_CALLS detected");
                        handle_tool_calls_from_response(read, strlen(read), ctx);
                        log_debug("HTTP-RELAY::STREAM::HALT (tool call handled)");
                        free(read);
                        free(buffcpy_orig);
                        free(buffer);
                        return ptid;
                    }
                    http_sse_write(ctx->hssi, .id = {.data = ctx->hssi->udata, .len = strlen(ctx->hssi->udata)}, .data = {.data = read, .len = strlen(read)}, .event = {.data = "usermessage-chk", .len = 15});
                    free(read);
                }
                log_debug("HTTP-RELAY::STREAM::HALT");
            }
            free(buffcpy_orig);
            memset(buffer, 0, CHUNK_BUFFER_SIZE);
        }
        else if (len < 0)
        {
            log_debug("HTTP-RELAY::STREAM::CONNECTION_CLOSED");
            break;
        }
        else if (safe_gauge == 0)
        {
            usleep(1000);
        }
    }
    free(buffer);
    return ptid;
}

static void on_tool_call(http_s *h)
{
    relay_context_t *ctx = ctx_from_udata(h);
    if (h->status_str == FIOBJ_INVALID)
    {
        FIOBJ container = *((FIOBJ *)h->udata);
        FIOBJ content = fiobj_str_new("content", 7);
        FIOBJ name = fiobj_str_new("tool_name", 9);
        FIOBJ fcall_key = fiobj_str_new("fcall", 4);
        FIOBJ fcall = fiobj_hash_get(container, fcall_key);
        fio_str_info_s content_info = fiobj_obj2cstr(fiobj_hash_get(container, content));
        fio_str_info_s name_info = fiobj_obj2cstr(fiobj_hash_get(container, name));
        FIOBJ opt_temp = fiobj_num_new((intptr_t)0);
        log_debug("REQ-TOOLS-CALL: %s", ctx->req_handle);
        bool opts_set = set_llm_req_opt("temperature", opt_temp, &ctx->req_handle);
        log_debug("REQ-TOOLS-CALL-OPT-SET: %s", ctx->req_handle);
        if (opts_set == true)
        {
            log_debug("Opts set");
        }
        else
        {
            log_debug("Opts not set");
        }
        FIOBJ valid_tmp = FIOBJ_INVALID;
        size_t consumed = fiobj_json2obj(&valid_tmp, content_info.data, content_info.len);
        // If there is more than 0 consumed bytes, it means that this is a valid JSON so, just pass it over.
        if (consumed > 0)
        {
            log_debug("Passing over the tool response as datamessage");
            http_sse_write(ctx->hssi, .id = {.data = ctx->hssi->udata, .len = strlen(ctx->hssi->udata)}, .data = content_info, .event = {.data = DATA_MSG, .len = strlen(DATA_MSG)});
            fiobj_free(content);
            fiobj_free(name);
            fiobj_free(fcall_key);
            return;
        }
        // Build tool response JSON safely using FIOBJ to handle escaping
        FIOBJ toolssec = fiobj_hash_new();
        fiobj_hash_set(toolssec, fiobj_str_new("role", 4), fiobj_str_new("tool", 4));
        fiobj_hash_set(toolssec, fiobj_str_new("name", 4), fiobj_str_new(name_info.data, name_info.len));
        fiobj_hash_set(toolssec, fiobj_str_new("content", 7), fiobj_str_new(content_info.data, content_info.len));
        log_debug("TOOL-SEC: %s", fiobj_obj2cstr(fiobj_obj2json(toolssec, 0)).data);
        update_curr_req_handle_messages(fcall, &ctx->req_handle);
        update_curr_req_handle_messages(toolssec, &ctx->req_handle);
        log_debug("URH: %s", ctx->req_handle);
        h->method = fiobj_str_new("POST", 4);
        log_debug("FR: %s", ctx->req_handle);
        http_send_body(h, ctx->req_handle, strlen(ctx->req_handle));
        fiobj_free(content);
        fiobj_free(name);
        fiobj_free(fcall_key);
        return;
    }
    FIOBJ ollama_res = h->body;
    fio_str_info_s ollama_res_s = fiobj_obj2cstr(ollama_res);
    log_debug(ollama_res_s.data);
    FIOBJ resp_parsed = FIOBJ_INVALID;
    fiobj_json2obj(&resp_parsed, ollama_res_s.data, ollama_res_s.len);
    FIOBJ errkey = fiobj_str_new("error", 5);

    if (fiobj_type_is(resp_parsed, FIOBJ_T_HASH) == 1 && fiobj_hash_haskey(resp_parsed, errkey) == 1)
    {
        FIOBJ errpayload = fiobj_hash_get(resp_parsed, errkey);
        http_sse_write(ctx->hssi, .id = {.data = ctx->hssi->udata, .len = strlen(ctx->hssi->udata)}, .data = fiobj_obj2cstr(errpayload), .event = {.data = CTL_MSG, .len = strlen(CTL_MSG)});
        return;
    }
    FIOBJ message = fiobj_hash_get(resp_parsed, fiobj_str_new("message", 7));
    FIOBJ content = fiobj_hash_get(message, fiobj_str_new("content", 7));
    fio_str_info_s content_s = fiobj_obj2cstr(content);
    if (content_s.len == 0)
    {
        FIOBJ ctlmessage_empty_resp = fiobj_str_new("EMPTY RESP", 10);
        http_sse_write(ctx->hssi, .id = {.data = ctx->hssi->udata, .len = strlen(ctx->hssi->udata)}, .data = fiobj_obj2cstr(ctlmessage_empty_resp), .event = {.data = CTL_MSG, .len = strlen(CTL_MSG)});
        fiobj_free(ctlmessage_empty_resp);
        fiobj_free(resp_parsed);
        return;
    }
    if (ollama_res_s.len > 0)
    {
        FIOBJ test_holder = FIOBJ_INVALID;
        size_t consumed = fiobj_json2obj(&test_holder, content_s.data, content_s.len);
        // 0 bytes consumed, that means that whatever LLM returned is not a JSON, just pass it over
        if (consumed == 0)
        {
            http_sse_write(ctx->hssi, .id = {.data = ctx->hssi->udata, .len = strlen(ctx->hssi->udata)}, .data = ollama_res_s, .event = {.data = "usermessage", .len = 11});
        }
        // Handle JSON response?
    }
}

/**
 * Checks the LLM response for tool_calls and executes them if found.
 * Forces stream:false on req_handle for the follow-up request to Ollama.
 *
 * @return true if tool_calls were present and handled, false otherwise.
 */
static bool handle_tool_calls_from_response(const char *response_data, size_t response_len, relay_context_t *ctx)
{
    FIOBJ ollama_response_obj = FIOBJ_INVALID;
    fiobj_json2obj(&ollama_response_obj, response_data, response_len);

    if (fiobj_type_is(ollama_response_obj, FIOBJ_T_HASH) != 1)
    {
        fiobj_free(ollama_response_obj);
        return false;
    }

    FIOBJ message_key = fiobj_str_new("message", 7);
    FIOBJ tool_calls_key = fiobj_str_new("tool_calls", 10);

    FIOBJ message = fiobj_hash_get(ollama_response_obj, message_key);
    if (fiobj_type_is(message, FIOBJ_T_HASH) != 1 || fiobj_hash_haskey(message, tool_calls_key) != 1)
    {
        fiobj_free(message_key);
        fiobj_free(tool_calls_key);
        return false;
    }

    // Force stream:false for the tool result follow-up to Ollama
    FIOBJ req_obj = FIOBJ_INVALID;
    fiobj_json2obj(&req_obj, ctx->req_handle, strlen(ctx->req_handle));
    FIOBJ stream_key = fiobj_str_new("stream", 6);
    fiobj_hash_set(req_obj, stream_key, fiobj_false());
    FIOBJ req_json = fiobj_obj2json(req_obj, 0);
    ctx->req_handle = fiobj_obj2cstr(req_json).data;

    FIOBJ fcalls = fiobj_hash_get(message, tool_calls_key);
    if (fcalls == FIOBJ_INVALID || fiobj_type_is(fcalls, FIOBJ_T_ARRAY) != 1)
    {
        log_error("TOOL_CALLS: invalid or missing tool_calls array");
        fiobj_free(message_key);
        fiobj_free(tool_calls_key);
        return false;
    }
    fio_trylock(&tool_call_lock);
    for (size_t i = 0; i < fiobj_ary_count(fcalls); i++)
    {
        FIOBJ fcall = fiobj_ary_index(fcalls, i);
        FIOBJ fkey = fiobj_str_new("function", 8);
        FIOBJ argkey = fiobj_str_new("arguments", 9);
        FIOBJ func = fiobj_hash_get(fcall, fkey);
        if (func == FIOBJ_INVALID || fiobj_type_is(func, FIOBJ_T_HASH) != 1)
        {
            log_error("TOOL_CALLS: invalid function object at index %zu", i);
            fiobj_free(fkey);
            fiobj_free(argkey);
            continue;
        }
        FIOBJ fnamekey = fiobj_str_new("name", 4);
        FIOBJ fname = fiobj_hash_get(func, fnamekey);
        FIOBJ args = fiobj_hash_get(func, argkey);

        FIOBJ cmds = fiobj_hash_get(ctx->session_container, fiobj_str_new("cmds", 4));

        if (cmds == FIOBJ_INVALID)
        {
            log_error("No cmds key in session container");
            http_sse_write(ctx->hssi, .id = {.data = ctx->hssi->udata, .len = strlen(ctx->hssi->udata)}, .data = fiobj_obj2cstr(fiobj_str_new("NO-CMDS", 7)), .event = {.data = USR_MSG, .len = strlen(USR_MSG)});
            fiobj_free(fkey);
            fiobj_free(fnamekey);
            fiobj_free(message_key);
            fiobj_free(tool_calls_key);
            return true;
        }
        for (size_t j = 0; j < fiobj_ary_count(cmds); j++)
        {
            FIOBJ cmd = fiobj_ary_index(cmds, (int64_t)j);
            FIOBJ tool_engine = fiobj_hash_get(cmd, fiobj_str_new("tool_engine", 11));
            char *tool_engine_str = fiobj_obj2cstr(tool_engine).data;
            char *curr_tool_name = fiobj_obj2cstr(fiobj_hash_get(cmd, fnamekey)).data;
            if (strcmp(curr_tool_name, fiobj_obj2cstr(fname).data) == 0)
            {
                char *params = malloc(16384);
                memset(params, 0, 16384);
                parse_arguments_hash(args, params);
                // Check requires_authorization flag on the tool
                FIOBJ req_auth_key = fiobj_str_new("requires_authorization", 22);
                FIOBJ req_auth_val = fiobj_hash_get(cmd, req_auth_key);
                if (req_auth_val != FIOBJ_INVALID && fiobj_true() == req_auth_val && ctx->user_token != NULL)
                {
                    log_debug("TOOL-REQ-AUTH: appending options for %s", curr_tool_name);
                    char options_param[8192];
                    if (ctx->bucket_id != NULL) {
                        snprintf(options_param, sizeof(options_param), "'{\"user_token\":\"%s\",\"bucket_id\":\"%s\"}'" , ctx->user_token, ctx->bucket_id);
                    } else {
                        snprintf(options_param, sizeof(options_param), "'{\"user_token\":\"%s\"}'" , ctx->user_token);
                    }
                    strcat(params, options_param);
                    strcat(params, " ");
                }
                fiobj_free(req_auth_key);
                log_debug("%s : %s", curr_tool_name, fiobj_obj2cstr(fname).data);
                char *output = malloc(16384);
                memset(output, 0, 16384);
                execute_tool(&output, tool_engine_str, curr_tool_name, params, &tool_call_lock);
                await_for_lock(&tool_call_lock);
                fio_str_info_s await_tool_call = fiobj_obj2cstr(fiobj_str_new("await tool call", 15));
                http_sse_write(ctx->hssi, .id = {.data = ctx->hssi->udata, .len = strlen(ctx->hssi->udata)}, .data = await_tool_call, .event = {.data = "ctlmessage", .len = 10});
                FIOBJ container = fiobj_hash_new();
                fiobj_hash_set(container, fiobj_str_new("hssi", 4), fiobj_ptr_wrap(ctx->hssi));
                fiobj_hash_set(container, fiobj_str_new("tool_name", 9), fiobj_str_new(curr_tool_name, strlen(curr_tool_name)));
                fiobj_hash_set(container, fiobj_str_new("content", 7), fiobj_str_new(output, strlen(output)));
                fiobj_hash_set(container, fiobj_str_new("fcall", 4), message);
                // Propagate per-request context to the tool-call follow-up
                fiobj_hash_set(container, fiobj_str_new("ctx", 3), fiobj_ptr_wrap(ctx));
                FIOBJ *contain_ptr = fio_malloc(sizeof(*contain_ptr));
                *contain_ptr = container;
                http_connect(OLLAMA_CHAT_ENDPOINT, NULL, .on_response = on_tool_call, .udata = contain_ptr);
                log_debug("%s", "RELAY-OK");
                free(output);
                free(params);
                break;
            }
        }
        fiobj_free(fkey);
        fiobj_free(fnamekey);
    }
    fiobj_free(message_key);
    fiobj_free(tool_calls_key);
    return true;
}

static void on_response(http_s *h)
{
    relay_context_t *ctx = ctx_from_udata(h);
    if (h->status_str == FIOBJ_INVALID)
    {
        h->method = fiobj_str_new("POST", 4);
        FIOBJ data_container = *((FIOBJ *)h->udata);
        FIOBJ session_container = fiobj_hash_get(data_container, fiobj_str_new("session_container", 17));
        char* toolname = fiobj_ptr_unwrap(fiobj_hash_get(data_container, fiobj_str_new("tool_name", 9)));
        ctx->session_container = fiobj_dup(session_container);
        char* token = fiobj_ptr_unwrap(fiobj_hash_get(data_container, fiobj_str_new("token", 5)));
        log_debug("TOKEN: %s", token);
        if (token != NULL) {
            ctx->user_token = strdup(token);
        }
        char* bucket_id = fiobj_ptr_unwrap(fiobj_hash_get(data_container, fiobj_str_new("bucket_id", 9)));
        if (bucket_id != NULL) {
            ctx->bucket_id = strdup(bucket_id);
        }
        log_debug("SESSION-CONT-KEY_COUNT: %d", fiobj_hash_count(ctx->session_container));
        ctx->hssi = (http_sse_s *)fiobj_ptr_unwrap(fiobj_hash_get(data_container, fiobj_str_new("hssi", 4)));
        apnd_syssec2req(ctx->session_container, &ctx->req_handle);
        char *model = malloc(MODEL_NAME_L);
        memset(model, 0, MODEL_NAME_L);
        extract_model(&model, ctx->req_handle);
        log_debug("Model: %s", model);
        if (toolname != NULL || supports_tools(model) == true)
        {
            log_debug("%s supports tools (or tool explicitly requested: %s)", model, toolname);
            log_debug("TOOL-RQST: %s", toolname);

            apnd_toolsec2req(ctx->session_container, &ctx->req_handle, toolname, token);
        }
        char *is_stream_request = strstr(ctx->req_handle, "\"stream\":false");
        http_send_body(h, ctx->req_handle, strlen(ctx->req_handle));
        if (is_stream_request == NULL)
        {
            log_debug("R: %s", ctx->req_handle);
            ctx->fd = http_hijack(h, NULL);
            fio_thread_new(&parse_chunked_response, ctx);
        }
        free(token);
        return;
    }

    log_debug("FD: %d", ctx->fd);

    fio_str_info_s ollama_res = fiobj_obj2cstr(h->body);
    log_debug(ollama_res.data);
    if (ctx->hssi != NULL)
    {
        log_debug("%s", "ON-RESP :: HSSI ok, response received");
        if (!handle_tool_calls_from_response(ollama_res.data, strlen(ollama_res.data), ctx))
        {
            http_sse_write(ctx->hssi, .id = {.data = ctx->hssi->udata, .len = strlen(ctx->hssi->udata)}, .data = ollama_res, .event = {.data = USR_MSG, .len = strlen(USR_MSG)});
        }
    }
}

static void on_cached_session_get(fio_pubsub_engine_s *e, FIOBJ reply, void *container)
{
    if (reply == FIOBJ_INVALID)
    {
        log_error("RPLY-INVALID -> ABORT");
        return;
    }
    fio_str_info_s rsinfo = fiobj_obj2cstr(reply);
    log_debug("CACHE-OUT-LEN: %d", rsinfo.len);
    char *url_decode_dst = malloc(rsinfo.len);
    http_decode_url(url_decode_dst, rsinfo.data, rsinfo.len);
    replace_char(url_decode_dst, '+', ' ');
    log_debug("CACHE-OUT: %s", url_decode_dst);
    fiobj_json2obj(container, url_decode_dst, strlen(url_decode_dst));
    free(url_decode_dst);
    fio_unlock(&redis_lock);
}

void pass_chat_message(char *sess_id, char *request, char **response, http_sse_s *hssi, http_s *h)
{
    log_debug("%d", strlen(request));
    relay_context_t *ctx = calloc(1, sizeof(relay_context_t));
    if (!ctx) {
        log_error("Failed to allocate relay context");
        *response = "no_id";
        return;
    }
    ctx->req_handle = malloc(strlen(request) + 1);
    memset(ctx->req_handle, 0, strlen(request) + 1);
    strncpy(ctx->req_handle, request, strlen(request) + 1);
    log_debug("REQ-HANDLE: %s", ctx->req_handle);
    size_t sesslen = strlen(sess_id);
    char *session_cache_id = malloc(sesslen + 16); // 16 for "_session_store" and null terminator
    sprintf(session_cache_id, "%s_%s", sess_id, "session_store");
    bool store_exists = redis_contains_key(session_cache_id);

    log_debug("SSHE-HNDL: %p", hssi);
    if (hssi == NULL)
    {
        log_fatal("SSE-HNDL: BROKEN -> ABORT");
        *response = "no_id";
        free(session_cache_id);
        return;
    }
    log_debug("STORE-EXSTS: %d", store_exists);
    FIOBJ session_container = fiobj_hash_new();
    if (false == store_exists)
    {
        log_warn("FALLBACK: Reason=%s,sessid: %s", "Server fell back, no store exists for session", sess_id);
        http_sse_write(hssi, .id = {.data = sess_id, .len = strlen(sess_id)},
                       .data = {.data = "reason: NO-STORE", .len = 16},
                       .event = {.data = ERR_MSG, .len = strlen(ERR_MSG)});
        free(session_cache_id);
        return;
    }

    FIOBJ get_session_command = fiobj_ary_new();
    FIOBJ hget = fiobj_str_new(GET, GET_L);
    FIOBJ value_name = fiobj_str_new(session_cache_id, strlen(session_cache_id));
    FIOBJ data_field = fiobj_str_new("data", 4);
    fiobj_ary_push(get_session_command, hget);
    fiobj_ary_push(get_session_command, value_name);
    fiobj_ary_push(get_session_command, data_field);
    log_debug("SESS-CACHE-ID: %s", session_cache_id);
    fio_trylock(&redis_lock);

    redis_engine_send(FIO_PUBSUB_DEFAULT, get_session_command, on_cached_session_get, &session_container);
    await_for_lock(&redis_lock);

    http_sse_write(hssi, .id = {.data = sess_id, .len = strlen(sess_id)},
                   .data = {.data = sess_id, .len = strlen(sess_id)},
                   .event = {.data = "ctlmessage", .len = 10});
    FIOBJ on_resp_data = fiobj_hash_new();
    char* token = extract_auth_header(h);
    log_debug("TOKEN: %s", token);
    char* bucket_id = extract_header(h, (char *)"x-bucket-id", (size_t)11);
    log_debug("BUCKET-ID: %s", bucket_id);
    fiobj_hash_set(on_resp_data, fiobj_str_new("session_container", 17), session_container);
    fiobj_hash_set(on_resp_data, fiobj_str_new("hssi", 4), fiobj_ptr_wrap(hssi));
    fiobj_hash_set(on_resp_data, fiobj_str_new("token", 5), fiobj_ptr_wrap(token));
    fiobj_hash_set(on_resp_data, fiobj_str_new("bucket_id", 9), fiobj_ptr_wrap(bucket_id));
    char *toolname = NULL;
    is_tool_header_present(h, &toolname);
    log_debug("TOOL-NAME: %s", toolname);
    int tool_name_res = fiobj_hash_set(on_resp_data, fiobj_str_new("tool_name", 9), fiobj_ptr_wrap(toolname));
    log_debug("TOOL-NAME-RES: %d", tool_name_res);
    // Attach per-request context so callbacks can access it via udata
    fiobj_hash_set(on_resp_data, fiobj_str_new("ctx", 3), fiobj_ptr_wrap(ctx));
    FIOBJ *onrptr = fio_malloc(sizeof(*onrptr));
    *onrptr = on_resp_data;
    intptr_t status = http_connect(OLLAMA_CHAT_ENDPOINT, NULL, .on_response = on_response, .udata = onrptr);
    FIOBJ hash = fiobj_hash_new();
    FIOBJ key = fiobj_str_new("process_id", 11);
    if (status != -1)
    {
        FIOBJ value = fiobj_str_new(sess_id, strlen(sess_id));
        int res = fiobj_hash_set(hash, key, value);
        if (res == -1)
        {
            fiobj_free(key);
            fiobj_free(hash);
            return;
        }
        *response = fiobj_obj2cstr(fiobj_obj2json(hash, 1)).data;
    }
    else
    {
        FIOBJ value = FIOBJ_INVALID;
        int res = fiobj_hash_set(hash, key, value);
        if (res == -1)
        {
            fiobj_free(key);
            fiobj_free(hash);
            free(session_cache_id);
            return;
        }
        *response = fiobj_obj2cstr(fiobj_obj2json(hash, 1)).data;
    }
    free(session_cache_id);
    fiobj_free(key);
    fiobj_free(hash);
    // free(req_handle);
    // free(request);
    // req_handle = NULL;
}

/**
 * Extracts the Authorization header value from an HTTP request.
 * 
 * @param h HTTP request struct
 * @return Dynamically allocated string containing the Authorization header value, 
 *         or NULL if the header isn't present. Caller must free this memory.
 */
char* extract_auth_header(http_s *h) {
    if (!h || h->headers == FIOBJ_INVALID) {
        log_debug("HTTP request or headers are invalid.");
        return NULL;
    }
    log_debug("Extracting Authorization header...");
    FIOBJ r = http_req2str(h); // Ensure the request is parsed and headers are available.
    log_debug("AUTH: %s", fiobj_obj2cstr(r).data);
    FIOBJ auth_key = fiobj_str_new("authorization", 13);
    if (!fiobj_hash_haskey(h->headers, auth_key)) {
        fiobj_free(auth_key);
        return NULL;
    }
    log_debug("Authorization header found in request.");
    FIOBJ auth_value = fiobj_hash_get(h->headers, auth_key);
    
    if (auth_value == FIOBJ_INVALID || fiobj_type_is(auth_value, FIOBJ_T_STRING) != 1) {
        return NULL;
    }
    log_debug("Authorization header found.");
    fio_str_info_s auth_str = fiobj_obj2cstr(auth_value);
    if (auth_str.len == 0) {
        return NULL;
    }
    
    char *result = malloc(auth_str.len);
    if (result == NULL) {
        log_error("MEM-ALLOC-FAIL for Authorization header");
        return NULL;
    }
    log_debug("Authorization header value: %.*s", (int)auth_str.len, auth_str.data);
    memcpy(result, auth_str.data, auth_str.len);
    fiobj_free(auth_key);
    return result;
}

char* extract_header(http_s *h, char *header_name, size_t header_name_len) {
    if (!h || h->headers == FIOBJ_INVALID) {
        return NULL;
    }
    FIOBJ hdr_key = fiobj_str_new(header_name, header_name_len);
    if (!fiobj_hash_haskey(h->headers, hdr_key)) {
        fiobj_free(hdr_key);
        return NULL;
    }
    FIOBJ hdr_value = fiobj_hash_get(h->headers, hdr_key);
    if (hdr_value == FIOBJ_INVALID || fiobj_type_is(hdr_value, FIOBJ_T_STRING) != 1) {
        fiobj_free(hdr_key);
        return NULL;
    }
    fio_str_info_s hdr_str = fiobj_obj2cstr(hdr_value);
    if (hdr_str.len == 0) {
        fiobj_free(hdr_key);
        return NULL;
    }
    char *result = malloc(hdr_str.len + 1);
    if (result == NULL) {
        fiobj_free(hdr_key);
        return NULL;
    }
    memcpy(result, hdr_str.data, hdr_str.len);
    result[hdr_str.len] = '\0';
    fiobj_free(hdr_key);
    return result;
}
