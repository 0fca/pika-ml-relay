#include "main.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#include <curl/curl.h>
#include <curl/easy.h>

// FIXME: To be moved to shared memory
static char *req_handle;
static http_sse_s *hssi_g = NULL;
fio_lock_i lock, redis_lock, dwn_lock, tool_call_lock;
static FIOBJ session_container_g = FIOBJ_INVALID;
volatile intptr_t fd = NULL;

void *parse_chunked_response()
{
    char *ptid = malloc(16);
    ssize_t safe_gauge = 0;
    char buffer[CHUNK_BUFFER_SIZE] = {0};
    ssize_t len = 0;

    while (true)
    {
        len = fio_read(fd, buffer, CHUNK_BUFFER_SIZE);
        if (len > 0)
        {
            char *buffcpy = malloc(len);
            memcpy(buffcpy, buffer, len);
            // TODO: Probably should be supporting more than just 2 chunks in single buffer read?
            char *read = read_until_delim(&buffcpy, '{', '\n');
            char *read2 = read_until_delim(&buffcpy, '{', '\n');
            log_debug("HTTP-RELAY::STREAM::READ: %s %s", read, read2);
            safe_gauge = len;
            if (hssi_g != NULL)
            {
                log_debug("HTTP-RELAY::STREAM::HSSI");
                
                if(read != NULL){
                    http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = {.data = read, .len = strlen(read)}, .event = {.data = "usermessage-chk", .len = 15});
                }

                if(read != NULL && read2 != NULL){
                    char* payload = malloc(strlen(read) + strlen(read2) + 1);
                    memset(payload, 0, strlen(read) + strlen(read2) + 1);
                    strcat(payload, read);
                    strcat(payload, read2);
                    http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = {.data = payload, .len = strlen(payload)}, .event = {.data = "usermessage-chk", .len = 15});
                }
            }
            if (read == NULL && read2 == NULL 
                // TODO: It is mostly a case when Ollama is used or some other API that does return such json
                || 1 == contains_substring(read, "\"done_reason\":\"stop\",\"done\":true") 
                || 1 == contains_substring(read2, "\"done_reason\":\"stop\",\"done\":true")
            )
            {
                log_debug("HTTP-RELAY::STREAM::STOP");
                return ptid;
            }
            memset(buffer, 0, CHUNK_BUFFER_SIZE);
        } else if(safe_gauge == 0){
            usleep(1000);
        }
    }
    return ptid;
}

static void on_tool_call(http_s *h)
{
    if (h->status_str == FIOBJ_INVALID)
    {
        char *tool_sec = malloc(TOOL_SEC_L);
        memset(tool_sec, 0, TOOL_SEC_L);
        FIOBJ container = *((FIOBJ *)h->udata);
        FIOBJ content = fiobj_str_new("content", 7);
        FIOBJ name = fiobj_str_new("tool_name", 9);
        FIOBJ fcall_key = fiobj_str_new("fcall", 4);
        FIOBJ fcall = fiobj_hash_get(container, fcall_key);
        fio_str_info_s content_info = fiobj_obj2cstr(fiobj_hash_get(container, content));
        fio_str_info_s name_info = fiobj_obj2cstr(fiobj_hash_get(container, name));
        FIOBJ opt_temp = fiobj_num_new((intptr_t)0);
        log_debug("REQ-TOOLS-CALL: %s", req_handle);
        bool opts_set = set_llm_req_opt("temperature", opt_temp, req_handle);
        log_debug("REQ-TOOLS-CALL-OPT-SET: %s", req_handle);
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
            http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = content_info, .event = {.data = DATA_MSG, .len = strlen(DATA_MSG)});
            return;
        }
        snprintf(tool_sec, TOOL_SEC_L, "{\"role\":\"tool\", \"name\":\"%s\", \"content\":\"%s\"}", name_info.data, content_info.data);
        FIOBJ toolssec = FIOBJ_INVALID;
        log_debug("%s", tool_sec);
        fiobj_json2obj(&toolssec, tool_sec, strlen(tool_sec));
        update_curr_req_handle_messages(fcall, &req_handle);
        update_curr_req_handle_messages(toolssec, &req_handle);
        log_debug("URH: %s", req_handle);
        h->method = fiobj_str_new("POST", 4);
        log_debug("FR: %s", req_handle);
        http_send_body(h, req_handle, strlen(req_handle));
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
        http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = fiobj_obj2cstr(errpayload), .event = {.data = CTL_MSG, .len = strlen(CTL_MSG)});
        return;
    }
    FIOBJ message = fiobj_hash_get(resp_parsed, fiobj_str_new("message", 7));
    FIOBJ content = fiobj_hash_get(message, fiobj_str_new("content", 7));
    fio_str_info_s content_s = fiobj_obj2cstr(content);
    if (content_s.len == 0)
    {
        FIOBJ ctlmessage_empty_resp = fiobj_str_new("EMPTY RESP", 10);
        http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = fiobj_obj2cstr(ctlmessage_empty_resp), .event = {.data = CTL_MSG, .len = strlen(CTL_MSG)});
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
            http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = ollama_res_s, .event = {.data = "usermessage", .len = 11});
        }
        // Handle JSON response?
    }
}

static void on_response(http_s *h)
{
    if (h->status_str == FIOBJ_INVALID)
    {
        h->method = fiobj_str_new("POST", 4);
        FIOBJ data_container = *((FIOBJ *)h->udata);
        FIOBJ session_container = fiobj_hash_get(data_container, fiobj_str_new("session_container", 17));
        session_container_g = fiobj_dup(session_container);
        hssi_g = (http_sse_s *)fiobj_ptr_unwrap(fiobj_hash_get(data_container, fiobj_str_new("hssi", 4)));
        apnd_syssec2req(session_container, &req_handle);
        char *model = malloc(MODEL_NAME_L);
        memset(model, 0, MODEL_NAME_L);
        extract_model(&model, req_handle);
        log_debug("Model: %s", model);
        if (supports_tools(model) == true)
        {
            log_debug("%s supports tools", model);
            apnd_toolsec2req(session_container, &req_handle);
        }
        log_debug("R: %s", req_handle);
        http_send_body(h, req_handle, strlen(req_handle));
        fd = http_hijack(h, NULL);
        fio_thread_new(&parse_chunked_response, NULL);
        fiobj_free(data_container);
        fiobj_free(session_container);
        return;
    }

    log_debug("FD: %d", fd);

    fio_str_info_s ollama_res = fiobj_obj2cstr(h->body);
    log_debug(ollama_res.data);
    if (hssi_g != NULL)
    {
        log_debug("%s", "ON-RESP :: HSSI ok, response received");
        FIOBJ ollama_response_obj = FIOBJ_INVALID;
        log_debug(ollama_res.data);
        fiobj_json2obj(&ollama_response_obj, ollama_res.data, strlen(ollama_res.data));
        if (fiobj_type_is(ollama_response_obj, FIOBJ_T_HASH) == 1)
        {
            FIOBJ message_key = fiobj_str_new("message", 7);
            FIOBJ tool_calls_key = fiobj_str_new("tool_calls", 10);

            FIOBJ message = fiobj_hash_get(ollama_response_obj, message_key);
            if (fiobj_type_is(message, FIOBJ_T_HASH) != 1 || fiobj_hash_haskey(message, tool_calls_key) != 1)
            {
                // It appears that the response from LLM didn't contain tool_calls, so just return whole response as is.
                http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = ollama_res, .event = {.data = USR_MSG, .len = strlen(USR_MSG)});
                return;
            }
            FIOBJ fcalls = fiobj_hash_get(message, tool_calls_key);
            fio_trylock(&tool_call_lock);
            for (size_t i = 0; i < fiobj_ary_count(fcalls); i++)
            {
                FIOBJ fcall = fiobj_ary_index(fcalls, i);
                FIOBJ fkey = fiobj_str_new("function", 8);
                FIOBJ argkey = fiobj_str_new("arguments", 9);
                FIOBJ func = fiobj_hash_get(fcall, fkey);
                FIOBJ fnamekey = fiobj_str_new("name", 4);
                FIOBJ fname = fiobj_hash_get(func, fnamekey);
                FIOBJ args = fiobj_hash_get(func, argkey);
                FIOBJ cmds = fiobj_hash_get(session_container_g, fiobj_str_new("cmds", 4));
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
                        log_debug("%s : %s", curr_tool_name, fiobj_obj2cstr(fname).data);
                        char *output = malloc(16384);
                        execute_tool(&output, tool_engine_str, curr_tool_name, params, tool_call_lock);
                        await_for_lock(&tool_call_lock);
                        fio_str_info_s await_tool_call = fiobj_obj2cstr(fiobj_str_new("await tool call", 15));
                        http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = await_tool_call, .event = {.data = "ctlmessage", .len = 10});
                        FIOBJ container = fiobj_hash_new();
                        fiobj_hash_set(container, fiobj_str_new("hssi", 4), fiobj_ptr_wrap(hssi_g));
                        fiobj_hash_set(container, fiobj_str_new("tool_name", 9), fiobj_str_new(curr_tool_name, strlen(curr_tool_name)));
                        fiobj_hash_set(container, fiobj_str_new("content", 7), fiobj_str_new(output, strlen(output)));
                        fiobj_hash_set(container, fiobj_str_new("fcall", 4), message);
                        FIOBJ *contain_ptr = fio_malloc(sizeof(*contain_ptr));
                        *contain_ptr = container;
                        http_connect(OLLAMA_CHAT_ENDPOINT, NULL, .on_response = on_tool_call, .udata = contain_ptr);
                        log_debug("%s", "RELAY-OK");
                        // free(output);
                        break;
                    }
                }
                fiobj_free(fkey);
                fiobj_free(fnamekey);
            }
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
    fiobj_json2obj(container, url_decode_dst, strlen(url_decode_dst));
    free(url_decode_dst);
    fio_unlock(&redis_lock);
}

void pass_chat_message(char *sess_id, char *request, char **response, http_sse_s *hssi)
{
    req_handle = request;
    size_t sesslen = strlen(sess_id);
    char *session_cache_id = malloc(sesslen + 14);
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
    fiobj_hash_set(on_resp_data, fiobj_str_new("session_container", 17), session_container);
    fiobj_hash_set(on_resp_data, fiobj_str_new("hssi", 4), fiobj_ptr_wrap(hssi));
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
        fiobj_free(value);
    }
    else
    {
        FIOBJ value = FIOBJ_INVALID;
        int res = fiobj_hash_set(hash, key, value);
        if (res == -1)
        {
            fiobj_free(key);
            fiobj_free(hash);
            return;
        }
        *response = fiobj_obj2cstr(fiobj_obj2json(hash, 1)).data;
        fiobj_free(value);
    }
    free(session_cache_id);
    fiobj_free(key);
    fiobj_free(hash);
}