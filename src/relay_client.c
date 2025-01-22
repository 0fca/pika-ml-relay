#include "main.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#include <curl/curl.h>
#include <curl/easy.h>

// FIXME: To be moved to shared memory
static char *req_handle;
static http_sse_s *hssi_g = NULL;
fio_lock_i lock, redis_lock, dwn_lock, tool_call_lock;
static int shmid, shmfid;
static FIOBJ session_container_g = FIOBJ_INVALID;

static bool set_llm_req_opt(char* optkey_s, FIOBJ value)
{
    if(req_handle == NULL)
    {
        log_debug("req_handle is either NULL or undefined, couldnt set");
        return false;
    }
    FIOBJ req_handle_obj = FIOBJ_INVALID;
    fiobj_json2obj(&req_handle_obj, req_handle, strlen(req_handle));
    FIOBJ optkey = fiobj_str_new("options", 7);
    FIOBJ opt_hash = fiobj_hash_get(req_handle_obj, optkey);
    if(opt_hash == FIOBJ_INVALID)
    {
        opt_hash = fiobj_hash_new();
    }
    FIOBJ key_obj = fiobj_str_new(optkey_s, strlen(optkey));
    fiobj_hash_set(opt_hash, key_obj, value);
    fiobj_hash_set(req_handle_obj, optkey, opt_hash);
    FIOBJ req_handle_str = fiobj_obj2json(req_handle_obj, 0);
    req_handle = fiobj_obj2cstr(req_handle_str).data;
    fiobj_free(req_handle_obj);
    fiobj_free(optkey);
    fiobj_free(opt_hash);
    fiobj_free(key_obj);
    fiobj_free(req_handle_str);
    return true;
}

static size_t write_curl_callback(void* ptr, size_t size, size_t nmemb, FILE* fp)
{
    size_t written = fwrite(ptr, size, nmemb, fp);
    return written;
}

static int iterate_over_args(FIOBJ o, void* parsed)
{
    char* param = fiobj_obj2cstr(o).data;
    char* enclosed_param = malloc(strlen(param));
    sprintf(enclosed_param, "'%s'", param);
    strcat(parsed, enclosed_param);
    strcat(parsed, " ");
    return 0;
}

static void parse_arguments_hash(FIOBJ arguments, char* parsed)
{
    if(fiobj_type_is(arguments, FIOBJ_T_HASH) == 0)
    {
        return;
    }
    size_t ret = fiobj_each1(arguments, (size_t)0, iterate_over_args, parsed);
    log_debug("Parsed Params From Function: %s", parsed);
}

static FIOBJ retrieve_req_handle_as_fiobj()
{
    FIOBJ handle = FIOBJ_INVALID;
    fiobj_json2obj(&handle, req_handle, strlen(req_handle));
    return handle;
}

static void update_curr_req_handle_messages(FIOBJ message)
{
    FIOBJ messagekey = fiobj_str_new("messages", 8);
    FIOBJ ollama_req = FIOBJ_INVALID; 
    fiobj_json2obj(&ollama_req, req_handle, strlen(req_handle));  
    FIOBJ message_arr = fiobj_dup(fiobj_hash_get(ollama_req, messagekey)); 
    fiobj_ary_push(message_arr, message);
    fiobj_hash_set(ollama_req, messagekey, message_arr);
    fiobj_free(messagekey);
    req_handle = fiobj_obj2cstr(fiobj_obj2json(ollama_req, 0)).data;
}

static void push_on_top_curr_req_messages(FIOBJ message)
{
    FIOBJ messagekey = fiobj_str_new("messages", 8);
    FIOBJ ollama_req = FIOBJ_INVALID; 
    fiobj_json2obj(&ollama_req, req_handle, strlen(req_handle));  
    FIOBJ message_arr = fiobj_dup(fiobj_hash_get(ollama_req, messagekey)); 
    FIOBJ tmp_message_arr = fiobj_ary_new2(fiobj_ary_count(message_arr) + 1);
    fiobj_ary_push(tmp_message_arr, message);
    for(int i = 0; i < fiobj_ary_count(message_arr); i++)
    {
        fiobj_ary_push(tmp_message_arr, fiobj_ary_entry(message_arr, i));
    }
    fiobj_hash_set(ollama_req, messagekey, tmp_message_arr);
    fiobj_free(messagekey);
    req_handle = fiobj_obj2cstr(fiobj_obj2json(ollama_req, 0)).data;
    fiobj_free(message_arr);
    fiobj_free(tmp_message_arr);
    fiobj_free(ollama_req);
}

// FIXME: Make this configurable to run more than just python scripts.
static char* execute_tool(char *tool_engine, char* tool_name, char* parameters)
{
    /*char *fname_addr;
    char *fname = shmat(shmfid, fname_addr, 0);*/
    char *cmd_str = malloc(256);
    log_debug("%s %s %s", tool_engine, tool_name, parameters);
    snprintf(cmd_str, 256, "bash -c \"%s %s %s\"", tool_engine, tool_name, parameters);
    FILE *fp;
    fp = popen(cmd_str, "r");
    if (fp == NULL)
    {
        printf("TOOL-EXEC-FAIL\n");
        return;
    }
    // FIXME: Should find another way round without using malloc with hardcoded, probably should not even use malloc?
    char* l = malloc(1024);
    char* result = malloc(65535);
    memset(result, 0, strlen(result));
    while (fgets(l, 1024, fp) != NULL)
    {
        strcat(result, l);
    }
    pclose(fp);
    free(l);
    free(cmd_str);
    //shmdt(fname);
    fio_unlock(&tool_call_lock);
    return result;
}

static void execute_download(char* full_url, char *name)
{
    log_debug("DWN: %s", full_url);
    CURL *curl = curl_easy_init();
    if(curl){
        FILE* fp = fopen(name, "wb+");
        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_curl_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        fclose(fp);
    }
}

static void download_tool(char *tool_url, char *name)
{
    shmfid = shmget(IPC_PRIVATE, strlen(name), IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
    char *fname_addr;
    char *shmfname = shmat(shmfid, fname_addr, 0);
    sprintf(shmfname, "%s", name);
    shmdt(shmfname);
    execute_download(tool_url, name);
}

static void apnd_syssec2req(FIOBJ container)
{
    FIOBJ syspromptskey = fiobj_str_new("sysprompts", 10);
    FIOBJ prompts = fiobj_hash_get(container, syspromptskey);
    if(fiobj_type_is(prompts, FIOBJ_T_ARRAY) == 1)
    {
        int promptc = fiobj_ary_count(prompts);
        for(int i = 0; i < promptc; i++)
        {
            FIOBJ prompt_hash = fiobj_ary_entry(prompts, i);
            if(fiobj_type_is(prompt_hash, FIOBJ_T_HASH) == 1)
            {
                push_on_top_curr_req_messages(prompt_hash);
            }
        }
    }
}

static void apnd_toolsec2req(FIOBJ container)
{
    FIOBJ cmdskey = fiobj_str_new("cmds", 4);
    FIOBJ urlkey = fiobj_str_new("tool_url", 8);
    FIOBJ enginekey = fiobj_str_new("tool_engine", 11);
    FIOBJ namekey = fiobj_str_new("name", 4);
    FIOBJ desckey = fiobj_str_new("description", 11);
    FIOBJ params = fiobj_str_new("params", 6);
    FIOBJ cmda = fiobj_hash_get(container, cmdskey);
    FIOBJ tool_section = fiobj_hash_new();
    FIOBJ tool_ary = fiobj_ary_new();
    if (fiobj_type_is(cmda, FIOBJ_T_ARRAY) == 1)
    {
        int cmdc = fiobj_ary_count(cmda);
        for (int i = 0; i < cmdc; i++)
        {
            FIOBJ cmd = fiobj_dup(fiobj_ary_index(cmda, i));
            if (fiobj_type_is(cmd, FIOBJ_T_HASH) == 1)
            {
                char *tool_sec = malloc(2048); // FIXME: It should be somehow calculated based on name, description length and consolidated length of parameters
                FIOBJ tool_url = fiobj_hash_get(cmd, urlkey);
                FIOBJ tool_engine = fiobj_hash_get(cmd, enginekey);
                char *url = fiobj_obj2cstr(tool_url).data;
                char *engine = fiobj_obj2cstr(tool_engine).data;
                char *name = fiobj_obj2cstr(fiobj_hash_get(cmd, namekey)).data;
                char *description = fiobj_obj2cstr(fiobj_hash_get(cmd, desckey)).data;
                char* params_json_str = strdup(fiobj_obj2cstr(fiobj_hash_get(cmd, params)).data);

                log_debug("REQ-PREP: %s, %s", url, engine);
                log_debug(params_json_str);
                download_tool(url, name);
                FIOBJ parsed_params_json = FIOBJ_INVALID;
                if(strcmp(params_json_str, "") == 0 || params_json_str == NULL)
                {
                    *params_json_str = "{}";
                } 
                fiobj_json2obj(&parsed_params_json, params_json_str, strlen(params_json_str));
                char* params = fiobj_obj2cstr(fiobj_obj2json(parsed_params_json, 0)).data;
                snprintf(tool_sec, 2048, "{\"type\":\"function\", \"function\":{\"name\": \"%s\", \"description\": \"%s\", \"parameters\": %s}}", name, description, params);
                log_debug(tool_sec);
                FIOBJ tool_sec_obj = FIOBJ_INVALID;
                fiobj_json2obj(&tool_sec_obj, strdup(tool_sec), strlen(tool_sec));
                fiobj_ary_push(tool_ary, tool_sec_obj);
                free(tool_sec);
            }
            fiobj_free(cmd);
        }
        FIOBJ req = FIOBJ_INVALID;
        fiobj_json2obj(&req, req_handle, strlen(req_handle));
        FIOBJ tools_key = fiobj_str_new("tools", 5);
        fiobj_hash_set(req, tools_key, tool_ary);
        FIOBJ req_json_obj = fiobj_obj2json(req, 0);
        char *req_with_tools = fiobj_obj2cstr(req_json_obj).data;
        req_handle = req_with_tools;
        log_debug("REQ-TOOLS-ADD: %s", req_with_tools);
    }
    fiobj_free(cmdskey);
    fiobj_free(urlkey);
    fiobj_free(enginekey);
    fiobj_free(namekey);
    fiobj_free(desckey);
    fiobj_free(tool_section);
}

static void on_tool_call(http_s *h)
{
    if (h->status_str == FIOBJ_INVALID)
    {
        char* tool_sec = malloc(65535);
        memset(tool_sec, 0, 65535);
        FIOBJ container = *((FIOBJ*)h->udata);
        FIOBJ content = fiobj_str_new("content", 7);
        FIOBJ name = fiobj_str_new("tool_name", 9);
        FIOBJ fcall_key = fiobj_str_new("fcall", 4);
        FIOBJ argskey = fiobj_str_new("args", 4);
        FIOBJ fcall = fiobj_hash_get(container, fcall_key);
        fio_str_info_s content_info = fiobj_obj2cstr(fiobj_hash_get(container, content));
        fio_str_info_s name_info = fiobj_obj2cstr(fiobj_hash_get(container, name));
        if(strncmp(content_info.data, "{", 1) == 0)
        {
            http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = content_info, .event = {.data = "datamessage", .len = 11});
            return;
        }
        snprintf(tool_sec, 65535, "{\"role\":\"tool\", \"name\":\"%s\", \"content\":\"%s\"}", name_info.data, content_info.data);
        FIOBJ toolssec = FIOBJ_INVALID;
        log_debug("%s", tool_sec);
        fiobj_json2obj(&toolssec, tool_sec, strlen(tool_sec));
        update_curr_req_handle_messages(fcall);
        update_curr_req_handle_messages(toolssec);
        http_sse_s* hssi = fiobj_ptr_unwrap(fiobj_hash_get(container, fiobj_str_new("hssi", 4)));
        /*FIOBJ opt_temp = fiobj_num_new(0);
        log_debug("REQ-TOOLS-CALL: %s", req_handle);
        bool opts_set = set_llm_req_opt("temperature", opt_temp);
        log_debug("REQ-TOOLS-CALL-OPT-SET: %s", req_handle);
        if(opts_set == true)
        {
            log_debug("Opts set");
        } 
        else 
        {
            log_debug("Opts not set");
        }*/
        FIOBJ ollama_req = retrieve_req_handle_as_fiobj();
        char* full_req = fiobj_obj2cstr(fiobj_obj2json(ollama_req, 0)).data;
        h->method = fiobj_str_new("POST", 4);
        http_send_body(h, full_req, strlen(full_req));
        //fiobj_free(opt_temp);
        fiobj_free(ollama_req);
        return;
    }
    FIOBJ ollama_res = h->body;
    fio_str_info_s ollama_res_s = fiobj_obj2cstr(ollama_res);
    FIOBJ resp_parsed = FIOBJ_INVALID;
    fiobj_json2obj(&resp_parsed, ollama_res_s.data, ollama_res_s.len);
    FIOBJ message = fiobj_hash_get(resp_parsed, fiobj_str_new("message", 7));
    FIOBJ content = fiobj_hash_get(message, fiobj_str_new("content", 7));
    fio_str_info_s content_s = fiobj_obj2cstr(content);
    if(content_s.len == 0)
    {
        FIOBJ ctlmessage_empty_resp = fiobj_str_new("EMPTY RESP", 10);
        http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = fiobj_obj2cstr(ctlmessage_empty_resp), .event = {.data = "ctlmessage", .len = 10});
        fiobj_free(ctlmessage_empty_resp);
        return;
    }
    if(ollama_res_s.len > 0)
    {
        FIOBJ test_holder = FIOBJ_INVALID;
        size_t consumed = fiobj_json2obj(&test_holder, content_s.data, content_s.len);
        // 0 bytes consumed, that means that whatever LLM returned is not a JSON, just pass it over
        if(consumed == 0)
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
        apnd_syssec2req(session_container);
        apnd_toolsec2req(session_container);
        http_send_body(h, req_handle, strlen(req_handle));
        return;
    }
    fio_str_info_s ollama_res = fiobj_obj2cstr(h->body);
    if (hssi_g != NULL)
    {
        FIOBJ ollama_response_obj = FIOBJ_INVALID;
        log_debug(ollama_res.data);
        fiobj_json2obj(&ollama_response_obj, ollama_res.data, strlen(ollama_res.data));
        if (fiobj_type_is(ollama_response_obj, FIOBJ_T_HASH) == 1)
        {
            FIOBJ message_key = fiobj_str_new("message", 7);
            FIOBJ tool_calls_key = fiobj_str_new("tool_calls", 10);

            FIOBJ message = fiobj_hash_get(ollama_response_obj, message_key);
            if (fiobj_hash_haskey(message, tool_calls_key) != 1)
            {
                // It appears that the response from LLM didn't contain tool_calls, so just return whole response as is.
                http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = ollama_res, .event = {.data = "usermessage", .len = 11});
                return;
            }
            FIOBJ fcalls = fiobj_hash_get(message, tool_calls_key);
            for (size_t i = 0; i < fiobj_ary_count(fcalls); i++)
            {
                fio_trylock(&tool_call_lock);
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
                        char* params = malloc(2048);
                        memset(params, 0, 2048);
                        parse_arguments_hash(args, params);
                        log_debug("%s : %s", curr_tool_name, fiobj_obj2cstr(fname).data);
                        char* output = execute_tool(tool_engine_str, curr_tool_name, params);
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
                        intptr_t tool_result_status = http_connect("http://192.168.1.203:11434/api/chat", NULL, .on_response = on_tool_call, .udata = contain_ptr);
                        log_debug("%s", "RELAY-OK");
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
    size_t consumed = fiobj_json2obj(container, url_decode_dst, strlen(url_decode_dst));
    free(url_decode_dst);
    fio_unlock(&redis_lock);
}

void pass_chat_message(char *sess_id, char *request, char **response, http_sse_s *hssi)
{
    req_handle = request;
    char *session_cache_id = malloc(strlen(sess_id) + strlen("_session_store"));
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
    if (store_exists == true)
    {
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
    }

    http_sse_write(hssi, .id = {.data = sess_id, .len = strlen(sess_id)},
                   .data = {.data = sess_id, .len = strlen(sess_id)},
                   .event = {.data = "ctlmessage", .len = 10});
    FIOBJ on_resp_data = fiobj_hash_new();
    fiobj_hash_set(on_resp_data, fiobj_str_new("session_container", 17), session_container);
    fiobj_hash_set(on_resp_data, fiobj_str_new("hssi", 4), fiobj_ptr_wrap(hssi));
    FIOBJ *onrptr = fio_malloc(sizeof(*onrptr));
    *onrptr = on_resp_data;
    intptr_t status = http_connect("http://192.168.1.203:11434/api/chat", NULL, .on_response = on_response, .udata = onrptr);
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
    fiobj_free(key);
    fiobj_free(hash);
}