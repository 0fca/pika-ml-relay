#include "main.h"
#include <sys/ipc.h>
#include <sys/shm.h>
// FIXME: To be moved to shared memory
static char *req_handle;
static http_sse_s *hssi_g = NULL;
fio_lock_i lock, redis_lock, dwn_lock, tool_call_lock;
static int shmid, shmfid;
static FIOBJ session_container_g = FIOBJ_INVALID;

static int iterate_over_args(FIOBJ o, void* parsed)
{
    char* param = fiobj_obj2cstr(o).data;
    strcat(parsed, param);
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

// FIXME: Make this configurable to run more than just python scripts.
static char* execute_tool(char *tool_engine, char* parameters)
{
    char *fname_addr;
    char *fname = shmat(shmfid, fname_addr, 0);
    char *cmd_str = malloc(256);
    snprintf(cmd_str, 256, "bash -c \"%s %s %s\"", tool_engine, fname, parameters);
    FILE *fp;
    fp = popen(cmd_str, "r");
    if (fp == NULL)
    {
        printf("TOOL-EXEC-FAIL\n");
        return;
    }
    char* l = malloc(256);
    char* result = malloc(1024);
    memset(result, 0, strlen(result));
    while (fgets(l, 256, fp) != NULL)
    {
        strcat(result, l);
    }
    log_debug("%s", result);
    pclose(fp);
    free(l);
    free(cmd_str);
    shmdt(fname);
    fio_unlock(&tool_call_lock);
    return result;
}

static void write_exec_file(char *path, char *content, intptr_t size)
{
    FIOBJ io = fiobj_data_newstr2(content, size, NULL);
    fiobj_data_save(io, path);
    fiobj_free(io);
}

static void on_script_tool_locate(http_s *h)
{
    if (h->status_str == FIOBJ_INVALID)
    {
        log_debug("LOC-CONN: OK");
        http_finish(h);
        return;
    }
    if (h->status == (uintptr_t)302)
    {
        FIOBJ location = fiobj_hash_get(h->headers, fiobj_str_new(HTTP_HEADER_LOCATION, strlen(HTTP_HEADER_LOCATION)));
        char *actual_download_url = malloc(4096);
        sprintf(actual_download_url, "%s", fiobj_obj2cstr(location).data);
        char *base_name = malloc(64);
        sprintf(base_name, "%s", "http://core.lukas-bownik.net:5000");
        char *full_url = malloc(4096);
        sprintf(full_url, "%s%s", base_name, actual_download_url);
        log_debug("Full URL: %s", full_url);
        char *full_url_addr;
        char *shmurl = shmat(shmid, full_url_addr, 0);
        sprintf(shmurl, "%s", full_url);
        shmdt(shmurl);
        fio_unlock(&lock);
        free(base_name);
        free(full_url);
        free(actual_download_url);
    }
}

static void on_script_tool_download(http_s *h)
{
    fio_trylock(&dwn_lock);
    if (h->status_str == FIOBJ_INVALID)
    {
        log_debug("DWN-CONN: OK");
        fio_unlock(&lock);
        http_finish(h);
        return;
    }
    if (h->status == (uintptr_t)200)
    {
        FIOBJ content_length = fiobj_hash_get(h->headers, fiobj_str_new("content-length", strlen("content-length")));
        intptr_t cl = fiobj_obj2num(content_length);
        char *fname_addr;
        char *fname = shmat(shmfid, fname_addr, 0);
        char *file_content = fiobj_obj2cstr(h->body).data;
        write_exec_file(fname, file_content, cl);
        fiobj_free(content_length);
        fio_unlock(&dwn_lock);
    }
}

static void execute_download(void *tool_engine, char *name)
{
    shmfid = shmget(IPC_PRIVATE, strlen(name), IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
    char *full_url_addr;
    char *full_url = shmat(shmid, full_url_addr, 0);
    char *fname_addr;
    char *shmfname = shmat(shmfid, fname_addr, 0);
    sprintf(shmfname, "%s", name);
    shmdt(shmfname);
    log_debug("DWN: %s", (char *)full_url);
    intptr_t sock_id = http_connect((char *)full_url, NULL, .on_response = on_script_tool_download, .udata = name);
    if (sock_id == 0)
    {
        log_fatal("TOOL-DOWNLOAD-FAIL");
        return;
    }
    await_for_lock(&dwn_lock);
    shmdt(full_url);
}

static void execute_location_get(void *tool_url)
{
    log_debug("LOC: %s", (char *)tool_url);
    int lockres = fio_trylock(&lock);
    if (lockres != 0)
    {
        log_fatal("TOOL-LOCATE-LOCK-FAIL");
        return;
    }
    intptr_t sock_id = http_connect((char *)tool_url, NULL, .on_response = on_script_tool_locate);

    if (sock_id == 0)
    {
        log_fatal("TOOL-LOCATE-FAIL");
        return;
    }
    await_for_lock(&lock);
}

static void download_tool(char *tool_url, char *tool_engine, char *name)
{
    shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
    execute_location_get(tool_url);
    execute_download(tool_engine, name);
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
                char* params_json_str = fiobj_obj2cstr(fiobj_hash_get(cmd, params)).data;

                log_debug("REQ-PREP: %s, %s", url, engine);
                log_debug(params_json_str);
                download_tool(url, engine, name);
                FIOBJ parsed_params_json = FIOBJ_INVALID;
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
        char* tool_sec = malloc(1024);
        FIOBJ container = *((FIOBJ*)h->udata);
        FIOBJ content = fiobj_str_new("content", 7);
        FIOBJ name = fiobj_str_new("tool_name", 9);
        FIOBJ fcall_key = fiobj_str_new("fcall", 4);
        FIOBJ argskey = fiobj_str_new("args", 4);
        FIOBJ fcall = fiobj_hash_get(container, fcall_key);
        fio_str_info_s content_info = fiobj_obj2cstr(fiobj_hash_get(container, content));
        fio_str_info_s name_info = fiobj_obj2cstr(fiobj_hash_get(container, name));
        snprintf(tool_sec, 1024, "{\"role\":\"tool\", \"name\":\"%s\", \"content\":\"%s\"}", name_info.data, content_info.data);
        FIOBJ toolssec = FIOBJ_INVALID;
        log_debug("%s", tool_sec);
        fiobj_json2obj(&toolssec, tool_sec, strlen(tool_sec));
        update_curr_req_handle_messages(fcall);
        update_curr_req_handle_messages(toolssec);
        http_sse_s* hssi = fiobj_ptr_unwrap(fiobj_hash_get(container, fiobj_str_new("hssi", 4)));
        FIOBJ ollama_req = retrieve_req_handle_as_fiobj();
        char* full_req = fiobj_obj2cstr(fiobj_obj2json(ollama_req, 0)).data;
        h->method = fiobj_str_new("POST", 4);
        http_send_body(h, full_req, strlen(full_req));
        fiobj_free(ollama_req);
        return;
    }
    FIOBJ ollama_res = h->body;
    http_sse_write(hssi_g, .id = {.data = hssi_g->udata, .len = strlen(hssi_g->udata)}, .data = fiobj_obj2cstr(ollama_res), .event = {.data = "usermessage", .len = 11});
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
                        char* output = execute_tool(tool_engine_str, params);
                        await_for_lock(&tool_call_lock);
                        fio_str_info_s await_tool_call = fiobj_obj2cstr(fiobj_str_new("AWAIT TOOL CALL", 15));
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
        fiobj_ary_push(get_session_command, fiobj_str_new(GET, GET_L));
        fiobj_ary_push(get_session_command, fiobj_str_new(session_cache_id, strlen(session_cache_id)));
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
    intptr_t status = http_connect("http://192.168.1.253:11434/api/chat", NULL, .on_response = on_response, .udata = onrptr);
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