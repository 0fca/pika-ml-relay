#include "main.h"
#include <sys/ipc.h>
#include <sys/shm.h>

static char* req_handle;
static http_sse_s* hssi_g = NULL;
static char* session_result = NULL;

static void on_response(http_s *h)
{
    if (h->status_str == FIOBJ_INVALID)
    {
        h->method = fiobj_str_new("POST", 4);
        FIOBJ json_container = FIOBJ_INVALID;
        hssi_g = (http_sse_s*)h->udata;
        http_send_body(h, req_handle, strlen(req_handle));
        fiobj_free(json_container);
        return;
    }
    fio_str_info_s ollama_res = fiobj_obj2cstr(h->body);
    if(hssi_g != NULL){
        http_sse_write(hssi_g, .data = fiobj_obj2cstr(fiobj_str_new(ollama_res.data, strlen(ollama_res.data))), .event = { .data = "usermessage", .len = 11});
        log_debug("%s\n", "RELAY-OK"); 
    }
}

static void on_cached_session_get(fio_pubsub_engine_s* e, FIOBJ reply, void* udata)
{
    if(reply == FIOBJ_INVALID){
        log_error("Reply is invalid object, aborting...");
        return;
    }
    fio_str_info_s rsinfo = fiobj_obj2cstr(reply);
    log_debug("Cached session: %d", rsinfo.len);
    char* decoded_reply_str = malloc(rsinfo.len*3 + 3);
    int actually_written = fio_base64_decode(decoded_reply_str, rsinfo.data, rsinfo.len*3);
    log_debug("Cached, decoded session: %s", decoded_reply_str);
    log_debug("Actually written: %d", actually_written);
}

void pass_chat_message(char* sess_id, char* request, char** response, http_sse_s* hssi)
{
    req_handle = request;
    char* session_cache_id = malloc(strlen(sess_id)+strlen("_session_store"));
    sprintf(session_cache_id, "%s_%s", sess_id, "session_store");
    bool store_exists = redis_contains_key(session_cache_id);
    if (store_exists == true)
    {
        FIOBJ get_session_command = fiobj_ary_new();
        fiobj_ary_push(get_session_command, fiobj_str_new(GET, GET_L));
        fiobj_ary_push(get_session_command, fiobj_str_new(session_cache_id, strlen(session_cache_id)));
        log_debug("SCI: %s", session_cache_id);
        redis_engine_send(FIO_PUBSUB_DEFAULT, get_session_command, on_cached_session_get, NULL);
    }

    log_debug("Current SSE handle: %p", hssi);
    http_sse_write(hssi, .id = { .data = sess_id, .len = strlen(sess_id)}, 
                         .data = { .data = sess_id, .len = strlen(sess_id) }, 
                         .event = { .data = "ctlmessage", .len = 10}                         
                         );
    intptr_t status = http_connect("http://192.168.1.253:11434/api/chat", NULL, .on_response = on_response, .udata = hssi);
    FIOBJ hash = fiobj_hash_new();
    FIOBJ key = fiobj_str_new("process_id", 11);
    if(status != -1){
        FIOBJ value = fiobj_str_new(sess_id, strlen(sess_id));
        int res = fiobj_hash_set(hash, key, value);
        if(res == -1){
            log_fatal("There was an issue on error handler.");
            fiobj_free(key);
            fiobj_free(hash);
            return;
        }
        *response = fiobj_obj2cstr(fiobj_obj2json(hash, 1)).data;
        fiobj_free(value);
    } else {
        FIOBJ value = FIOBJ_INVALID;
        int res = fiobj_hash_set(hash, key, value);
        if(res == -1){
            log_fatal("There was an issue on error handler.");
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