#include "main.h"
#include <sys/ipc.h>
#include <sys/shm.h>

static char* req_handle;
static http_sse_s* hssi_g = NULL;

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
        fprintf(stderr, "%ld\n", hssi_g);
        http_sse_write(hssi_g, .data = fiobj_obj2cstr(fiobj_str_new(ollama_res.data, strlen(ollama_res.data))), .event = { .data = "usermessage", .len = 11});
        fprintf(stderr, "%s\n", "RELAY-OK"); 
    }
}

void pass_chat_message(char* sess_id, char* request, char** response, http_sse_s* hssi)
{
    req_handle = request;
    http_sse_write(hssi, .data = { .data = sess_id, .len = strlen(sess_id) }, .event = { .data = "ctlmessage", .len = 10}, .retry = 10);
    intptr_t status = http_connect("http://192.168.1.253:11434/api/chat", NULL, .on_response = on_response, .udata = hssi);
    FIOBJ hash = fiobj_hash_new();
    FIOBJ key = fiobj_str_new("process_id", 11);
    if(status != -1){
        FIOBJ value = fiobj_str_new(sess_id, strlen(sess_id));
        int res = fiobj_hash_set(hash, key, value);
        if(res == -1){
            fprintf(stderr, "There was an issue on error handler.");
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
            fprintf(stderr, "There was an issue on error handler.");
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