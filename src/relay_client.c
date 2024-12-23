#include "main.h"

static char* req_handle;
char* sess_handle;

static void on_response(http_s *h)
{
    if (h->status_str == FIOBJ_INVALID)
    {
        h->method = fiobj_str_new("POST", 4);
        FIOBJ json_container = FIOBJ_INVALID;
        http_send_body(h, req_handle, strlen(req_handle));
        fiobj_free(json_container);
        return;
    }
    fio_str_info_s ollama_res = fiobj_obj2cstr(h->body);
    int c_count = strlen(sess_handle) + strlen(ollama_res.data);
    char* set_str = malloc(c_count * sizeof(char));
    int data_len = ollama_res.len;
    char* encoded_data;
    encoded_data = malloc(strlen(ollama_res.data) * sizeof(char));
    fio_base64_encode(encoded_data, ollama_res.data, data_len);
    snprintf(set_str,  c_count, "%s %s %s", "SET", sess_handle, encoded_data);
    FIOBJ set_command = fiobj_str_new(set_str, strlen(set_str));
    fprintf(stderr, set_str);
    redis_engine_send(FIO_PUBSUB_DEFAULT, set_command, redis_callback, NULL);
    FIOBJ s = fiobj_str_new("ollama_callback", 16);
    fio_str_info_s channel = fiobj_obj2cstr(s);
    FIOBJ m = fiobj_str_new(encoded_data, strlen(encoded_data));
    fio_str_info_s message = fiobj_obj2cstr(m);
    fio_publish(.engine = FIO_PUBSUB_DEFAULT, .channel = channel, .message = message, .is_json = 0);
    free(encoded_data);
    free(set_str);
    free(sess_handle);
}

void pass_chat_message(char* sess_id, char* request, char** response)
{
    req_handle = request;
    //char* local_sess_handle = malloc(strlen(sess_id) * sizeof(char) + sizeof(char));
    sess_handle = malloc(strlen(sess_id) * sizeof(char) + 1);
    if(sess_handle == NULL){
        fprintf(stderr, "%s", "Sess_handle failed to allocate");
        return;
    }
    //memcpy(sess_handle, sess_id, strlen(sess_id)+1);
    fprintf(stderr, "t: %s\n", sess_handle);
    intptr_t status = http_connect("http://192.168.1.253:11434/api/chat", NULL, .on_response = on_response);
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