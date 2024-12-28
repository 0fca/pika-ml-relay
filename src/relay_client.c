#include "main.h"
#include <sys/ipc.h>
#include <sys/shm.h>

static char* req_handle;
static int sess_shm_id;

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
    char* shm_addr;
    char* sess_handle = (char*)shmat(sess_shm_id, shm_addr, 0);
    fio_str_info_s ollama_res = fiobj_obj2cstr(h->body);
    int data_len = ollama_res.len;
    char* encoded_data = malloc(256);
    fio_base64_encode(encoded_data, ollama_res.data, data_len);
    size_t set_count = 4 + strlen(sess_handle) + strlen(encoded_data);
    char* set_str = malloc(set_count);
    snprintf(set_str, set_count, "%s %s %s", "SET", (char*)sess_handle, encoded_data);
    FIOBJ set_command = fiobj_str_new(set_str, strlen(set_str));
    redis_engine_send(FIO_PUBSUB_DEFAULT, set_command, redis_callback, NULL);
    FIOBJ s = fiobj_str_new("ollama_callback", 16);
    fio_str_info_s channel = fiobj_obj2cstr(s);
    FIOBJ m = fiobj_str_new(encoded_data, strlen(encoded_data));
    fio_str_info_s message = fiobj_obj2cstr(m);
    fio_publish(.engine = FIO_PUBSUB_ROOT, .channel = channel, .message = message, .is_json = 0);
    shmdt(sess_handle);
}

void pass_chat_message(char* sess_id, char* request, char** response)
{
    sess_shm_id = shmget(IPC_PRIVATE, 1024, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
    char* addr;
    char* sess_handle = shmat(sess_shm_id, addr, 0);
    sprintf(sess_handle, "%s", sess_id);
    shmdt(sess_handle);
    req_handle = request;
    intptr_t status = http_connect("http://127.0.0.1:11434/api/chat", NULL, .on_response = on_response);
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