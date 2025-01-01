#include "main.h"

static bool key_exists = false;

void initialize_redis()
{
    fio_pubsub_engine_s *r = redis_engine_create(.address.data = "127.0.0.1");
    if (!r)
    {
        perror("Couldn't initialize Redis");
        exit(-1);
    }
    fio_state_callback_add(FIO_CALL_AT_EXIT,
                           (void (*)(void *))redis_engine_destroy, r);
    FIO_PUBSUB_DEFAULT = r;
}


void on_redis_keys_command(fio_pubsub_engine_s* engine, FIOBJ reply, void *udata)
{
    key_exists = false;
    if(reply == FIOBJ_INVALID)
    {
        log_error("Couldn't read KEYS from Redis");
        return;
    }
    
    char* key = fiobj_obj2cstr(fiobj_ary_pop(reply)).data;
    log_debug("%s : %s", key, (char*)udata);
    if(strcmp(key, (char*)udata) == 0)
    {
        key_exists = true;
    }
    log_debug("%d", key_exists);
}

bool redis_contains_key(char* key)
{
    FIOBJ keys_command = fiobj_ary_new();
    char* pattern = malloc(strlen(key) + 2);
    sprintf(pattern, "%s", key);
    fiobj_ary_push(keys_command, fiobj_str_new("KEYS", 4));
    fiobj_ary_push(keys_command, fiobj_str_new(pattern, strlen(pattern)));
    redis_engine_send(FIO_PUBSUB_DEFAULT, keys_command, on_redis_keys_command, key);
    // shall rewrite it using fio_* functions for threads and locking
    sleep(1);
    return key_exists;
}
