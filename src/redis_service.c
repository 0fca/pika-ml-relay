#include "redis_engine.h"

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

void redis_callback(fio_pubsub_engine_s* engine, FIOBJ reply, void *udata)
{
    if(reply == FIOBJ_INVALID)
    {
        fprintf(stderr, "It appears that there was an error on Redis op");
    }

    fprintf(stderr, "%ld", fiobj_obj2cstr(reply).len);
}
