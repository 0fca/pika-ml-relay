void initialize_redis();
void redis_callback(fio_pubsub_engine_s* engine, FIOBJ reply, void *udata);