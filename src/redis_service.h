#include <stdbool.h>
#define GET "GET"
#define GET_L 3


void initialize_redis();
bool redis_contains_key(char* key);
static void on_redis_keys_command(fio_pubsub_engine_s* engine, FIOBJ reply, void *udata);