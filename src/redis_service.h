#include <stdbool.h>
// We use HGET because .NET library used by ApiService uses hashes to store strings.
#define GET "HGET"
#define GET_L 4


void initialize_redis();
bool redis_contains_key(char* key);
static void on_redis_keys_command(fio_pubsub_engine_s* engine, FIOBJ reply, void *udata);