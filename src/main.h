#include <fio.h>
#include <fiobj.h>
#include <unistd.h>
#include <time.h>

#include "cli.h"
#include "fio_cli.h"
#include "redis_engine.h"
#include "http.h"
#include "http_service.h"
#include "relay_client.h"
#include "redis_service.h"
#include "log.h"

#define HTTP_HEADER_LOCATION "location"
#define HTTP_HEADER_CONTENT_DISPOSITION "content-disposition"

int compare_string(FIOBJ str, char* plain);
char* read_string_since(char* str, const char* delim);
char* parse_content_disposition(char* cd_str);
long mstons(long milis);
void await_for_lock(fio_lock_i* lock);



