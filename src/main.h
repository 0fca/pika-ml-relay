#include <fio.h>
#include <fiobj.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>

#include "cli.h"
#include "fio_cli.h"
#include "redis_engine.h"
#include "http.h"
#include "ollama_utils.h"
#include "tools_utils.h"
#include "http_service.h"
#include "relay_util.h"
#include "redis_service.h"
#include "log.h"


#define HTTP_HEADER_LOCATION "location"
#define HTTP_HEADER_CONTENT_DISPOSITION "content-disposition"

int compare_string(FIOBJ str, char* plain);
char* read_string_since(char* str, const char* delim);
char* parse_content_disposition(char* cd_str);
long mstons(long milis);
void await_for_lock(fio_lock_i* lock);
char *read_until_delim(char **buffer, char start_token, char delim);
char *concat(const char *s1, const char *s2);
int contains_substring(const char *haystack, const char *needle);