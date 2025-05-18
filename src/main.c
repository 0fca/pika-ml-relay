#include "main.h"

#define DEFAULT_AWAIT_MS 10
#define DEFAULT_TIMEOUT DEFAULT_AWAIT_MS * 10

void await_for_lock(fio_lock_i *lock)
{
  int timeout_counter = 0;
  while (1)
  {
    fio_throttle_thread(mstons(DEFAULT_AWAIT_MS));
    if (fio_is_locked(lock) == 0 || timeout_counter >= DEFAULT_TIMEOUT)
    {
      log_debug("Freeing lock, either because unlocked or timeout hit in");
      return;
    }
    timeout_counter += 1;
  }
}

int compare_string(FIOBJ str, char *plain)
{
  fio_str_info_s info = fiobj_obj2cstr(str);
  char *mt = info.data;
  return strcmp(mt, plain);
}

char *read_string_since(char *str, const char *delim)
{
  if (strstr(str, delim) == NULL)
  {
    return str;
  }
  char *result = strsep(&str, delim);
  result = strsep(&str, delim);
  return result;
}

char *parse_content_disposition(char *cd_str)
{
  char *fname = read_string_since(cd_str, ";");
  fname = read_string_since(fname, "=");
  return fname;
}

long mstons(long milis)
{
  return milis * 10000 * 100;
}

char *read_until_delim(char **buffer, char start_token, char delim) {
    if (!buffer || !*buffer) return NULL;

    char *start = strchr(*buffer, start_token);
    if (!start) return NULL;

    char *end = strchr(start, delim);
    size_t len = end ? (size_t)(end - start) : strlen(start);

    char *result = malloc(len + 1);
    if (!result) return NULL;
    memcpy(result, start, len);
    result[len] = '\0';

    if (end)
        *buffer = end + 1;
    else
        *buffer = start + len;

    return result;
}

char *concat(const char *s1, const char *s2) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    char *result = malloc(len1 + len2 + 1); // +1 for the null terminator
    if (!result) return NULL;
    memcpy(result, s1, len1);
    memcpy(result + len1, s2, len2 + 1); // +1 to copy the null terminator
    return result;
}

// Returns 1 if 'needle' is found anywhere in 'haystack', 0 otherwise.
int contains_substring(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    return strstr(haystack, needle) != NULL ? 1 : 0;
}

void initialize_log()
{
  FILE *log_fp;
  time_t *timer = malloc(32);
  time(timer);
  struct tm *tmbuf = gmtime(timer);
  char *formatted_time = malloc(32);
  http_date2rfc2822(formatted_time, tmbuf);
  formatted_time = read_string_since(formatted_time, " ");
  char *fname = malloc(64);
  sprintf(fname, "./log/relay_%s.log", formatted_time);
  log_fp = fopen(fname, "a");
  int log_level = fio_cli_get_i("-llog");
  if (log_level == 0)
  {
    log_level = LOG_INFO;
  }
  log_add_fp(log_fp, log_level);
  log_set_level(log_level);
  log_set_quiet(fio_cli_get_bool("-q"));
  free(fname);
}

int main(int argc, char const *argv[])
{
  /* accept command line arguments and setup default values, see "cli.c" */
  initialize_cli(argc, argv);

  initialize_log();

  initialize_redis();

  /* initialize HTTP service, see "http_service.h" */
  initialize_http_service();

  /* start facil */
  fio_start(.threads = fio_cli_get_i("-t"), .workers = fio_cli_get_i("-w"));

  /* cleanup CLI, see "cli.c" */
  free_cli();
  return 0;
}
