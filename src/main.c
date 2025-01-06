#include "main.h"

void await_for_lock(fio_lock_i* lock)
{
  while(1)
    {
        fio_throttle_thread(mstons(10));
        if(fio_is_locked(lock) == 0)
        {
            return;
        }
    }
}

int compare_string(FIOBJ str, char* plain)
{
  fio_str_info_s info = fiobj_obj2cstr(str);
  char* mt = info.data;
  return strcmp(mt, plain);
}

char* read_string_since(char* str, const char* delim)
{
  char* result = strsep(&str, delim);
  result = strsep(&str, delim);
  return result;
}

char* parse_content_disposition(char* cd_str)
{
    char* fname = read_string_since(cd_str, ";");
    fname = read_string_since(fname, "=");
    return fname;
}

long mstons(long milis)
{
  return milis * 10000 * 100;
}

void initialize_log(){
  FILE* log_fp;
  time_t* timer = malloc(32);
  time(timer);
  struct tm* tmbuf = gmtime(timer);
  char* formatted_time = malloc(32);
  http_date2rfc2822(formatted_time, tmbuf);
  formatted_time = read_string_since(formatted_time, " ");
  char* fname = malloc(64);
  sprintf(fname, "./log/relay_%s.log", formatted_time);
  log_fp = fopen(fname, "a");
  int log_level = fio_cli_get_i("-llog");
  if(log_level == 0)
  {
    log_level = LOG_INFO;
  }
  log_add_fp(log_fp, log_level);
  log_set_level(log_level);
  log_set_quiet(fio_cli_get_bool("-q"));
}

int main(int argc, char const *argv[]) {
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
