#include "main.h"

void initialize_log(){
  FILE* log_fp;
  time_t* timer = malloc(32);
  time(timer);
  struct tm* tmbuf = gmtime(timer);
  char* formatted_time = malloc(32);
  http_date2rfc2822(formatted_time, tmbuf);
  char* fname = malloc(64);
  sprintf(fname, "./log/relay_%s.log", formatted_time);
  log_fp = fopen(fname, "w+");
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
