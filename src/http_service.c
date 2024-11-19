#include "fio_cli.h"
#include "main.h"

int compare_string(FIOBJ str, char* plain)
{
    fio_str_info_s info = fiobj_obj2cstr(str);
    char* mt = info.data;
    return strcmp(mt, plain);
}

static void on_http_request(http_s *h) {
  const int isPost = compare_string(h->method, "POST");
  if(isPost == 0){
    on_post_request(h);
    return;
  }
  FIOBJ json = h->body;
  int res = fiobj_data_save(json, "data.dump.json");
  if(res == 0)
  {
      http_send_body(h, "dumped to file", 15);
  }
  http_send_body(h, "error", 5);
}

/* starts a listeninng socket for HTTP connections. */
void initialize_http_service(void) {
  /* listen for inncoming connections */
  if (http_listen(fio_cli_get("-p"), fio_cli_get("-b"),
                  .on_request = on_http_request,
                  .max_body_size = fio_cli_get_i("-maxbd") * 1024 * 1024,
                  .ws_max_msg_size = fio_cli_get_i("-max-msg") * 1024,
                  .public_folder = fio_cli_get("-public"),
                  .log = fio_cli_get_bool("-log"),
                  .timeout = fio_cli_get_i("-keep-alive"),
                  .ws_timeout = fio_cli_get_i("-ping")) == -1) {
    /* listen failed ?*/
    perror("ERROR: facil couldn't initialize HTTP service (already running?)");
    exit(1);
  }
}

void on_post_request(http_s *h)
{
  const int isPostPath = compare_string(h->path, "/path");
  printf("%d", isPostPath);
  if(isPostPath == 0)
  {
    http_send_body(h, "post path", 10);
    return;
  }
  http_send_error(h, (size_t)405);
  return;
}
