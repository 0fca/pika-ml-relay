#include "main.h"
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>


static FIOBJ paths = FIOBJ_INVALID;
static http_sse_s* hssi = NULL;

// String functions

int compare_string(FIOBJ str, char* plain)
{
  fio_str_info_s info = fiobj_obj2cstr(str);
  char* mt = info.data;
  return strcmp(mt, plain);
}

char* read_string_since(char* str)
{
  char* result = strsep(&str, "=");
  result = strsep(&str, "=");
  return result;
}

void on_chat_message(http_s *h) {
  FIOBJ json = h->body;
  size_t is_post = compare_string(h->method, "POST");
  size_t is_get = compare_string(h->method, "GET");
  // TODO: To be extracted further
  if(fiobj_type(json) == FIOBJ_T_NULL && is_post == 0){
    http_send_error(h, (size_t)400);
    return; 
  }
  char* sess_id_raw = fiobj_obj2cstr(h->query).data;
  sess_id_raw = read_string_since(sess_id_raw);

  if(is_post == 0){
    char* response;
    char* request_body = fiobj_obj2cstr(json).data;
    pass_chat_message(sess_id_raw, request_body, &response, hssi);
    http_send_body(h, response, strlen(response));
  }
  if(is_get == 0){
    http_send_error(h, (size_t)400);
  }
  fiobj_free(json);
}

static void on_http_request(http_s *h) {
  for(size_t i = 0; i < fiobj_hash_count(paths); i++){
    FIOBJ key = fiobj_num_new((intptr_t)i);
    char* path = fiobj_obj2cstr(fiobj_hash_get(paths, key)).data;
    if(compare_string(h->path, path) == 0){
      if(strcmp(path, "/chat/message") == 0){
        on_chat_message(h);
        break;
      }
    }
  }
}

static void on_sse_open(http_sse_s* sse) {
  hssi = http_sse_dup(sse);
  http_sse_set_timout(hssi, fio_cli_get_i("-ping"));
}

static void on_sse_ready(http_sse_s* sse){
  fprintf(stderr, "%s", "OK\n");
}

static void on_sse_cleanup(http_sse_s* sse){
  http_sse_free(hssi);
  http_sse_close(sse);
}

static void on_sse_close(http_sse_s* sse){
  http_sse_free(hssi);
  http_sse_close(sse);
  fprintf(stderr, "%s\n", "DISCONN");
}

static void on_sse_upgrade(http_s* request, char* requested_protocol, size_t len)
{
  fprintf(stderr, "Upgrade request for: %s\n", requested_protocol);
  http_upgrade2sse(request, .on_open = on_sse_open, 
                  .on_ready = on_sse_ready, 
                  .on_close = on_sse_close, 
                  .on_shutdown = on_sse_cleanup
  );
}

void initialize_http_service(void) {
  paths = fiobj_hash_new();
  const char* config_path = fio_cli_get("-cfg");
  FILE* config_f_struct;
  config_f_struct = fopen(config_path, "r");
  if(config_f_struct == NULL){
    // Failover cause there is no config file, cannot proceed.
    printf("Aborting because there is no config file.\n");
    exit(-1);
  }
  int config_fd = fileno(config_f_struct);
  FIOBJ holder = fiobj_data_newfd(config_fd);  
  fio_str_info_s stream = fiobj_data_read(holder, 0);
  FIOBJ container = FIOBJ_INVALID;
  size_t consumed = fiobj_json2obj(&container, stream.data, strlen(stream.data));
  FIOBJ endpoints_key = fiobj_str_new("endpoints", 9);
  if (consumed > 0 
      && FIOBJ_TYPE_IS(container, FIOBJ_T_HASH)
      && fiobj_hash_get(container, endpoints_key)) { 
    FIOBJ endpoints = fiobj_hash_get(container, endpoints_key);
    fiobj_type_enum array_t = FIOBJ_T_ARRAY;
    size_t endpoints_type = fiobj_type_is(endpoints, array_t);
    if(endpoints_type == 1)
    {
      for(size_t i = 0; i < fiobj_ary_count(endpoints); i++){
        const char* path = fiobj_obj2cstr(fiobj_ary_index(endpoints, i)).data;
        FIOBJ key = fiobj_num_new((intptr_t)i);
        int res = fiobj_hash_set(paths, key, fiobj_dup(fiobj_ary_index(endpoints, i)));
        if(res == -1){
          continue;
        }
        fiobj_free(key);
      }
    }
  }
  fiobj_free(endpoints_key);
  fiobj_free(container);
  fiobj_free(holder);

  if (http_listen(fio_cli_get("-p"), fio_cli_get("-b"),
                  .on_request = on_http_request,
                  .on_upgrade = on_sse_upgrade,
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
