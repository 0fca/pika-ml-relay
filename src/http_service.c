#include "main.h"

static FIOBJ paths = FIOBJ_INVALID;

int compare_string(FIOBJ str, char* plain)
{
    fio_str_info_s info = fiobj_obj2cstr(str);
    char* mt = info.data;
    return strcmp(mt, plain);
}

static void on_chat_message(http_s *h) {
  FIOBJ json = h->body;
  if(fiobj_type(json) == FIOBJ_T_NULL){
    http_send_error(h, (size_t)400);
  }
  char* response;
  pass_chat_message("{\"model\":\"llama3.2\",\"stream\":false,\"messages\":[{\"content\":\"Dzie\u0144 dobry\",\"role\":\"user\"}]}", &response);
  http_send_body(h, response, 13);
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

/* starts a listeninng socket for HTTP connections. */
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
