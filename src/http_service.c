#include "main.h"

static FIOBJ paths = FIOBJ_INVALID;
static size_t is_chat_result = 0;

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

// Callbacks

void on_channel_message(fio_msg_s *msg)
{
  is_chat_result = 1;
}

void on_get_command(fio_pubsub_engine_s* engine, FIOBJ reply, void *udata)
{
    if(reply == FIOBJ_INVALID)
    {
        fprintf(stderr, "It appears that there was an error on Redis op");
    }

    fprintf(stderr, fiobj_obj2cstr(reply).data);
    //fprintf(stderr, "%s", (char*)udata);
}

void on_chat_message(http_s *h) {
  FIOBJ json = h->body;
  size_t is_post = compare_string(h->method, "POST");
  // TODO: To be extracted further
  if(fiobj_type(json) == FIOBJ_T_NULL && is_post == 0){
    http_send_error(h, (size_t)400);
    return;
  }
  char* sess_id_raw = fiobj_obj2cstr(h->query).data;
  fprintf(stderr, "hs.c: %ld", strlen(sess_id_raw) * sizeof(char) + 1);
  //char* res = sess_id_raw;//malloc(strlen(sess_id_raw) * sizeof(char) + 1);
  sess_id_raw = read_string_since(sess_id_raw);

  fprintf(stderr, "%s\n", sess_id_raw);
  if(is_post == 0){
    char* response;
    char* request_body = fiobj_obj2cstr(json).data;
    pass_chat_message(sess_id_raw, request_body, &response);
    http_send_body(h, response, strlen(response));
  }
  if(compare_string(h->method, "GET") == 0){
    int c_count = 6 + strlen(sess_id_raw);
    char* get_command_str = malloc(c_count * sizeof(char));
    snprintf(get_command_str, c_count, "%s %s", "GET", sess_id_raw);
    FIOBJ get_command = fiobj_str_new(get_command_str, strlen(get_command_str));
    redis_engine_send(FIO_PUBSUB_DEFAULT, get_command, on_get_command, "");
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

void initialize_http_service(void) {
  FIOBJ s = fiobj_str_new("ollama_callback", 16);
  fio_str_info_s channel = fiobj_obj2cstr(s);
  fio_subscribe(.channel = channel, .on_message = on_channel_message);
  fiobj_free(s);
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
