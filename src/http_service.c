#include "main.h"


static FIOBJ paths = FIOBJ_INVALID;
// hssi_s is actually a hash
// volatile allows the server to run in 1 worker, but in multi-threaded mode
// should move to IPC mechanism
volatile FIOBJ hssi_s = FIOBJ_INVALID;

fio_lock_i memory_execution_lock;

static char* rhmem = NULL;
static size_t rhsize = 512;

// Helper functions

static void* create_shared_memory(size_t size)
{
  int protection = PROT_READ | PROT_WRITE;
  int visibility = MAP_SHARED | MAP_ANONYMOUS;
  return mmap(NULL, size, protection, visibility, -1, 0);
}

static void erase_shmem(size_t size)
{
  int r = munmap(NULL, size);
  if(r != 0)
  {
    log_error("%s", "Failed to unmap memory");
  }
}

static void on_memory_header_present(http_s *h)
{
  FIOBJ headers = h->headers;
  FIOBJ r = http_req2str(h);
  log_debug("MEM-REQ: %s", fiobj_obj2cstr(r).data);
  FIOBJ mem_hdr_key = fiobj_str_new("x-memory", 8);
  int is_present = fiobj_hash_haskey(headers, mem_hdr_key);
  log_debug("MEM-HDR: %d", is_present);
  if(is_present == 1)
  {
    FIOBJ memory_config = fiobj_hash_get(headers, mem_hdr_key);
    log_debug("HDR-TYPE: %s", fiobj_type_name(memory_config));
    if(fiobj_type_is(memory_config, FIOBJ_T_STRING) == 1)
    {
      FIOBJ mem_off_str = fiobj_str_new("0", 1);

      if(strcmp(fiobj_obj2cstr(memory_config).data, fiobj_obj2cstr(mem_off_str).data) == 0)
      {
        log_debug("Memory header is set to 0, skipping");
        return;
      }
      fio_str_info_s b = fiobj_obj2cstr(h->body);
      char* msg = newest_message_from_request(b.data);
      char* model = malloc(MODEL_NAME_L);
      FIOBJ query_cp = fiobj_str_copy(h->query);
      char* sessid = fiobj_obj2cstr(query_cp).data;
      sessid = read_string_since(sessid, "=");
      extract_model(&model, b.data);
      log_debug("%s, \"%s\", %s", model, msg, sessid);
      size_t alloc_size = strlen(msg) + strlen(model) + strlen(sessid);
      char* memory_params = malloc(alloc_size);
      sprintf(memory_params, "%s %s", model, sessid);
      FILE *fp;
      char* fname = malloc(strlen(sessid)+14); // + 14 because we add _message suffix to it
      sprintf(fname, "tools/%s_message", sessid);
      fp = fopen(fname, "w");
      fprintf(fp, "%s", msg);
      fclose(fp);
      log_debug("Mem Params: %s", memory_params);
      // Memory script shall be deployed not as a tool, but with a server itself or configured through .json
      char* memory_result = malloc(16834);
      fio_trylock(&memory_execution_lock);
      execute_tool(&memory_result, "python", "tools/memory.py", memory_params, memory_execution_lock);
      await_for_lock(&memory_execution_lock);
      log_debug("MEM_RES: %s", memory_result);
      FIOBJ memory_message = fiobj_hash_new();
      // FIXME: Move keys and value objects into refference access variable, so those could be freed
      fiobj_hash_set(memory_message, fiobj_str_new("role", 4), fiobj_str_new("system", 6));
      fiobj_hash_set(memory_message, fiobj_str_new("content", 7), fiobj_str_new(memory_result, strlen(memory_result)));
      char* req_handle = malloc(b.len);
      sprintf(req_handle, "%s", b.data);
      push_on_top_curr_req_messages(memory_message, &req_handle);
      rhsize = strlen(req_handle);
      if(rhmem == NULL){
        rhmem = (char*)create_shared_memory(rhsize);
      }
      log_debug("RH: %s", req_handle);
      strncpy(rhmem, req_handle, rhsize);
      fiobj_free(query_cp);
      fiobj_free(headers);
      fiobj_free(r);
      fiobj_free(mem_hdr_key);
      fiobj_free(memory_config);
      free(fname);
      free(memory_params);
    }
  }
}

static void on_chat_message(http_s *h) {
  FIOBJ json = h->body;
  size_t is_post = compare_string(h->method, "POST");
  size_t is_get = compare_string(h->method, "GET");
  if(fiobj_type(json) == FIOBJ_T_NULL && is_post == 0){
    http_send_error(h, (size_t)400);
    return; 
  }
  FIOBJ query_cp = fiobj_str_copy(h->query);
  char* sess_id_raw = fiobj_obj2cstr(query_cp).data;
  log_debug("%s", sess_id_raw);
  sess_id_raw = read_string_since(sess_id_raw, "=");

  if(is_post == 0){
    char* response;
    log_debug("%d", rhsize);
    char* request_body = malloc(rhsize);
    if(rhmem == NULL){
      fio_str_info_s rb = fiobj_obj2cstr(json);
      strncpy(request_body, rb.data, rb.len);
    } 
    else 
    {
      strncpy(request_body, rhmem, rhsize);
      log_debug("HND: %s %s", request_body, (char*)rhmem);
      erase_shmem(rhsize);
    }
    FIOBJ key = fiobj_str_new(sess_id_raw, strlen(sess_id_raw));
    http_sse_s* hssi = (http_sse_s*)fiobj_ptr_unwrap(fiobj_hash_get(hssi_s, key));
    log_debug("HSSI handles count: %d", fiobj_hash_count(hssi_s));
    log_debug("RB to pass: %s", request_body);
    pass_chat_message(sess_id_raw, request_body, &response, hssi);
    if(strcmp(response, "no_id") == 0)
    {
      http_set_header(h, fiobj_str_new("X-Precondition", 13), fiobj_str_new("Sent too early, first initiate SSE connection", 46));
      char* loc_value = malloc(strlen(sess_id_raw)+9);
      sprintf(loc_value, "/sess_id=%s", sess_id_raw);
      http_set_header(h, fiobj_str_new("Location", 9), fiobj_str_new(loc_value, strlen(loc_value)));
      http_send_error(h, (size_t)412);
      return;
    }
    http_send_body(h, response, strlen(response));
    fiobj_free(key);
  }
  if(is_get == 0){
    http_send_error(h, (size_t)400);
  }
  fiobj_free(query_cp);
  fiobj_free(json);
}

// Server-based functions

static void on_http_request(http_s *h) {
  for(size_t i = 0; i < fiobj_hash_count(paths); i++){
    FIOBJ key = fiobj_num_new((intptr_t)i);
    char* path = fiobj_obj2cstr(fiobj_hash_get(paths, key)).data;
    if(compare_string(h->path, path) == 0){
      if(strcmp(path, "/chat/message") == 0){
        on_memory_header_present(h);
        on_chat_message(h);
        break;
      }
    }
  }
}

static void on_sse_open(http_sse_s* sse) {
  http_sse_set_timout(sse, fio_cli_get_i("-ping"));  
  FIOBJ val = fiobj_ptr_wrap(sse);
  FIOBJ skey = fiobj_str_new(sse->udata, strlen(sse->udata));
  log_debug("Handle wrapper pointer (On_SSE_Open): %p", val);
  int res = fiobj_hash_set(hssi_s, skey, val);
  if(res == -1){
    log_fatal("Moving sse object to shared hash failed.");
  }
}

static void on_sse_close(http_sse_s* sse){
  FIOBJ skey = fiobj_str_new(sse->udata, strlen(sse->udata));
  log_debug("%s :: %s", "TRY-DISCONN", sse->udata);
  fiobj_hash_remove(hssi_s, skey);
  log_debug("%s", "OK-DISCONN");
  log_info("Session for %s disconnected", sse->udata);
}

static void on_sse_upgrade(http_s* request, char* requested_protocol, size_t len)
{
  log_debug("UPREQ: %s", requested_protocol);
  char* sess_id_raw = fiobj_obj2cstr(request->query).data;
  if(compare_string(request->query, "null") == 0){
    log_fatal("Missing query, aborting upgrade");
    return;
  }
  sess_id_raw = read_string_since(sess_id_raw, "=");
  http_upgrade2sse(request, 
                  .on_open = on_sse_open, 
                  .on_close = on_sse_close, 
                  .udata = strdup(sess_id_raw)
  );
}

void initialize_http_service(void) {
  if(hssi_s == FIOBJ_INVALID){
    hssi_s = fiobj_hash_new();
  }
  paths = fiobj_hash_new();
  const char* config_path = fio_cli_get("-cfg");
  FILE* config_f_struct;
  config_f_struct = fopen(config_path, "r");
  if(config_f_struct == NULL){
    // Failover cause there is no config file, cannot proceed.
    log_error("Aborting because there is no config file.");
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
    log_fatal("ERROR: facil couldn't initialize HTTP service (already running?)");
    exit(1);
  }
}
