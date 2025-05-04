#include "stdbool.h"

char* newest_message_from_request(const char* request);
void apnd_toolsec2req(FIOBJ container, char** req_handle);
void apnd_syssec2req(FIOBJ container, char** req_handle);
void push_on_top_curr_req_messages(FIOBJ message, char** req_handle);
void update_curr_req_handle_messages(FIOBJ message, char** req_handle);
FIOBJ retrieve_req_handle_as_fiobj(char* req_handle);
bool set_llm_req_opt(char* optkey_s, FIOBJ value, char* req_handle);
