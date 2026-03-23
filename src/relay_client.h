#define CMD_LEN 16384
#define OUTPUT_SINGLE_L 16384
#define OUTPUT_L 65535
#define TOOL_SEC_L 65535
#define MODEL_NAME_L 32
#define PARAMS_L 2048
// Message types
#define CTL_MSG "ctlmessage"
#define ERR_MSG "errmessage"
#define DATA_MSG "datamessage"
#define USR_MSG "usermessage"

// Constant strings

#define OLLAMA_BASE_URL "http://192.168.1.252:11434"
#define OLLAMA_CHAT_ENDPOINT OLLAMA_BASE_URL "/api/chat"
#define OLLAMA_TAGS_ENDPOINT OLLAMA_BASE_URL "/api/tags"
#define TOOLSEC_TEMPLATE "{\"type\":\"function\", \"function\":{\"name\": \"%s\", \"description\": \"%s\", \"parameters\": %s}}"
#define CHUNK_BUFFER_SIZE 16384


void pass_chat_message(char* sess_id, char* message, char** response, http_sse_s* hssi, http_s *h);
void* parse_chunked_response(void *arg);
char* extract_auth_header(http_s *h);