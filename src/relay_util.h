int iterate_over_args(FIOBJ o, void* parsed);
void parse_arguments_hash(FIOBJ arguments, char* parsed);
size_t write_curl_callback(void* ptr, size_t size, size_t nmemb, FILE* fp);
void download_tool(char *tool_url, char *name);
bool supports_tools(char* model);
void extract_model(char** model, char* request);
