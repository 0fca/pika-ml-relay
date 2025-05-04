#include "main.h"

// It is just a default value so to be sure that the server will run anything on Ollama or at least will try to
// It is to be populated from config.json at relay init.
const char* tool_support[1] = {"granite3.1-dense:8b"}; 

void extract_model(char** model, char* request)
{
    FIOBJ holder = FIOBJ_INVALID;
    fiobj_json2obj(&holder, request, strlen(request));
    if(fiobj_type_is(holder, FIOBJ_T_HASH) == 1)
    {
        FIOBJ modelkey = fiobj_str_new("model", 5);
        FIOBJ model_str = fiobj_hash_get(holder, modelkey);
        if(model_str != FIOBJ_INVALID)
        {
            *model = fiobj_obj2cstr(model_str).data;
        }
    }
}

bool supports_tools(char* model)
{
    for(int i = 0; i < 1; i++)
    {
        if(strcmp(model, tool_support[i]) == 0)
        {
            log_debug("ST: %s", model);
            return true;
        }
    }
    return false;
}

size_t write_curl_callback(void* ptr, size_t size, size_t nmemb, FILE* fp)
{
    size_t written = fwrite(ptr, size, nmemb, fp);
    return written;
}

int iterate_over_args(FIOBJ o, void* parsed)
{
    char* param = fiobj_obj2cstr(o).data;
    char* enclosed_param = malloc(strlen(param));
    sprintf(enclosed_param, "'%s'", param);
    strcat(parsed, enclosed_param);
    strcat(parsed, " ");
    free(enclosed_param);
    return 0;
}

void parse_arguments_hash(FIOBJ arguments, char* parsed)
{
    if(fiobj_type_is(arguments, FIOBJ_T_HASH) == 0)
    {
        return;
    }
    size_t ret = fiobj_each1(arguments, (size_t)0, iterate_over_args, parsed);
    log_debug("Parsed Params From Function: %s", parsed);
}


void execute_download(char* full_url, char *name)
{
    log_debug("DWN: %s", full_url);
    CURL *curl = curl_easy_init();
    if(curl){
        FILE* fp = fopen(name, "wb+");
        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_curl_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        fclose(fp);
    }
}

void download_tool(char *tool_url, char *name)
{
    /*shmfid = shmget(IPC_PRIVATE, strlen(name), IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
    char *fname_addr;
    char *shmfname = shmat(shmfid, fname_addr, 0);
    sprintf(shmfname, "%s", name);
    shmdt(shmfname);*/
    execute_download(tool_url, name);
}
