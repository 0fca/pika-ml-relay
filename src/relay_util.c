#include "main.h"
#include "relay_client.h"

// Dynamic model list loaded from Ollama /api/tags at startup.
// Falls back to config.json "tool_support" if present.
#define MAX_MODELS 64
static char* tool_support_models[MAX_MODELS];
static size_t tool_support_count = 0;
static char* all_model_names[MAX_MODELS];
static size_t all_model_count = 0;

// Curl write callback that appends to a string buffer
struct curl_string_buf {
    char *data;
    size_t len;
    size_t cap;
};

static size_t write_string_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t total = size * nmemb;
    struct curl_string_buf *buf = (struct curl_string_buf *)userdata;
    if (buf->len + total >= buf->cap) return 0; // overflow guard
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

void load_models_from_ollama(void)
{
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        log_error("Failed to init curl for model listing");
        return;
    }

    struct curl_string_buf buf;
    buf.cap = 65536;
    buf.data = calloc(buf.cap, 1);
    buf.len = 0;

    curl_easy_setopt(curl, CURLOPT_URL, OLLAMA_TAGS_ENDPOINT);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_string_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
    {
        log_error("Failed to fetch models from Ollama: %s", curl_easy_strerror(res));
        free(buf.data);
        return;
    }

    FIOBJ parsed = FIOBJ_INVALID;
    fiobj_json2obj(&parsed, buf.data, buf.len);
    free(buf.data);

    if (fiobj_type_is(parsed, FIOBJ_T_HASH) != 1)
    {
        log_error("Ollama /api/tags response is not a JSON object");
        fiobj_free(parsed);
        return;
    }

    FIOBJ models_key = fiobj_str_new("models", 6);
    FIOBJ models = fiobj_hash_get(parsed, models_key);
    if (models == FIOBJ_INVALID || fiobj_type_is(models, FIOBJ_T_ARRAY) != 1)
    {
        log_error("Ollama /api/tags has no models array");
        fiobj_free(models_key);
        fiobj_free(parsed);
        return;
    }

    // Clear old model lists
    for (size_t i = 0; i < all_model_count; i++) free(all_model_names[i]);
    all_model_count = 0;

    FIOBJ name_key = fiobj_str_new("name", 4);
    for (size_t i = 0; i < fiobj_ary_count(models) && all_model_count < MAX_MODELS; i++)
    {
        FIOBJ model = fiobj_ary_index(models, (int64_t)i);
        if (fiobj_type_is(model, FIOBJ_T_HASH) != 1) continue;
        FIOBJ name = fiobj_hash_get(model, name_key);
        if (name == FIOBJ_INVALID) continue;
        fio_str_info_s name_str = fiobj_obj2cstr(name);
        if (name_str.data && name_str.len > 0)
        {
            all_model_names[all_model_count] = strndup(name_str.data, name_str.len);
            log_info("Discovered model: %s", all_model_names[all_model_count]);
            all_model_count++;
        }
    }

    // If no tool_support configured from config, default all models as tool-capable
    if (tool_support_count == 0)
    {
        for (size_t i = 0; i < all_model_count && tool_support_count < MAX_MODELS; i++)
        {
            tool_support_models[tool_support_count] = strdup(all_model_names[i]);
            tool_support_count++;
        }
    }

    fiobj_free(name_key);
    fiobj_free(models_key);
    fiobj_free(parsed);
    log_info("Loaded %zu models from Ollama (%zu tool-capable)", all_model_count, tool_support_count);
}

void load_tool_support_from_config(FIOBJ config)
{
    FIOBJ key = fiobj_str_new("tool_support", 12);
    FIOBJ arr = fiobj_hash_get(config, key);
    if (arr != FIOBJ_INVALID && fiobj_type_is(arr, FIOBJ_T_ARRAY) == 1)
    {
        // Clear existing
        for (size_t i = 0; i < tool_support_count; i++) free(tool_support_models[i]);
        tool_support_count = 0;

        for (size_t i = 0; i < fiobj_ary_count(arr) && tool_support_count < MAX_MODELS; i++)
        {
            FIOBJ entry = fiobj_ary_index(arr, (int64_t)i);
            fio_str_info_s s = fiobj_obj2cstr(entry);
            if (s.data && s.len > 0)
            {
                tool_support_models[tool_support_count] = strndup(s.data, s.len);
                log_info("Tool-capable model (config): %s", tool_support_models[tool_support_count]);
                tool_support_count++;
            }
        }
    }
    fiobj_free(key);
}

FIOBJ get_models_json(void)
{
    FIOBJ result = fiobj_hash_new();
    FIOBJ models_arr = fiobj_ary_new();
    for (size_t i = 0; i < all_model_count; i++)
    {
        FIOBJ entry = fiobj_hash_new();
        fiobj_hash_set(entry, fiobj_str_new("name", 4),
                       fiobj_str_new(all_model_names[i], strlen(all_model_names[i])));
        fiobj_hash_set(entry, fiobj_str_new("supports_tools", 14),
                       supports_tools(all_model_names[i]) ? fiobj_true() : fiobj_false());
        fiobj_ary_push(models_arr, entry);
    }
    fiobj_hash_set(result, fiobj_str_new("models", 6), models_arr);
    return result;
}

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
    for(size_t i = 0; i < tool_support_count; i++)
    {
        if(strcmp(model, tool_support_models[i]) == 0)
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
    char* param = NULL;
    FIOBJ json_str = FIOBJ_INVALID;
    if (fiobj_type_is(o, FIOBJ_T_STRING) == 1)
    {
        param = fiobj_obj2cstr(o).data;
    }
    else if (fiobj_type_is(o, FIOBJ_T_NUMBER) == 1 ||
             fiobj_type_is(o, FIOBJ_T_FLOAT) == 1 ||
             o == fiobj_true() || o == fiobj_false() || o == fiobj_null())
    {
        param = fiobj_obj2cstr(o).data;
    }
    else
    {
        // Hash, Array, or other complex type — serialize to JSON
        json_str = fiobj_obj2json(o, 0);
        if (json_str != FIOBJ_INVALID)
        {
            param = fiobj_obj2cstr(json_str).data;
        }
    }

    if (!param)
    {
        log_error("iterate_over_args: could not convert argument to string");
        if (json_str != FIOBJ_INVALID) fiobj_free(json_str);
        return 0;
    }

    char* enclosed_param = malloc(strlen(param) + 3);
    sprintf(enclosed_param, "'%s'", param);
    strcat(parsed, enclosed_param);
    strcat(parsed, " ");
    free(enclosed_param);
    if (json_str != FIOBJ_INVALID) fiobj_free(json_str);
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


void execute_download(char* full_url, char *name, char* token)
{
    log_debug("DWN: %s", full_url);
    CURL *curl = curl_easy_init();
    if(curl){
        FILE* fp = fopen(name, "wb+");
        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_curl_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        struct curl_slist *headers = NULL;
        if (token && strlen(token) > 0) {
            size_t token_len = strlen(token) + 15; // "Authorization: Bearer " + token
            char* auth_header = malloc(token_len);
            sprintf(auth_header, "Authorization: %s", token);
            log_debug("Auth Header: %s", auth_header);
            headers = curl_slist_append(headers, auth_header);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }

        curl_easy_perform(curl);
        if (headers) {
            curl_slist_free_all(headers);
        }
        curl_easy_cleanup(curl);
        fclose(fp);
    }
}

void download_tool(char *tool_url, char *name, char *token)
{
    /*shmfid = shmget(IPC_PRIVATE, strlen(name), IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
    char *fname_addr;
    char *shmfname = shmat(shmfid, fname_addr, 0);
    sprintf(shmfname, "%s", name);
    shmdt(shmfname);*/
    execute_download(tool_url, name, token);
}
