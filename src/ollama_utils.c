#include "main.h"

char* newest_message_from_request(const char* request)
{
    FIOBJ tmp = FIOBJ_INVALID;
    size_t consumed = fiobj_json2obj(&tmp, request, strlen(request));
    if(consumed > 0 && fiobj_type_is(tmp, FIOBJ_T_HASH) == 1)
    {
        FIOBJ msgs_key = fiobj_str_new("messages", 8);
        FIOBJ messages = fiobj_hash_get(tmp, msgs_key);
        if(fiobj_type_is(messages, FIOBJ_T_ARRAY))
        {
           FIOBJ newest_message = fiobj_ary_pop(messages);
           FIOBJ content_key = fiobj_str_new("content", 7);
           FIOBJ message_text = fiobj_hash_get(newest_message, content_key);
           fio_str_info_s text = fiobj_obj2cstr(message_text);
           return text.data;
        }
        fiobj_free(msgs_key);
        fiobj_free(tmp);
        return NULL;
    }
    return NULL;
}

bool set_llm_req_opt(char* optkey_s, FIOBJ value, char* req_handle)
{
    if(req_handle == NULL)
    {
        log_debug("req_handle is either NULL or undefined, couldnt set");
        return false;
    }
    FIOBJ req_handle_obj = FIOBJ_INVALID;
    fiobj_json2obj(&req_handle_obj, req_handle, strlen(req_handle));
    FIOBJ optkey = fiobj_str_new("options", 7);
    FIOBJ opt_hash = fiobj_hash_get(req_handle_obj, optkey);
    fiobj_free(optkey);
    if(opt_hash == FIOBJ_INVALID)
    {
        opt_hash = fiobj_hash_new();
    }
    FIOBJ key_obj = fiobj_str_new(optkey_s, strlen(optkey_s));
    int valres = fiobj_hash_set(opt_hash, key_obj, value);
    log_debug("%s", fiobj_obj2cstr(fiobj_obj2json(opt_hash, 0)).data);
    FIOBJ optkey2 = fiobj_str_new("options", 7);
    fiobj_hash_replace(req_handle_obj, optkey2, opt_hash);
    FIOBJ req_handle_str = fiobj_obj2json(req_handle_obj, 0);
    req_handle = fiobj_obj2cstr(req_handle_str).data;
    fiobj_free(req_handle_obj);
    fiobj_free(optkey);
    fiobj_free(opt_hash);
    fiobj_free(key_obj);
    fiobj_free(req_handle_str);
    return valres != -1;
}

FIOBJ retrieve_req_handle_as_fiobj(char* req_handle)
{
    FIOBJ handle = FIOBJ_INVALID;
    fiobj_json2obj(&handle, req_handle, strlen(req_handle));
    return handle;
}

void update_curr_req_handle_messages(FIOBJ message, char** req_handle)
{
    FIOBJ messagekey = fiobj_str_new("messages", 8);
    FIOBJ ollama_req = FIOBJ_INVALID; 
    fiobj_json2obj(&ollama_req, *req_handle, strlen(*req_handle));  
    FIOBJ message_arr = fiobj_dup(fiobj_hash_get(ollama_req, messagekey)); 
    fiobj_ary_push(message_arr, message);
    fiobj_hash_set(ollama_req, messagekey, message_arr);
    fiobj_free(messagekey);
    *req_handle = fiobj_obj2cstr(fiobj_obj2json(ollama_req, 0)).data;
}

void push_on_top_curr_req_messages(FIOBJ message, char** req_handle)
{
    FIOBJ messagekey = fiobj_str_new("messages", 8);
    FIOBJ ollama_req = FIOBJ_INVALID; 
    fiobj_json2obj(&ollama_req, *req_handle, strlen(*req_handle));  
    FIOBJ message_arr = fiobj_dup(fiobj_hash_get(ollama_req, messagekey)); 
    FIOBJ tmp_message_arr = fiobj_ary_new2(fiobj_ary_count(message_arr) + 1);
    fiobj_ary_push(tmp_message_arr, message);
    for(size_t i = 0; i < fiobj_ary_count(message_arr); i++)
    {
        fiobj_ary_push(tmp_message_arr, fiobj_ary_entry(message_arr, i));
    }
    fiobj_hash_set(ollama_req, messagekey, tmp_message_arr);
    fiobj_free(messagekey);
    *req_handle = fiobj_obj2cstr(fiobj_obj2json(ollama_req, 0)).data;
    fiobj_free(message_arr);
    fiobj_free(tmp_message_arr);
    fiobj_free(ollama_req);
}

void apnd_syssec2req(FIOBJ container, char** req_handle)
{
    FIOBJ syspromptskey = fiobj_str_new("sysprompts", 10);
    FIOBJ prompts = fiobj_hash_get(container, syspromptskey);
    if(fiobj_type_is(prompts, FIOBJ_T_HASH) == 0)
    {
        return;
    }
    char* model = fio_malloc(MODEL_NAME_L);
    extract_model(&model, *req_handle);
    log_debug("%s", model);
    FIOBJ model_obj = fiobj_str_tmp();
    fiobj_str_printf(model_obj, "%s", model);
    if(fiobj_hash_haskey(prompts, model_obj) != 1)
    {
        log_error("%s %s", "Couldnt set a context message from session for", model);
        return;
    }
    FIOBJ nprompts = fiobj_hash_get(prompts, model_obj);
    log_debug("%d", fiobj_type_is(nprompts, FIOBJ_T_ARRAY));
    if(fiobj_type_is(nprompts, FIOBJ_T_ARRAY) == 1)
    {
        int promptc = fiobj_ary_count(nprompts);
        for(int i = 0; i < promptc; i++)
        {
            FIOBJ prompt_hash = fiobj_ary_entry(nprompts, i);
            if(fiobj_type_is(prompt_hash, FIOBJ_T_HASH) == 1)
            {
                push_on_top_curr_req_messages(prompt_hash, req_handle);
            }
        }
    }
}

void apnd_toolsec2req(FIOBJ container, char** req_handle)
{
    FIOBJ cmdskey = fiobj_str_new("cmds", 4);
    FIOBJ urlkey = fiobj_str_new("tool_url", 8);
    FIOBJ enginekey = fiobj_str_new("tool_engine", 11);
    FIOBJ namekey = fiobj_str_new("name", 4);
    FIOBJ desckey = fiobj_str_new("description", 11);
    FIOBJ params = fiobj_str_new("params", 6);
    FIOBJ cmda = fiobj_hash_get(container, cmdskey);
    FIOBJ tool_section = fiobj_hash_new();
    FIOBJ tool_ary = fiobj_ary_new();
    if (fiobj_type_is(cmda, FIOBJ_T_ARRAY) == 1)
    {
        int cmdc = fiobj_ary_count(cmda);
        for (int i = 0; i < cmdc; i++)
        {
            FIOBJ cmd = fiobj_dup(fiobj_ary_index(cmda, i));
            if (fiobj_type_is(cmd, FIOBJ_T_HASH) == 1)
            {
                char *tool_sec = malloc(TOOL_SEC_L); // FIXME: It should be somehow calculated based on name, description length and consolidated length of parameters
                FIOBJ tool_url = fiobj_hash_get(cmd, urlkey);
                FIOBJ tool_engine = fiobj_hash_get(cmd, enginekey);
                char *url = fiobj_obj2cstr(tool_url).data;
                char *engine = fiobj_obj2cstr(tool_engine).data;
                char *name = fiobj_obj2cstr(fiobj_hash_get(cmd, namekey)).data;
                char *description = fiobj_obj2cstr(fiobj_hash_get(cmd, desckey)).data;
                char* params_json_str = strdup(fiobj_obj2cstr(fiobj_hash_get(cmd, params)).data);

                log_debug("REQ-PREP: %s, %s", url, engine);
                log_debug(params_json_str);
                download_tool(url, name);
                FIOBJ parsed_params_json = FIOBJ_INVALID;
                if(strcmp(params_json_str, "") == 0 || params_json_str == NULL)
                {
                    *params_json_str = "{}";
                } 
                fiobj_json2obj(&parsed_params_json, params_json_str, strlen(params_json_str));
                char* params_str = fiobj_obj2cstr(fiobj_obj2json(parsed_params_json, 0)).data;
                memset(tool_sec, 0, TOOL_SEC_L);
                snprintf(tool_sec, TOOL_SEC_L, TOOLSEC_TEMPLATE, name, description, params_str);
                log_debug(tool_sec);
                FIOBJ tool_sec_obj = FIOBJ_INVALID;
                fiobj_json2obj(&tool_sec_obj, strdup(tool_sec), strlen(tool_sec));
                fiobj_ary_push(tool_ary, tool_sec_obj);
                free(tool_sec);
            }
            fiobj_free(cmd);
        }
        FIOBJ req = FIOBJ_INVALID;
        fiobj_json2obj(&req, *req_handle, strlen(*req_handle));
        FIOBJ tools_key = fiobj_str_new("tools", 5);
        fiobj_hash_set(req, tools_key, tool_ary);
        FIOBJ req_json_obj = fiobj_obj2json(req, 0);
        char *req_with_tools = fiobj_obj2cstr(req_json_obj).data;
        *req_handle = req_with_tools;
        log_debug("REQ-TOOLS-ADD: %s", req_with_tools);
    }
    fiobj_free(cmdskey);
    fiobj_free(urlkey);
    fiobj_free(enginekey);
    fiobj_free(namekey);
    fiobj_free(desckey);
    fiobj_free(tool_section);
}