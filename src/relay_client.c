#include "main.h"

static void on_response(http_s *h)
{
    if (h->status_str == FIOBJ_INVALID)
    {
        http_finish(h);
        return;
    }
    /* Second response is actual response */
    FIOBJ r = http_req2str(h);
    fprintf(stderr, "%s\n", fiobj_obj2cstr(r).data);
}

static void on_request(http_s *h)
{
    h->method = fiobj_str_new("POST", 4);
}

void pass_chat_message(const char *message, char** response)
{
    intptr_t status = http_connect("http://127.0.0.1:11434/api/chat", NULL, .on_response = on_response, .on_request = on_request);
    if(status == 0){
        fprintf(stderr, "Everything seems to be just right.");
        *response = "relayed";
        return;
    } else {
        *response = "err";
        return;
    }
}