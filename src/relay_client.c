#include "main.h"


void on_response(http_s* h)
{
    if(h->status == 0){
        printf("We just got successfully connected to the server, proceeding.");
    }
    if(h->status == 200)
    {
        printf("http_s should contain something right now.");
        if(h->body != FIOBJ_INVALID)
        {
            FIOBJ stringified_resp = fiobj_obj2json(h->body, (uint8_t)1);
            //TODO: Actually, relay it in Redis so it can be returned from http_service somehow.
            char* string_resp = fiobj_obj2cstr(stringified_resp).data;
            fiobj_free(stringified_resp);
        }
    }
}

void pass_chat_message(const char *message, char** response)
{
    intptr_t status = http_connect("http://192.168.1.253:11434/api/chat", NULL, .on_response = on_response);
    if(status == 0){
        printf("Everything seems to be just right.");
        *response = "relayed";
        return;
    }
    *response = "err";
}