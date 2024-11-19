#include "fiobj.h"
#include <string.h>

#ifndef H_HTTP_SERVICE_H
#define H_HTTP_SERVICE_H

/* this function can be safely ignored. */
void initialize_http_service(void);

void on_post_request(http_s *h);

#endif
