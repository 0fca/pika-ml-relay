#include "fiobj.h"
#include "fio_cli.h"
#include <string.h>
#include <stdio.h>
#include "relay_client.h"

#ifndef H_HTTP_SERVICE_H
#define H_HTTP_SERVICE_H

/* this function can be safely ignored. */
void initialize_http_service(void);

void on_post_request(http_s *h);

#endif
