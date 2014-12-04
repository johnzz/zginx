#ifndef __ZGINX_H__

#include "zginx.h"

#define CR      (u_char)'\r'
#define LF      (u_char)'\n'
#define CRLF    "\r\n"

#define ZGX_HTTP_PARSE_INVALID_METHOD   1
#define ZGX_HTTP_INVALID_METHOD         2
#define ZGX_HTTP_INVALID_REQUEST        3
#define ZGX_HTTP_INVALID_PROTOCOL       4



#define ZGX_HTTP_INTERNAL_SERVER_ERROR 500

#define zgx_str3_cmp(m,c0,c1,c2)                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2

#define zgx_str4_cmp(m,c0,c1,c2,c3)                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3


#define zgx_str5_cmp(m,c0,c1,c2,c3,c4)                    \
    m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4


#define ZGX_HTTP_UNKNOWN                   0x0001
#define ZGX_HTTP_GET                       0x0002
#define ZGX_HTTP_HEAD                      0x0004
#define ZGX_HTTP_POST                      0x0008
#define ZGX_HTTP_PUT                       0x0010
#define ZGX_HTTP_DELETE                    0x0020

int zgx_read_request_line(zgx_connection_t *c);

int zgx_parase_request_line(zgx_request_t *r);

int zgx_read_request_header(zgx_connection_t *c);

int zgx_parase_request_header(zgx_request_t *r);


#endif
