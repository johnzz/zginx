#ifndef __ZGX_REQUEST_H__
#define __ZGX_REQUEST_H__

#define CR      (u_char)'\r'
#define LF      (u_char)'\n'
#define CRLF    "\r\n"

#define ZGX_HTTP_PARSE_INVALID_METHOD   1
#define ZGX_HTTP_INVALID_METHOD         2
#define ZGX_HTTP_INVALID_REQUEST        3
#define ZGX_HTTP_INVALID_PROTOCOL       4
#define ZGX_HTTP_BAD_REQUEST            5
#define ZGX_HTTP_PARSE_HEADER_DONE      6
#define ZGX_HTTP_PARSE_INVALID_HEADER   7


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

void zgx_http_block_reading(zgx_request_t *r);

int zgx_read_request_line(zgx_connection_t *c);
static int zgx_http_read_request_header(zgx_request_t   *r);
static int zgx_http_parse_header_line(zgx_request_t *r,zgx_buff_t *b);
static int zgx_http_core_write_hanlder(zgx_request_t *r);

void zgx_http_core_run_phases(zgx_request_t *r);
static void zgx_http_request_handler(zgx_event_t *ev);
static void zgx_http_process_request(zgx_request_t *r);
static int zgx_http_process_request_header(zgx_request_t *r);
static void  zgx_http_process_request_headers(zgx_event_t *rev);
static int  zgx_http_process_request_uri(zgx_request_t  *r);
void zgx_http_finalize_request(zgx_request_t *r, int flag);
static int zgx_http_alloc_large_header_buffer(zgx_request_t *r, int flag);
static void zgx_http_process_request_line(zgx_event_t *rev);
static ssize_t zgx_read(int fd, u_char *buff, ssize_t size);


int zgx_parase_request_line(zgx_request_t *r);
static int zgx_http_send_body(zgx_request_t *r);

int zgx_read_request_header(zgx_connection_t *c);

int zgx_parase_request_header(zgx_request_t *r);
void zgx_http_wait_request_handler(zgx_event_t  *rev);
void zgx_http_empty_handler(zgx_event_t	*rev);
zgx_request_t *zgx_create_request(zgx_connection_t *c);
void zgx_http_close_connection(zgx_connection_t *c);


void zgx_close_connection(zgx_connection_t *c);
void zgx_http_close_request(zgx_request_t   *r, int flag);
void zgx_http_finalize_request(zgx_request_t *r, int flag);



#endif
