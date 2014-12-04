#include "zgx_request.h"

#define CLIENT_HEADER_BUFFER_SIZE   2048
#define ZGX_HTTP_MODULE 0x50545448


void zgx_http_block_reading(zgx_request_t *r)
{

}

static inline int zgx_list_init(zgx_list_t *list, int n, size_t size)
{
}

zgx_request_t *zgx_create_request(zgx_connection_t *c)
{
    zgx_request_t       *r;
    struct timeval              tv;

    r = zgx_calloc(sizeof(zgx_request_t));
    if (r == NULL) {
        return NULL;
    }

    r->connection = c;
    r->signature = ZGX_HTTP_MODULE;
    r->read_event_handler = zgx_http_block_reading;

    r->header_in = c->buffer;

    if (zgx_list_init(&r->headers_out.headers, 20, sizeof(zgx_table_elt_t)) != ZGX_OK) {
        return NULL;
    }

    gettimeofday(&tv,NULL);
    r->start_sec = tv.tv_sec;

    r->method = ZGX_HTTP_UNKNOWN;
    r->http_version = ZGX_HTTP_VERSION_10;
    r->headers_in.content_length_n = -1;
    r->headers_in.keep_alive_n = -1;
    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;

    r->http_state = ZGX_HTTP_READING_REQUEST_STATE;

    return r;

}


static inline int zgx_http_parse_request_line(zgx_request_t *r, zgx_buff_t *b)
{
    int         state;
    u_char      ch, *p;
    u_char      *method_end, *method_start;

    enum {
        sw_start = 0,
        sw_method,
        sw_uri_start,
        sw_http_protocol_start,
        sw_almost_done,
    }stat;

    state =  r->state;

    for (p = b->pos; p < b->last; ) {
        ch = *p;

        switch(state) {
            case sw_start:
                r->request_start = p;

                if (ch == CR || ch == LF) {
                    break;
                }

                if (ch < 'A' || ch > 'Z') {
                    return ZGX_HTTP_PARSE_INVALID_METHOD;
                }

                while (ch == ' ' || ch == '_') {
                    p++;
                }

                state = sw_method;
                break;

            case sw_method:
                method_end = p;
                method_start = p;

                while (ch != ' ') {
                    method_end ++;
                    p++;
                }

                r->method_end = method_end;
                switch (method_end - method_start) {
                    case 3:

                        if (zgx_str3_cmp(method_start,'G','E','T')) {
                            r->method = ZGX_HTTP_GET;
                            break;
                        }

                        if (zgx_str3_cmp(method_start,'P','U','T')) {
                            r->method = ZGX_HTTP_PUT;
                            break;
                        }

                        break;

                    case 4:

                        if (zgx_str4_cmp(method_start,'H','E','A','D')) {
                            r->method = ZGX_HTTP_HEAD;
                            break;
                        }

                        if (zgx_str4_cmp(method_start,'P','O','S','T')) {
                            r->method = ZGX_HTTP_POST;
                            break;
                        }

                        break;

                    default:
                        return ZGX_HTTP_INVALID_METHOD;
                }

                state = sw_uri_start;
                break;

            case sw_uri_start:

                if (ch == '/') {
                    r->uri_start = p;

                    while (ch != ' ') {
                        p++;
                    }

                    r->uri_end = p;

                    state =  sw_http_protocol_start;
                    break;
                }

                p++;

            case sw_http_protocol_start:
                if (ngx_str5_cmp(p,'H','T','T','P','/')) {
                    p += 6;

                    if (*p == '1' || *p == '0') {
                        state = sw_almost_done;
                    } else {
                        return ZGX_HTTP_INVALID_PROTOCOL;
                    }

                    while (ch != CR) {
                        p++;
                    }

                }

                if (ch == CR) {
                    state = sw_almost_done;
                    p++;
                    break;
                }

                if (ch == LF) {
                    goto done;
                }

            case sw_almost_done:

                r->request_end = p - 1;

                if (ch == LF) {
                    goto done;
                }

                return ZGX_HTTP_INVALID_REQUEST;
        }
    }

    b->pos = p;
    r->state = state;

    return ZGX_AGAIN;
done:
    b->pos = p + 1;
    r->request_end = p;
    r->state = sw_start;

    return ZGX_OK;
}

void zgx_close_request(zgx_request_t *r, int rc)
{
 
}

static void  zgx_http_process_request_headers(zgx_event_t *rev)
{
    zgx_connection_t    *c;
    zgx_request_t       *r;
    zgx_table_elt_t     *h;

    size_t              size,n;
    int     rc;

    c = rev->data;
    r = c->data;

    rc = ZGX_AGAIN;
    size= CLIENT_HEADER_BUFFER_SIZE;

    for ( ;; ) {
        if (rc == ZGX_AGAIN) {
            if (r->header_in->post == r->header_in->end) {
                r->header_in = zgx_alloc(2*size);
            }

            n = zgx_http_read_request_header(r);

            if (n == ZGX_AGAIN || n == ZGX_ERROR) {
                return;
            }

        }

        rc = zgx_http_parse_header_line(r, r->header_in);

        if (rc == ZGX_OK) {
            r->request_length += r->header_in->pos - r->header_name_start;
            h = zgx_list_push(&r->headers_in.headers);
            if (h == NULL) {
                zgx_http_close_request(r,ZGX_HTTP_INTERNAL_SERVER_ERRROR);
                return;
            }

            h->hash = r->header_hash;

        }
    }
}


static size_t zgx_read_request_header(zgx_request_t  *r)
{

}

static int  zgx_http_process_request_uri(zgx_request_t  *r)
{
    return ZGX_OK; 

}

static void zgx_http_process_request_line(zgx_event_t *rev)
{
    int                 rc,n;
    zgx_connection_t    *c;
    zgx_request_t       *r;
    zgx_str_t           host;

    c = rev->data;
    r = c->data;

    rc = ZGX_AGAIN;

    for ( ;; ) {
        if (rc == ZGX_AGAIN) {
            n = zgx_read_request_header(r);

            if (n == ZGX_AGAIN || n == ZGX_ERROR) {
                return;
            }
        }

        rc = zgx_http_parse_request_line(r,r->header_in);

        if (rc == ZGX_OK) {
            r->request_line.len = r->request_end - r->request_start;
            r->request_line.data = r->request_start;
            r->request_length = r->header_in->pos - r->request_start;

            r->method_name.len = r->method_end - r->request_start + 1;
            r->method_name.data = r->request_line.data;

            if (zgx_http_process_request_uri(r) != ZGX_OK) {
                return;
            }

            if (r->host_start && r->host_end) {
                host.len = r->host_end - r->host_start;
                host.data = r->host_start;
            }

            if (zgx_list_init(&r->headers_in.headers, 20, sizeof(zgx_table_elt_t)) != ZGX_OK) {
                zgx_close_request(r, ZGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            rev->handler = zgx_http_process_request_headers;
            zgx_http_process_request_headers(rev);
        }

        if (rc != ZGX_AGAIN) {
            zgx_http_finalize_request(r, ZGX_HTTP_BAD_REQUEST);
            return;
        }

        if (r->header_in->pos == r->header_in->end) {
            rv = zgx_http_alloc_large_header_buffer(r,1);

            if (rv == ZGX_ERROR) {
                zgx_http_close_request(r, ZGX_HTTP_BAD_REQUEST);
                return;
            }

        }
    }
}

void zgx_http_wait_request_handler(zgx_event_t  *rev)
{
    unsigned int        size;
    zgx_buff_t          *b = NULL;
    zgx_connection_t    *c;
    size_t              n;

    c = rev->data;

    size = CLIENT_HEADER_BUFFER_SIZE;

    if (b == NULL) {
        b = zgx_calloc(sizeof(zgx_buff_t));
        if (b == NULL) {
            zgx_close_accepted_connection(c);
            return;
        }

        b->start = zgx_calloc(size);
        if (b->start == NULL) {
            zgx_close_accepted_connection(c);
            return;
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + size;
        c->state = WAIT_REQUEST;
    }

    c->buffer = b;

    n = read(c->fd, b->last, size);
    if (n == ZGX_AGAIN){
        if (zgx_handle_read_event(rev, 0) != ZGX_OK) {
            zgx_close_accepted_connection(c);
            return;
        }

        free(b->start);

        return;
    }

    if (n == ZGX_ERROR) {
        zgx_close_accepted_connection(c);
        return;
    }

    if (n == 0) {
        zgx_log(ERROR,"client closed connection!");
        zgx_close_accepted_connection(c);
        return;
    }

    b->last += n;
    c->state = READ_REQUEST;

    c->data = zgx_create_request(c);
    if (c->data == NULL) {
        zgx_close_connection(c);
        return;
    }

    rev->handler = zgx_http_process_request_line;
    zgx_http_process_request_line(rev);
}


