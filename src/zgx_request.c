#include "zginx.h"
#include "zgx_request.h"
#include "zgx_epoll.h"

#define CLIENT_HEADER_BUFFER_SIZE   2048
#define RESPONSE_BUFFER_SIZE		2048

#define SERVER_SOFTWARE			"ZGINX_0.0.1"

#define ZGX_HTTP_MODULE 0x50545448
#define URI_PREFIX		"/data1/ext0/sina/zhaojq/test/zginx/www"
#define URI_PREFIX_LEN   strlen(URI_PREFIX)

static u_char  lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

void zgx_http_block_reading(zgx_request_t *r)
{
	zgx_log(DEBUG,"zgx_http_block_reading will del the event");
	zgx_event_t		*ev;
	zgx_connection_t	*c;
	
	c = r->connection;
	ev = c->read;
	
	if (ev->active) {
		if (zgx_epoll_del_event(ev, ZGX_READ_EVENT, 0) != ZGX_OK ) {
			zgx_log(DEBUG,"zgx_http_block_reading del the event failed!");
		}
	}
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

	dd("request start sec %d",r->start_sec);
	
    r->method = ZGX_HTTP_UNKNOWN;
    r->http_version = ZGX_HTTP_VERSION_10;
    r->headers_in.content_length_n = -1;
    r->headers_in.keep_alive_n = -1;
    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;

	r->headers_out.buff = NULL;
    r->http_state = ZGX_HTTP_READING_REQUEST_STATE;

    return r;

}

static inline int zgx_http_send_response(zgx_request_t *r,
				int status, char *status_str) 
{
	zgx_connection_t	*c;
	zgx_buff_t			*b;
	char				*protocal;
	int					ret;
	const char* rfc1123_fmt = "%a, %d %b %Y %H:%M:%S GMT";
	time_t				now, expires;
	char				timebuff[100];
	
	b = r->headers_out.buff;
	if (!b) {
		b = zgx_calloc(sizeof(zgx_buff_t));
		if (!b) {
			zgx_http_close_request(r,0);
			return;
		} else {

		b->start = zgx_calloc(RESPONSE_BUFFER_SIZE);
		if (!b->start) {
			zgx_close_connection(c);
			return;
		}

		b->pos = b->start;
		b->last = b->start;
		b->end = b->start + RESPONSE_BUFFER_SIZE;
		}
	}

	protocal = r->http_protocol.data;
	ret = sprintf(b->pos, "%s %d %s%s",protocal,status,status_str,CRLF);
	b->pos += ret;
	
	ret = sprintf(b->pos, "Server: %s%s",SERVER_SOFTWARE,CRLF);
	b->pos += ret;

	now = time();
	strftime(timebuff, sizeof(timebuff), rfc1123_fmt, gmtime(&now));
	
	ret = sprintf(b->pos, "Date: %s%s",timebuff,CRLF);
	b->pos += ret;

	ret = sprintf(b->pos, "Content-Type: %s%s","text/html; charset=utf-8",CRLF);
	b->pos += ret;

	ret = sprintf(b->pos,"Content-Length: %d%s",r->content_length,CRLF);
	b->pos += ret;

	ret = sprintf(b->pos,"Last-Modified: %s%s",timebuff,CRLF);
	b->pos += ret;

	if (r->headers_in.keep_alive) {
		ret = sprintf(b->pos,"Connection: %s%s","keep-alive",CRLF);
		b->pos += ret;
	}
	
	ret = sprintf(b->pos,"%s",CRLF);
	b->pos += ret;

	r->headers_out.response_ok = 1;
	return ZGX_OK;
	
}

static int zgx_http_send_body(zgx_request_t *r)
{
	zgx_connection_t	*c;
	ssize_t				size,ret;
	zgx_buff_t			*b;
	zgx_event_t			*ev;
	int					filefd;
	
	b = r->headers_out.buff;
	c = r->connection;
	ev = c->write;
	
	dd("content_length %d ",r->content_length);

	filefd = open(r->uri.data,O_RD);
	if (filefd < 0) {
		zgx_log(ERROR,"Open %s file error!",r->uri.data);
		return;
	}

	ret = read(filefd, b->pos, r->content_length);
	if (ret < 0) {
		zgx_http_close_request(r, ZGX_HTTP_INTERNAL_SERVER_ERROR);
		close(filefd);
		return ZGX_ERROR;
	}

	close(filefd);

	return ZGX_OK;
}

static inline int zgx_http_parse_request_line(zgx_request_t *r, zgx_buff_t *b)
{
    u_char      ch, *p;
    u_char      *method_end, *method_start;

    enum {
        sw_start = 0,
        sw_method,
        sw_uri_start,
        sw_http_protocol_start,
        sw_almost_done,
    }state;

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

                while ((ch == ' ' || ch == '_') && p < b->last) {
                    p++;
                }

                state = sw_method;
                break;

            case sw_method:
                method_end = p;
                method_start = p;

                while (ch != ' ' && p < b->last) {
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

                    while (ch != ' ' && p < b->last) {
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

                    while (ch != CR && p < b->last) {
                        p++;
                    }

                }

                if (ch == CR && p < b->last) {
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


void zgx_http_free_request(zgx_request_t  *r, int flag)
{
	if (r->header_in.start) {
		free(r->header_in.start);
	}
	
	r->header_in.start = NULL;
}

void zgx_http_close_request(zgx_request_t  *r, int flag)
{
	zgx_connection_t	*c;

	c = r->connection;

	zgx_http_free_request(r, flag);
	zgx_http_close_connection(c);
}

static int zgx_http_read_request_header(zgx_request_t   *r)
{
    zgx_connection_t        *c;
    zgx_event_t             *rev;
    size_t                  n;

    c = r->connection;
    rev = c->read;

    n = r->header_in->last - r->header_in->pos;

    if (n > 0) {
        return n;
    }

    if (rev->ready) {
        n = zgx_read(c->fd, r->header_in->last, r->header_in->end - r->header_in->last);
    } else {
        n = ZGX_AGAIN;
    }

    if (n == ZGX_AGAIN) {
        if (zgx_handle_read_event(rev, 0) != ZGX_OK) {
            zgx_http_close_request(r, ZGX_HTTP_INTERNAL_SERVER_ERROR);
            return ZGX_ERROR;
       }

        return ZGX_AGAIN;

    }

    if (n == 0) {
        zgx_log(ERROR,"client may close the connection!");
    }

    r->header_in->last += n;

    return n;
}

static int zgx_http_parse_header_line(zgx_request_t *r,zgx_buff_t *b)
{
    enum {
        sw_start = 0,
        sw_name,
        sw_value,
        sw_almost_done,
        sw_header_almost_done,
    }state;

    u_char          ch,*p;


    state = r->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (ch) {

            case sw_start:
                r->header_name_start = p;

                switch(ch) {
                    case CR:
                        r->header_end = p;
                        state = sw_header_almost_done;
                        break;

                    case LF:
                        r->header_end = p;
                        goto header_done;

                    default:
                        state = sw_name;
                        break;
                }

                break;

            case sw_name:
                r->header_name_start = p;
				
                if (ch == ':' ) {
                    r->header_name_end = p;
                    state = sw_value;
                    break;
                }

                if (ch == CR) {
                    r->header_name_end = p;
                    state = sw_almost_done;
                    break;
                }

                if (ch == LF) {
                    r->header_start = p;
                    r->header_end   = p;
                    goto done;
                }

                if (ch == '\0') {
                    return ZGX_HTTP_PARSE_INVALID_HEADER;
                }

                break;

            case sw_value:

                if (ch == ' '){
                    break;
                }

                if (ch == CR) {
                    r->header_start = p;
                    r->header_end = p;
                    state = sw_almost_done;
                    break;
                }

                if (ch == LF) {
                    r->header_start = p;
                    r->header_end = p;
                    goto done;
                }

                if (ch == '\0') {
                    return ZGX_HTTP_PARSE_INVALID_HEADER;
                }

                r->header_start = p;
                state = sw_almost_done;
                break;

            case sw_almost_done:
                if (ch == CR) {
                    r->header_end = p;
                    state = sw_header_almost_done;
                    break;
                }

                if (ch == LF) {
                    goto done;
                }

                return ZGX_HTTP_PARSE_INVALID_HEADER;

            case sw_header_almost_done:
                if (ch == LF) {
                    goto header_done;
                }

                return ZGX_HTTP_PARSE_INVALID_HEADER;
        }
    }

    b->pos = p;
    r->state = state;
    
    return ZGX_AGAIN;
done:
    b->pos = p + 1;
    r->state = sw_start;

    return ZGX_OK;

header_done:

    b->pos = p + 1;
    r->state = sw_start;

    return ZGX_HTTP_PARSE_HEADER_DONE;
}

zgx_table_elt_t * zgx_list_push(zgx_list_t *headers)
{

}


static int zgx_http_core_write_hanlder(zgx_request_t *r)
{

	ssize_t			size,ret;
	zgx_buff_t		*b;
	zgx_connection_t	*c;
	zgx_event_t		*wev;

	c = r->connection;
	b = r->headers_out.buff;
	wev = c->write;
	
	ret = zgx_write(c->fd, b->last, r->pos - r->start + 1);
	
	if (ret == ZGX_AGAIN) {
        if (zgx_handle_write_event(wev, 0) != ZGX_OK) {
            zgx_http_close_request(r, ZGX_HTTP_INTERNAL_SERVER_ERROR);
            return ZGX_ERROR;
       }
		
		b->last += ret;
        return ZGX_AGAIN;

    }

	if (ret == 0) {
		zgx_http_finalize_request(r, 0);
	}
	
	if (ret == r->content_length) {
		b->last += ret;
		return ZGX_OK;
	}

}

void zgx_http_core_run_phases(zgx_request_t *r) 
{
	ssize_t		ret,size;
	zgx_buff_t	*b;
	int			filefd;
	
	if (!r->headers_out.response_ok) {
		zgx_http_send_response(r);
	}

	zgx_http_send_body(r);

	ret = zgx_http_core_write_hanlder(r);
	if (ret == ZGX_AGAIN) {
		r->write_event_handler = zgx_http_core_write_hanlder;
	}

	return;
}

static void zgx_http_request_handler(zgx_event_t *ev)
{
	zgx_connection_t	*c;
	zgx_request_t		*r;

	c = ev->data;
	r = c->data;

	if (ev->write) {
		r->write_event_handler(r);
	} else {
		r->read_event_handler(r);
	}

	return;
}

static void zgx_http_process_request(zgx_request_t *r) 
{
	zgx_connection_t	*c;
	ssize_t		ret;
	int			filefd;
	zgx_buff_t	*b;

	c = r->connection;
	
	c->read->handler = zgx_http_request_handler;
	c->write->handler = zgx_http_request_handler;

	r->read_event_handler = zgx_http_block_reading;
	r->write_event_handler = zgx_http_core_run_phases;

	zgx_http_core_run_phases(r);
	
}


static int zgx_http_process_request_header(zgx_request_t *r)
{
//TODO 
	return ZGX_OK;
}


static void  zgx_http_process_request_headers(zgx_event_t *rev)
{
    zgx_connection_t    *c;
    zgx_request_t       *r;
    zgx_table_elt_t     *h;

    size_t              size,n;
    int     			rc;

    c = rev->data;
    r = c->data;

    rc = ZGX_AGAIN;
    size = CLIENT_HEADER_BUFFER_SIZE;

    for ( ;; ) {
        if (rc == ZGX_AGAIN) {
            if (r->header_in->pos == r->header_in->end) {
				zgx_log(DEBUG,"r->header_in buffer realloc!");
				
				//r->header_in = zgx_alloc(2*size); TODO realloc
            }

            n = zgx_http_read_request_header(r);

            if (n == ZGX_AGAIN || n == ZGX_ERROR) {
                return;
            }

        }

        rc = zgx_http_parse_header_line(r, r->header_in);

        if (rc == ZGX_OK) {
            r->request_length += r->header_in->pos - r->header_name_start;
		/*TODO
            h = zgx_list_push(&r->headers_in.headers);
            if (h == NULL) {
                zgx_http_close_request(r,ZGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            h->hash = r->header_hash;
            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

        }
	*/
		dd("Content-Length [%s], length %s ",r->header_name_start
												,r->header_start);
		
		if (!(strncmp("Content-Length", r->header_name_start,
								r->header_name_end - r->header_name_start)) {
			int i,cl_num=0;
			for (i = 0; i < (r->header_end - r->header_start); i++) {
				cl_num = cl_num*10  + r->header_start[i] - '0';
			}

			r->content_length = cl_num;
			dd("r->content_length = %d",r->content_length);
			
		}
        if (rc == ZGX_HTTP_PARSE_HEADER_DONE) {
            r->request_length += r->header_in->pos - r->header_name_start;

            r->http_state = ZGX_HTTP_PROCESS_REQUEST_STATE;

            rc = zgx_http_process_request_header(r);

            if (rc != ZGX_OK) {
                return;
            }

            zgx_http_process_request(r);

            return;
        }

        if (rc == ZGX_AGAIN) {
            zgx_log(DEBUG,"rc == ZGX_AGAIN in zgx_http_process_request_headers");
            continue;
        }

        zgx_http_finalize_request(r,ZGX_HTTP_BAD_REQUEST);
        return;
    	}
	}
}


static int  zgx_http_process_request_uri(zgx_request_t  *r)
{
	char	*uri_whole;
	int		len;

	
    r->uri.data = r->uri_start;
	r->uri.len = r->uri_end - r->uri_start + 1;

	len = URI_PREFIX_LEN + r->uri.len + 1;
	uri_whole = zgx_calloc(len);
	strncat(uri_whole, r->uri.data, len);
	dd("the request uri is %s",uri_whole);

	r->uri.data = uri_whole;
	r->uri.len	= len;

	return ZGX_OK;
	
}

void zgx_http_finalize_request(zgx_request_t *r, int flag)
{
	return zgx_http_close_request(r, flag);
}


static int zgx_http_alloc_large_header_buffer(zgx_request_t *r, int flag)
{
	zgx_log(DEBUG,"zgx_http_alloc_large_header_buffer");
	
	return ZGX_OK;
}

static void zgx_http_process_request_line(zgx_event_t *rev)
{
    int                 rc,n,rv;
    zgx_connection_t    *c;
    zgx_request_t       *r;
    zgx_str_t           host;

    c = rev->data;
    r = c->data;

    rc = ZGX_AGAIN;

    for ( ;; ) {
        if (rc == ZGX_AGAIN) {
            n = zgx_http_read_request_header(r);

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
			/*
            if (r->host_start && r->host_end) {
                host.len = r->host_end - r->host_start;
                host.data = r->host_start;
            }
		*/
            if (zgx_list_init(&r->headers_in.headers, 20, sizeof(zgx_table_elt_t)) != ZGX_OK) {
                zgx_http_close_request(r, ZGX_HTTP_INTERNAL_SERVER_ERROR);
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

void zgx_http_empty_handler(zgx_event_t	*rev)
{
	zgx_log(DEBUG,"http write empty handler!");
	
	return;
}

static ssize_t zgx_read(int fd, u_char *buff, ssize_t size)
{
	ssize_t		recv_size;
	int			ret,errno;


	recv_size = read(fd, buff, size);
	if (recv_size < 0) {
		if (errno == EAGAIN || errno == EINT){
			zgx_log(ERROR,"read fd %d again!",fd);
			
			return ZGX_AGAIN;
		} else {
			return ZGX_ERROR;
			}
		}
	
		if (recv_size == 0) {
			return  0;
		}

		if(recv_size == size) {
			return size;
		}
		
}


static ssize_t zgx_write(int fd, u_char *buff, ssize_t size)
{
	ssize_t		recv_size;
	int			ret,errno;


	recv_size = write(fd, buff, size);
	if (recv_size < 0) {
		if (errno == EAGAIN || errno == EINT){
			zgx_log(ERROR,"read fd %d again!",fd);
			
			return ZGX_AGAIN;
		} else {
			return ZGX_ERROR;
			}
		}
	
		if (recv_size == 0) {
			return  0;
		}

		if(recv_size == size) {
			return size;
		}
		
}

void zgx_http_close_connection(zgx_connection_t *c)
{
	int			fd;
	
	if (c->read->active) {
		zgx_epoll_del_event(c->read, ZGX_READ_EVENT, ZGX_CLOSE_EVENT);
	}

	if (c->write->active) {
		zgx_epoll_del_event(c->write, ZGX_WRITE_EVENT, ZGX_CLOSE_EVENT);
	}

	zgx_reusable_connection(c, 0);
	zgx_free_connection(c);
	
}

void zgx_http_wait_request_handler(zgx_event_t  *rev)
{
    ssize_t		        size;
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

    n = zgx_read(c->fd, b->last, size);
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


