//#include <sys/net.h>
#ifndef __ZGINX_H__
#define __ZGINX_H__

#define _GNU_SOURCE
#include <sched.h>
#include <sys/stat.h>
#include <event.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>



#include "zgx_mutex.h"
#define ZGX_INVALID_FILE -1
#define ZGX_OK		0
#define ZGX_ERROR	-1
#define ZGX_AGAIN   -2
#define ZGX_DECLINED -3


#define ZGX_HTTP_UNKNOWN        0x0001
#define ZGX_HTTP_VERSION_10     1000



sig_atomic_t zgx_terminate;

typedef volatile unsigned int zgx_atomic_t ;


typedef enum {
	HTTP_METHOD_UNSET = -1,
	HTTP_METHOD_GET,
	HTTP_METHOD_HEAD,
	HTTP_METHOD_POST,
	HTTP_METHOD_PUT,
	HTTP_METHOD_CONNECT,
}zgx_method_t;

typedef enum {
	DEBUG = 0,
	ERROR,
	CRIT,
}zgx_log_level_t;

typedef enum {
	HTTP_VERSION_1_0 = 0,
	HTTP_VSERION_1_1,
}zgx_version_t;

typedef struct zgx_str_s {
	char		*data;
	size_t		len;
}zgx_str_t;

typedef struct zgx_buff_s {
    u_char      *pos;
    u_char      *last;

	u_char		*start;
    u_char      *end;

    unsigned    memory:1;
}zgx_buff_t;

typedef struct zgx_event_s zgx_event_t;
typedef struct zgx_open_file_s zgx_open_file_t;
typedef struct zgx_queue_s  zgx_queue_t;
typedef struct zgx_listening_s zgx_listening_t;

typedef struct zgx_connection_s zgx_connection_t;
typedef void(*zgx_connection_handler_pt)(zgx_connection_t *c);
typedef void (*zgx_event_handler_pt)(zgx_event_t *ev);

struct zgx_event_s {
	void			*data;
	unsigned		accept:1;
	unsigned		write:1;
	unsigned		read:1;
	unsigned		ready:1;
	unsigned		active:1;
	unsigned		instance:1;

	/* the links of the posted queue */
    zgx_event_t     *next;
    zgx_event_t    **prev;

	zgx_event_handler_pt	handler;
};



struct zgx_connection_s {
	void				*data;
	zgx_event_t			*read;
	zgx_event_t			*write;
	int					 fd;

	
	#ifdef USE_SSL
	SSL					*ssl;
	#endif
	
	struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;
	int					connection_status;
	zgx_buff_t			*buffer;
    int                 state;
    unsigned long       requests;

	unsigned            tcp_nodelay:2;   
    unsigned            tcp_nopush:2;   
	unsigned			reusable:1;
};

typedef struct {
    unsigned int    hash;
    zgx_str_t       key;
    zgx_str_t       value;
    u_char          *lowcase_key;
}zgx_table_elt_t;

typedef struct zgx_list_part_s zgx_list_part_t;
struct zgx_list_part_s{
    void            *elts;
    unsigned int    nelts;
    zgx_list_part_t *next;
};

typedef struct {
    zgx_list_part_t     *last;
    zgx_list_part_t     part;
    size_t              size;
    unsigned int        nalloc;
}zgx_list_t;

typedef struct {
    zgx_buff_t						  *buff;
    int                               status;
    zgx_str_t                         status_line;
	zgx_str_t						  server;
	zgx_str_t						  date;
	zgx_str_t						  cache_control;
    zgx_str_t                         content_type;
	zgx_str_t						  Connection;

    size_t                            content_type_len;

    zgx_str_t                         charset;
    u_char                           *content_type_lowcase;

    off_t                             content_length_n;
    time_t                            date_time;
    time_t                            last_modified_time;
	unsigned						  response_ok:1;
} zgx_http_headers_out_t;

typedef enum {
    ZGX_HTTP_INITING_REQUEST_STATE = 0,
    ZGX_HTTP_READING_REQUEST_STATE,
    ZGX_HTTP_PROCESS_REQUEST_STATE,

    ZGX_HTTP_CONNECT_UPSTREAM_STATE,
    ZGX_HTTP_WRITING_UPSTREAM_STATE,
    ZGX_HTTP_READING_UPSTREAM_STATE,

    ZGX_HTTP_WRITING_REQUEST_STATE,
    ZGX_HTTP_LINGERING_CLOSE_STATE,
    ZGX_HTTP_KEEPALIVE_STATE
}zgx_http_state_e;

typedef struct {
    zgx_list_t              headers;

    zgx_table_elt_t         *host;
    zgx_table_elt_t         *connection;
    zgx_table_elt_t         *if_modified_since;
    zgx_table_elt_t         *if_match;
    zgx_table_elt_t         *refer;
    zgx_table_elt_t         *content_length;
    zgx_table_elt_t         *content_type;
    zgx_table_elt_t         *range;
    zgx_table_elt_t         *authorization;
   
    zgx_table_elt_t         *keep_alive;

    time_t                  keep_alive_n;
    off_t                   content_length_n;

}zgx_http_headers_in_t;


typedef struct zgx_request_s zgx_request_t;
typedef void(*zgx_http_event_handler_pt)(zgx_request_t *r);
typedef struct zgx_request_s {
	zgx_connection_t        *connection;
    unsigned int            signature;

    zgx_http_event_handler_pt   read_event_handler;
    zgx_http_event_handler_pt   write_event_handler;

    zgx_buff_t		*request;
	zgx_buff_t		*orig_uri;
    zgx_buff_t      *header_in;
	zgx_buff_t		*header_out;
    unsigned int    method;
    unsigned int    http_version;
    unsigned int    header_hash;
    zgx_str_t       request_line;
    zgx_str_t       uri;
    zgx_str_t       method_name;
    zgx_str_t       http_protocol;

    zgx_http_headers_in_t       headers_in;
    zgx_http_headers_out_t      headers_out;
	zgx_method_t	http_method;

	zgx_buff_t		*http_host;
    
    off_t                             request_length;

    time_t          start_sec;
    time_t          start_msec;

	const char		*http_range;
	const char		*http_content_type;
	const char		*http_if_modified_since;
	const char		*http_if_none_match;

	size_t			content_length;
    unsigned                http_state:4;
	/* 
     * use for parse line 
     */
    unsigned int                    state;

    u_char                           *uri_start;
    u_char                           *uri_end;
    u_char                           *uri_ext;
    u_char                           *args_start;
    u_char                           *request_start;
    u_char                           *request_end;
    u_char                           *method_end;
    u_char                           *schema_start;
    u_char                           *schema_end;
    u_char                           *host_start;
    u_char                           *host_end;
    u_char                           *port_start;
    u_char                           *port_end;

    u_char                           *header_name_start;
    u_char                           *header_name_end;
    u_char                           *header_start;
    u_char                           *header_end;
}zgx_request_t;

typedef enum {
    ZGX_ACCEPT = 0,
    WAIT_REQUEST,
    READ_REQUEST,
    REQUEST_DONE,
    RESPONSE,
    CLOSE,
}zgx_http_state;


struct zgx_open_file_s {
	char		*name;
	int			fd;
};


typedef struct configure {
	char			*user;
	char				*host;
	int					process_num;
	int					port;
	char				*dir;
	char				*pidfile;
	char				*log;
	char				*error_log;
	int					llevel;
	unsigned long		connections_n;
	unsigned long		events;
	char        		*lockfile;

}configure_t;



struct zgx_queue_s {
	zgx_queue_t 	*prev;
	zgx_queue_t		*next;
};


typedef struct zgx_cycle_s {
	zgx_open_file_t			*file;
	zgx_connection_t		*connections;

	zgx_listening_t			*ls;
	zgx_listening_t			*next;

    FILE                    *logfp;
	int						listen_num;
	
	int						cpu_number;
	int						level;
	
	unsigned				use_accept_mutex:1;
	
}zgx_cycle_t;

typedef struct zgx_process_cycle_s {
	zgx_connection_t		*connections;
	zgx_connection_t		*free_connections;
	
	zgx_event_t				*read_events;
	zgx_event_t				*write_events;
	struct epoll_event  	*event_list;
    zgx_queue_t             reusable_connections_queue;

	unsigned long 			free_connection_n;
	int 					epfd;

	//zgx_shmtx_t				*zgx_shmtx;
	
}zgx_process_cycle_t;

struct zgx_listening_s {
	int				fd; //listen fd
	
	struct sockaddr	 sockaddr;
	struct sockaddr_in sa_in;
	socklen_t		socklen;
    int             sin_port;
	#ifdef USE_IPV6
	#endif

	zgx_connection_t		*connection;
	zgx_connection_handler_pt handler;
};

/*
typedef union epoll_data {
    void                *ptr;
    int                 fd;
    unsigned int        u32;
    unsigned long long  u64;
} epoll_data_t;

struct epoll_event {
    uint32_t      events;
    epoll_data_t  data;
};
*/
volatile zgx_event_t	*zgx_posted_accept_events;
volatile zgx_event_t	*zgx_posted_events;
typedef void (*zgx_spawn_proc_pt) (void *data);
extern zgx_cycle_t cycle;
extern zgx_process_cycle_t process_cycle;
extern configure_t      conf;
extern zgx_shmtx_t      zgx_shmtx;
void * zgx_calloc(int size);
void * zgx_alloc(int size);


#endif
