#include <sys/net.h>
#include <event.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>


#define ZGX_INVALID_FILE -1
#define ZGX_OK 0

extern configure_t		conf;
typedef enum {
	HTTP_METHOD_UNSET = -1,
	HTTP_METHOD_GET,
	HTTP_METHOD_HEAD,
	HTTP_METHOD_POST,
	HTTP_METHOD_PUT,
	HTTP_METHOD_CONNECT,
}zgx_method_t;

typedef enum {
	ZGX_LOG_DEBUG = 0,
	ZGX_LOG_ERROR,
	ZGX_LOG_CRIT,
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
	char		*start;
	size_t		used;
	size_t		size;
}zgx_buff_t;

typedef struct zgx_connection_s {
	void				*data;
	zgx_event_t			*read;
	zgx_event_t			*write;
	int					fd;

	
	#ifdef USE_SSL
	SSL					*ssl;
	#endif
	
	struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;
	int					connection_status;
	zgx_buff_t			*buffer;
	
	unsigned			reuse:1;
	
}zgx_connection_t;

typedef struct zgx_request_s {
	zgx_buff_t		*request;
	zgx_buff_t		*uri;
	zgx_buff_t		*orig_uri;

	zgx_method_t	http_method;
	zgx_version_t	http_version;

	zgx_buff_t		*request_line;
	zgx_buff_t		*http_host;
	const char		*http_range;
	const char		*http_content_type;
	const char		*http_if_modified_since;
	const char		*http_if_none_match;

	size_t			content_length;
	
}zgx_request_t;

typedef struct configure {
	const char			*user;
	char				*host;
	int					process_num;
	int					port;
	char				*dir;
	char				*pidfile;
	char				*log;
	char				*error_log;
	int					llevel;
	
}configure_t;

typedef void (*zgx_event_handler_pt)(zgx_event_t *ev);

typedef struct zgx_event_s {
	void			*data;
	unsigned		accept:1;
	unsigned		write:1;
	unsigned		read:1;
	unsigned		ready:1;

	/* the links of the posted queue */
    zgx_event_t     *next;
    zgx_event_t    **prev;
	
	zgx_event_handler_pt	handler;
}zgx_event_t;

typedef struct zgx_queue_s {
	zgx_queue_t 	*prev;
	zgx_queue_t		*next;
}zgx_queue_t;

typedef struct zgx_open_file_s {
	char		*name;
	int			fd;
}zgx_open_file_t;

typedef struct zgx_cycle_s {
	zgx_open_file_t	*file;
	int			level;
	
}zgx_cycle_t;

typedef struct zgx_listening_s {
	int				fd; //listen fd
	//struct sockaddr	 sockaddr;
	struct sockadd_in sa_in;
	socklen_t		socklen;
	#ifdef USE_IPV6
	#endif
	
	zgx_connection_handler_pt handler;
};

typedef void(*zgx_connection_handler_pt)(zgx_connection_t *c);
typedef volatitle zgx_event_t	*zgx_posted_accept_events;
typedef	volatitle zgx_event_t	*zgx_posted_events;
typedef void (*zgx_spawn_proc_pt) (void *data);
extern zgx_cycle_t cycle;