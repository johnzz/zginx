#ifndef __ZGX_EPOLL_H__
#include "zginx.h"

#define ZGX_EPOLL_CTL_ADD EPOLL_CTL_ADD 
#define ZGX_EPOLL_CTL_MOD EPOLL_CTL_MOD
#define ZGX_EPOLL_CTL_DEL EPOLL_CTL_DEL

#define ZGX_READ_EVENT     (EPOLLIN|EPOLLRDHUP)
#define ZGX_WRITE_EVENT    EPOLLOUT

typedef enum {
	ACCEPT = 0,
	
}connection_status;

#endif


