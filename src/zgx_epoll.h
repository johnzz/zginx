#ifndef __ZGX_EPOLL_H__
#include "zginx.h"

#define ZGX_EPOLL_CTL_ADD EPOLL_CTL_ADD 
#define ZGX_EPOLL_CTL_MOD EPOLL_CTL_MOD
#define ZGX_EPOLL_CTL_DEL EPOLL_CTL_DEL

#define ZGX_READ_EVENT     (EPOLLIN|EPOLLRDHUP)
#define ZGX_WRITE_EVENT    EPOLLOUT

#define ZGX_DISABLE_EVENT	1
#define	ZGX_CLOSE_EVENT		2

typedef enum {
	ACCEPT = 0,

}connection_status;


void zgx_close_accepted_connection(zgx_connection_t *c);
void zgx_process_events(zgx_process_cycle_t *process_cycle);
void zgx_process_event_init(zgx_process_cycle_t *process_cycle);
//extern zgx_shmtx_t     zgx_shmtx;

#endif


