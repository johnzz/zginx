#include "zgx_epoll.h"

#define ZGX_SOCKADDRLEN 512 
#define	ZGX_BUFFER_SIZE	1024

#define ZGX_POST_EVENTS 1
#define zgx_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)

int		use_accept_mutex = 1;
int		accept_mutex_held;
unsigned int	timeout = 500 ;//ms;
static int	accept_disabled = 0;
static struct epoll_event		*event_list;
static unsigned long	g_events;

zgx_connection_t * zgx_get_connection(zgx_process_cycle_t *process_cycle, int fd); 
void zgx_close_accepted_connection(zgx_connection_t *c);
static int zgx_epoll_add_conn(zgx_connection_t *c);
void zgx_epoll_process_events(zgx_process_cycle_t *process_cycle,
                                                      int timeout, int flags);

void zgx_event_process_posted(zgx_process_cycle_t *pc, volatile zgx_event_t  * * events);

static void zgx_locked_inqueue(zgx_event_t **queue, zgx_event_t *ev)
{
	if (ev->next == NULL) {
		ev->next = (zgx_event_t *) *queue;
		ev->prev = (zgx_event_t **)queue;
		*queue = ev;

		if (ev->next) {
			ev->next->prev = &ev->next;
		}

	}

	zgx_log(DEBUG,"Update event  %p ",ev);
}

static void zgx_locked_outqueue(zgx_event_t *ev)
{
/*
	if (!*queue) {
		zgx_log(ERROR,"queue:%p is empty",queue);
		return;
	}
*/
	*(ev->prev) = ev->next;
	if (ev->next) {
		ev->next->prev = ev->prev;
	}
	ev->prev = NULL;
}

void zgx_accept_event(zgx_event_t *ev)
{
	int		cfd;
	zgx_connection_t	*c;
	zgx_listening_t		*l;
	zgx_event_t			*rev;
	zgx_event_t			*wev;
	char		sa[ZGX_SOCKADDRLEN];
	int			socklen = ZGX_SOCKADDRLEN;
	int			err;
	
	l = cycle.ls;

    cfd = accept(l->fd, (struct sockaddr *)sa, &socklen);
	if (cfd == (int)-1) {
		err = errno;
		if (err == EAGAIN) {
			zgx_log(ERROR,"accept not ready!");
			return;
		}
		if (err == ENFILE || err == EMFILE) {
			zgx_log(ERROR,"errno is ENFILE or EMFILE");
		}
	}

    zgx_nonblocking(cfd);
	c = zgx_get_connection(&process_cycle, cfd);
	if (!c) {
		zgx_log(ERROR,"zgx_get_connection failed!");
		return;
	}
	
	c->connection_status = ACCEPT;
	c->buffer = zgx_calloc(ZGX_BUFFER_SIZE);
	c->local_sockaddr = &l->sockaddr;
	
	rev = c->read;
	wev = c->write;
	rev->read = 1;

	l->handler(c);
	if (zgx_epoll_add_conn(c) == ZGX_ERROR) {
		zgx_close_accepted_connection(c);
	}
}

static void zgx_read_request_handler(zgx_event_t *e)
{
    zgx_connection_t        *c;
    char    buff[1024];
    
    zgx_log(DEBUG,"i 'm read request handler!'");
    c = e->data;
    c = (zgx_connection_t *)((unsigned int)c & (unsigned int)~1);
    sprintf(buff,"i'm a test !");
    write(c->fd, buff, strlen(buff));
    close(c->fd);
    return;
}

static void zgx_request_handler(zgx_event_t *e) 
{

}

void zgx_close_accepted_connection(zgx_connection_t *c)
{

}

void zgx_drain_connections()
{

}

zgx_connection_t * zgx_get_connection(zgx_process_cycle_t *process_cycle, int fd)
{
	zgx_connection_t	*c;
	zgx_event_t			*rev;
	zgx_event_t			*wev;
	int			instance;

	c = process_cycle->free_connections;
	if (c == NULL) {
		zgx_drain_connections();
		c = process_cycle->free_connections;
	}
	
	if (c == NULL) {
		zgx_log(ERROR,"get connection is null!");
		return NULL;
	}

	process_cycle->free_connections = c->data;
	process_cycle->free_connection_n--;

	rev = c->read;
	wev = c->write;

	memset(c,0,sizeof(zgx_connection_t));

	c->read = rev;
	c->write = wev;
	c->fd = fd;

	instance = rev->instance;
	memset(rev, 0, sizeof(zgx_event_t));
	memset(wev, 0, sizeof(zgx_event_t));

	//why malloc last bit is 0?
	rev->instance = !instance;
	wev->instance = !instance;

	rev->data = c;
	wev->data = c;

	wev->write = 1;

	return c;
	
}

static void zgx_set_ls_handler(zgx_connection_t *e)
{
	if (e) {
		e->read->handler = zgx_read_request_handler;
		e->write->handler = zgx_request_handler;
		return;
	}

	zgx_log(ERROR,"zgx_set_ls_handler error!");
}

void zgx_process_event_init(zgx_process_cycle_t *process_cycle)
{
	zgx_connection_t	*connections = NULL;
	zgx_connection_t	*next = NULL;
	zgx_connection_t	*c;
	unsigned long  connections_n = conf.connections_n;
	zgx_event_t		*read_events;
	zgx_event_t		*write_events;
	struct epoll_event ee;
	zgx_event_t		*e;

	unsigned long	i,l;

	connections = zgx_alloc(connections_n*sizeof(zgx_connection_t));
	if (!connections) {
		zgx_log(ERROR,"zgx_alloc connections failed");
		return;
	}

	read_events = zgx_alloc(connections_n*sizeof(zgx_event_t));
	if (!read_events) {
		zgx_log(ERROR,"zgx_alloc read_events failed!");
		free(connections);
		connections = NULL;
		return;
	}

	write_events = zgx_alloc(connections_n*sizeof(zgx_event_t));
	if (!write_events) {
		zgx_log(ERROR,"zgx_alloc write_events failed!");
		free(connections);
		free(read_events);
		connections = NULL;
		read_events = NULL;
		return;
	}

	process_cycle->connections = connections;
	i = connections_n;
	do {
		i--;
		connections[i].data = next;
		connections[i].fd	= (int)-1;
		connections[i].read = &read_events[i];
		connections[i].write = &write_events[i];
		next = &connections[i];
	} while (i);

	process_cycle->free_connections = next;

	process_cycle->epfd = epoll_create( conf.connections_n/2 );
	ee.data.fd = cycle.ls->fd;
	ee.events = EPOLLIN|EPOLLET;

    c = zgx_get_connection(process_cycle, cycle.ls->fd);
	if (!c) {
		zgx_log(DEBUG,"epoll_ctl zgx_get_connection error!");
		return;
	}

    /*
    zgx_log(DEBUG,"epoll_add listen fd:%d in epoll fd:%d!",cycle.ls->fd,process_cycle->epfd);
	if ( epoll_ctl(process_cycle->epfd, ZGX_EPOLL_CTL_ADD, cycle.ls->fd, &ee) < 0 ) {
		zgx_log(DEBUG,"epoll_ctl process_cycle.epfd error!");
		return;
	}
    ee.data.ptr = (void *)((int)c | c->read->instance);
	*/
    c->read->accept = 1;

	cycle.ls->connection = c;
	cycle.ls->handler = zgx_set_ls_handler;
	c->read->handler = zgx_accept_event;
	
	g_events = conf.events;
	event_list = zgx_alloc(g_events*sizeof(struct epoll_event));
	if (!event_list) {
		zgx_log(ERROR,"alloc event_list error!");
		return;
	}


	return ;
}

void zgx_process_events(zgx_process_cycle_t *process_cycle)
{
	int flags;

	if (use_accept_mutex) {
		if (accept_disabled > 0) {
			accept_disabled--;
		} else {

			if (zgx_trylock_accept_mutex(process_cycle) == ZGX_ERROR) {
                return;
			}


            zgx_log(ERROR,"accept_mutex_held %d",accept_mutex_held);
			if (accept_mutex_held) {
				flags |= ZGX_POST_EVENTS;
			}
		}
	}

	zgx_epoll_process_events(process_cycle, timeout, flags);

    if (zgx_posted_accept_events) {
		zgx_event_process_posted(process_cycle, &zgx_posted_accept_events);
	}

	if (accept_mutex_held) {
		zgx_unlock(&zgx_shmtx);
	}

	if (zgx_posted_events) {
		zgx_event_process_posted(process_cycle, &zgx_posted_events);
	}
}

static int zgx_epoll_add_event(zgx_event_t *ev,  int event,int flags)
{
	zgx_event_t		*e;
	zgx_connection_t	*c;
	struct	epoll_event ee;
	unsigned int		prev,events,op;
	
	c = ev->data;
    events = event;

	if (event == ZGX_READ_EVENT) {
		e = c->write;
		prev = EPOLLOUT;
	}  else {
		e = c->read;
		prev = EPOLLIN | EPOLLRDHUP;
	}

	if (ev->active) {
		op = EPOLL_CTL_MOD;
		events |= prev;
        zgx_log(ERROR,"i'm mod:%d",process_cycle.epfd);
	} else {
		op = EPOLL_CTL_ADD;

	}

	ee.events = events | flags;
	ee.data.ptr = (void *)((int)c | ev->instance);

    zgx_log(ERROR,"process_cycle.epfd:%d",process_cycle.epfd);
	if (epoll_ctl(process_cycle.epfd, op, c->fd, &ee) == -1) {
		zgx_log(ERROR,"epoll_ctl(%d,%d) add events error!%d",op,c->fd,errno);
		return ZGX_ERROR;
	}

	ev->active = 1;

	return ZGX_OK;
}

static int zgx_epoll_add_conn(zgx_connection_t *c) 
{
	struct epoll_event		ee;

	ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
	ee.data.ptr = (void *)((int)c | c->read->instance);
	
	zgx_log(ERROR,"zgx_epoll_add_conn begin");
	if (epoll_ctl(process_cycle.epfd, ZGX_EPOLL_CTL_ADD, c->fd, &ee ) == -1) {
		zgx_log(ERROR,"epoll_ctl(%d,ZGX_EPOLL_CTL_ADD) failed!",process_cycle.epfd);

		return ZGX_ERROR;
	}
	
	c->read->active = 1;
	c->write->active = 1;

	return ZGX_OK;
}
static int zgx_epoll_del_event(zgx_event_t *ev, int event, int flags)
{
	struct epoll_event		ee;
	zgx_connection_t		*c;
	zgx_event_t				*e;
	int						prev,op;
	
	if (flags | ZGX_DISABLE_EVENT) {
		ev->active = 0;
		return ZGX_OK;
	}

	c = ev->data;
	if (event == ZGX_READ_EVENT) {
		e = c->write;
		prev = EPOLLOUT;
	} else {
		e = c->read;
		prev = EPOLLIN |EPOLLRDHUP;
	}
	
	if (e->active) {
		op = EPOLL_CTL_MOD;
		ee.events = prev | flags;
		ee.data.ptr = (void *)((int) c | ev->instance);
	} else {
		op = EPOLL_CTL_DEL;
		ee.events = 0;
		ee.data.ptr = NULL;
	}

	zgx_log(DEBUG,"epoll_ctl(%d,ZGX_EPOLL_CTL_ADD) !",process_cycle.epfd);
	
	if (epoll_ctl(process_cycle.epfd, op, c->fd, &ee) == -1) {
		zgx_log(ERROR,"epoll_ctl(%d,ZGX_EPOLL_CTL_ADD) failed!",process_cycle.epfd);
		return ZGX_ERROR;		
	}
	
	ev->active = 0;

	return ZGX_OK;
}

void zgx_epoll_process_events(zgx_process_cycle_t *process_cycle,
										int timeout, int flags)
{
	zgx_event_t		*rev,*wev,**queue;
	int	            i,ret;
	zgx_connection_t	*c;
	unsigned int	 instance;
	int				 revents;
	
    zgx_log(DEBUG,"begin to process events!");

	ret = epoll_wait(process_cycle->epfd, event_list, g_events, timeout);

    zgx_log(DEBUG,"get %d events!",ret);

	for (i=0; i<ret; i++) {
		c = event_list[i].data.ptr;

		instance = (unsigned int)c & 1;
		c = (zgx_connection_t *)((unsigned int)c & (unsigned int)~1);

		rev = c->read;
		//wev = c->write;

		revents = event_list[i].events;

		if (c->fd == -1 || rev->instance != instance) {
			zgx_log(ERROR,"stale connection %p",c);
			continue;
		}

		if (revents &(EPOLLERR|EPOLLHUP)) {
			zgx_log(ERROR,"epoll_wait() error on fd:%d ev:%04xd",c->fd,revents);
		}

		if ((revents & EPOLLIN) && rev->active) {
			if (flags & ZGX_POST_EVENTS) {
				queue = (zgx_event_t **)(rev->accept ? &zgx_posted_accept_events:&zgx_posted_events);
				zgx_locked_inqueue(queue,rev);
				continue;
			} else {
                zgx_log(DEBUG,"call read handler!");
				rev->handler(rev);
			}
		}

		wev = c->write;
		if ((revents & EPOLLOUT) && wev->active) {
			if (flags & ZGX_POST_EVENTS) {
				queue = (zgx_event_t **)&zgx_posted_events;
				zgx_locked_inqueue(queue,wev);
			} else {
                zgx_log(DEBUG,"call write handler!");
				wev->handler(wev);
			}
		}


	}

}

static int zgx_enable_accept(void)
{
	zgx_listening_t		*ls;
	zgx_connection_t	*c;
	int		ret;

	ls = cycle.ls;
	c = ls->connection;

	if (c->read->active) {
	    return ZGX_OK;
    }

	if (zgx_epoll_add_event(c->read, ZGX_READ_EVENT,0) == ZGX_ERROR ) {
        zgx_log(ERROR,"i'm test %d",getpid());
		return ZGX_ERROR;
	}

	return ZGX_OK;
}

static int zgx_disable_accept()
{
	zgx_connection_t	*c;
	zgx_listening_t		*l;

	l = cycle.ls;
	c = l->connection;

	if (!c->read->active) {
		return ZGX_OK;
	}
	
	if (zgx_epoll_del_event(c->read, ZGX_READ_EVENT, ZGX_DISABLE_EVENT) == ZGX_ERROR ) {
		return ZGX_ERROR;
	}

	return ZGX_OK;
}

int zgx_trylock_accept_mutex()
{
	if (zgx_trylock()) {

		zgx_log(DEBUG,"accept mutex locked,pid:%d",getpid());

		if (accept_mutex_held)
			return ZGX_OK;

		if (zgx_enable_accept() == ZGX_ERROR) {
			zgx_unlock(&zgx_shmtx);
			return ZGX_ERROR;
		}

		accept_mutex_held = 1;

		return ZGX_OK;
	}

	zgx_log(DEBUG,"accept mutex lock failed");

	if (accept_mutex_held) {
		if (zgx_disable_accept() == ZGX_ERROR ) {
			return ZGX_ERROR;
		}

		accept_mutex_held = 0;
	}

	return ZGX_OK;
}

void zgx_event_process_posted(zgx_process_cycle_t *pc, volatile zgx_event_t **events)
{
    zgx_event_t     *ev;

    for( ;; ){
        ev = (zgx_event_t *) *events;

        if (ev == NULL) {
            return;
        }

        zgx_locked_outqueue(ev);

        ev->handler(ev);
    }
}

