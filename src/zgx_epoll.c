#include "zgx_epoll.h"

int		use_accept_mutex;
int		accept_mutex_held;
unsigned int	timeout;
unsigned int	accept_disabled;

void zgx_accept_event()
{
}

zgx_connection_t * zgx_get_connection(int fd)
{
	
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
		connections[i].read = read_events[i];
		connections[i].write = write_events[i];
		next = &connections[i];
		
	} while (i)

	process_cycle.free_connections = next;
	
	process_cycle.epfd = epoll_create( conf.connections_n/2 );
	ee.data.fd = cycle.ls.fd;
	ee.events = EPOLLIN|EPOLLET;
	if ( epoll_ctl(process_cycle.epfd, ZGX_EPOLL_CTL_ADD, cycle.ls.fd, &ee) < 0 ) {
		zgx_log(ERROR,"epoll_ctl process_cycle.epfd error!");
		return;
	}
	
	c = zgx_get_connection(cycle.ls.fd);
	if (!c) {
		zgx_log(ERROR,"epoll_ctl zgx_get_connection error!");
		return;
	}
	
	c->read->handler = zgx_accept_event;
	c->read->accept = 1;
	
	
	return ;
}

void zgx_process_event(zgx_process_cycle_t *process_cycle)
{
	int flags;
	
	if (use_accept_mutex) {
		if (accept_disabled > 0) {
			accept_disabled--;
		} else {
			if (zgx_trylock_enable_accept(process_cycle) == ZGX_ERROR) {
				return;
			}

			if (accept_mutex_held) {
				flags |= ZGX_POST_EVENTS;
			}
		}
	}
}

int zgx_trylock_enable_accept()
{
	if (zgx_lock)
}

