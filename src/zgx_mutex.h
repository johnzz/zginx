#ifndef __ZGX_MUTEX_H__
#define __ZGX_MUTEX_H__

//#include "zginx.h"

typedef struct {
#if (ZGX_HAVE_ATOMIC_OPS)
    zgx_atomic_t  *lock;
#if (ZGX_HAVE_POSIX_SEM)
    zgx_atomic_t  *wait;
    unsigned int   semaphore;
    sem_t          sem;
#endif
#else
	int			fd;
	char		*name;
}zgx_shmtx_t;


int zgx_trylock();
void zgx_unlock(zgx_shmtx_t *zgx_shmtx);
//extern zgx_shmtx_t		zgx_shmtx;
//extern configure_t      conf;
#endif
#endif
