#include "zginx.h"

#define zgx_memzero(buf,n) (void)memset(buf,0,n)

void * zgx_alloc(int size)
{
	void		*p;

    p = malloc(size);
	if (p == NULL) {
		return NULL;
	}

//	zgx_log(DEBUG,"malloc: %p:%uz",p,size);

	return p;
}



void * zgx_calloc(int size)
{
	void		*p;

	p = zgx_alloc(size);
	if (p) {
		zgx_memzero(p,size);
		return p;
	}

	return NULL;
}

