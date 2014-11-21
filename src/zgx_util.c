#include "zginx.h"

#define zgx_memzero(buf,n) (void)memset(buf,0,n)
void * zgx_alloc(size_t size)
{
	void		*p;
	p = malloc(size);
	if (p == NULL) {
		zgx_log(ERROR,"malloc (%uz) failed",size);
		return NULL;
	}

	zgx_log(DEBUG,"malloc: %p:%uz",p,size);
	
	return p;
}



void * zgx_calloc(size_t size)
{
	void		*p;
	p = zgx_alloc(size);
	if (p) {
		zgx_memzero(p,size);
		return p;
	}
	
	return NULL;
}

