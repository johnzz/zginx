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

int zgx_list_init(zgx_list_t *list, unsigned int n, size_t  size)
{
    list->part.elts = zgx_calloc(n*size);
    if (list->part.elts == NULL ){
        return ZGX_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;

    return ZGX_OK;
}
