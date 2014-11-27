#include "zgx_mutex.h"
#include "zginx.h"

zgx_shmtx_t		zgx_shmtx;

int zgx_shmtx_init()
{
	int		fd;

    fd = open(conf.lockfile->name,O_RDWR|O_CREAT|O_APPEND,S_IRWXU|S_IRGRP|S_IROTH);
	if ( fd == -1 ) {
		zgx_log(ERROR,"open lockfile %s error!",conf.lockfile->name);
		return ZGX_ERROR;
	}
	zgx_shmtx.name = conf.lockfile->name;

	return ZGX_OK;
}

int zgx_trylock_fd()
{
	struct flock fl;
	
	int fd = zgx_shmtx.fd;
	
	memset(&fl,0,sizeof(struct flock));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;

	if ( fcntl(fd, F_SETLK, &fl) == -1) {
		return ZGX_ERROR;
	}
	
	return ZGX_OK;
}

int zgx_trylock()
{
	int		err;
	
	err = zgx_trylock_fd();
	if (err == 0) {
		return 1;
	}
	
	return 0;
}

int zgx_unlock_fd(int fd)
{
	struct flock  fl;

	memset(&fl,0,sizeof(struct flock));
	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;

	if ( fcntl(fd, F_SETLK, &fl) == -1) {
		return ZGX_ERROR;
	}

	return ZGX_OK;
}

void zgx_unlock(zgx_shmtx_t *zgx_shmtx)
{
	int		err;
	int		fd = zgx_shmtx->fd;
	
	err = zgx_unlock_fd(fd);
	if (err == 0){
		return;
	}
	zgx_log(ERROR,"zgx_unlock failed!");
}
