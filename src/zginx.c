#include "zginx.h"

#define ZGX_MAX_PROCESS 1024
zgx_cycle_t cycle;

zgx_process_cycle_t process_cycle;

int make_deamon()
{
	pid_t	pid;
	int		i;
	
	pid = fork();
	if (pid < 0 ){
		fprintf(stderr,"make deamon error!\n");
		return -1;
	}
	if(pid > 0) {
		exit(0);
	}
	if(setsid() < 0){
		perror("setsid()");
		return -1;
	}
	chdir("/");

   // close(0);
	//close(1);
	//close(2);

	umask(0);
	
	return 0;
}


int init_listening_socket(zgx_listening_t *l)
{
	int		rc;
    int     flags;
    int     i = 1;

	l = zgx_alloc(sizeof(zgx_listening_t));
	if (!l) {
		zgx_log(ERROR,"zgx_alloc zgx_listening_t failed!");
		return -1;
	}
	
	l->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (l->fd  < 0) {
		zgx_log(ERROR,"socket() error!");
		return -1;
	}
/*
	if (fcntl(l->fd, F_SETFL, O_NONBLOCK) < 0 ){
		perror("fcntl error!");
		close(l->fd);
		return -1;
	}
*/
    bzero(&l->sa_in,sizeof(l->sa_in));

	l->sa_in.sin_family = AF_INET;
	l->sa_in.sin_port = htons(conf.port);

    if ( (rc=inet_pton(AF_INET,conf.host,(void *)&(l->sa_in.sin_addr))) < 0 ){
		zgx_log(ERROR, "Illegal address: %s\n", conf.host);
		close(l->fd);
		return -1;
	}

	//setsockopt(l->fd, SOL_SOCKET, SO_REUSEADDR, (void *)&i, sizeof(i));

	if (bind(l->fd, (struct sockaddr *)&(l->sa_in), sizeof(l->sa_in)) < 0) {
		zgx_log(ERROR,"bind fd:%d error!",l->fd);
		close(l->fd);
		return -1;
	}

	if (listen(l->fd,1024) < 0) {
		zgx_log(ERROR,"listen error!");
		close(l->fd);
		return -1;
	}

	cycle.ls = l;

    zgx_log(ERROR,"bind fd:%d host:%s,port:%d,success!",l->fd,conf.host,conf.port);
	return 0;
}

int  zgx_worker_process_init(int worker, zgx_process_cycle_t *process_cycle)
{
	cpu_set_t mask;
	int			i;
	
	process_cycle = (zgx_process_cycle_t *)zgx_calloc(sizeof(zgx_process_cycle_t));
	if (!process_cycle) {
		zgx_log(ERROR,"zgx_calloc failed!\n");
		return -1;
	}
	
	i = worker % cycle.cpu_number;
	CPU_ZERO(&mask);
	CPU_SET(i, &mask);
	if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1){
		zgx_log(ERROR,"sched_setaffinity() failed!");
		return -1;
	}

	return 0;
	
}
void zgx_process_exit(zgx_process_cycle_t *process_cycle) 
{
}

void zgx_worker_process_cycle(void *data)
{
	int worker = (int) data;
	int		ep;
	
	zgx_log(DEBUG,"in worker cycle %d!\n",getpid());
	zgx_worker_process_init(worker, &process_cycle);
	//setproctitle("%s","work_process");

	zgx_process_event_init(&process_cycle);

    for ( ; ; ) {
        /*
		if (zgx_terminate) {
			zgx_log(ERROR,"process is exit!\n");
			zgx_process_exit(&process_cycle);
		}
*/
		//zgx_trylock_enable_accept();
		zgx_process_events(&process_cycle);
	}
}

void * zgx_start_worker_process(void *data, zgx_spawn_proc_pt process)
{
	int retpid;
	
	retpid = fork();
	switch(retpid) {
		case -1:
			zgx_log(ERROR,
                      "fork() failed while spawning");
			return NULL;
		case 0:
			process(data);
			break;
		default:
			break;
	}
}

void cycle_init()
{
	zgx_log_init();
	cycle.level = conf.llevel;

	/*
	*get cpu number
	*/
	cycle.cpu_number = sysconf(_SC_NPROCESSORS_ONLN);

	cycle.listen_num = 1;

	cycle.use_accept_mutex = 1;
	
}

int main(int argc, char *argv[])
{
	char			*conf_path;
	struct passwd	*pwd;
	FILE			*pidfd;
	zgx_listening_t	*listen;
	uid_t			uid;
	gid_t			gid;
	char			c;
	int				ret;
	int				i;

	while ((c = getopt(argc,argv,"c:")) != -1 ) {
		switch (c) {
		case 'c':
			conf_path = optarg;
			break;
		default:
			fprintf(stderr,"Usage:%s -c ConfigFile\r\n",argv[0]);
			return -1;
		}
	}

    fprintf(stderr,"conf path %s\n",conf_path);
	if ( (ret = parse_conf(conf_path)) < 0) {
		return -1;
	}

	cycle_init();
	zgx_shmtx_init();

	/* If we're root and we're going to become another user, get the uid/gid
    ** now.
    */
	
	if (getuid() == 0) {
		pwd = getpwnam("www");
		if (!pwd) {
			fprintf(stderr,"unkown user:%s\n",conf.user);
			return -1;
		}
		
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;
	}
	/*logfile
	*/
	if (conf.log[0] != '/') {
		fprintf(stderr,"pls set log abs path!\n");
		return -1;
	}
	
	cycle.logfp = fopen(conf.log,"a");
	if (!cycle.logfp){
		fprintf(stderr,"open the log [%s] error!\n",conf.log);
		return -1;
	}

	if (getuid() == 0) {
		if ( fchown(fileno(cycle.logfp),uid,gid) < 0) {
			fprintf(stderr,"fchown logfile - error!\n");
			return -1 ;
		}
	}
	
	/*daemonize
	*/
	if ( (ret = make_deamon()) < 0 ) {
		fprintf(stderr,"make daemon error!\n");
		return -1;
	}

	if (conf.pidfile[0] != '/') {
		fprintf(stderr,"it's not a abs path!\n");
	}
	
	pidfd = fopen(conf.pidfile,"w");
	if (!pidfd){
		fprintf(stderr, "can't open [%s] pid file!\n",conf.pidfile);
		return -1;
	}

	fprintf(pidfd,"%d\n",(int)getpid());
	fclose(pidfd);

    zgx_log(ERROR,"begin to listen!");
	if ( init_listening_socket(listen) < 0 ) {
        return -1;
	}
	
	for (i=0;i<conf.process_num;i++) {
		zgx_start_worker_process((void *)(int) i, zgx_worker_process_cycle);
	}
	
	
}


