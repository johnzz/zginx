#include "zginx.h"

#define ZGX_MAX_PROCESS 1024
zgx_cycle_t cycle;

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
	for (i=0; i<getdtablesize();i++) {
		close(i);
	}
	
	umask(0);
	
	return 0;
}


int init_listening_socket(zgx_listening_s *l)
{
	int		rc;
	
	l.fd = socket(AF_INET,SOCK_STREAM,0);
	if (l.fd  < 0) {
		perror("socket()");
		return -1;
	}

	if (fcntl(l.fd,F_SETFL,O_NONBLOCK) < 0 ){
		perror("fcntl error!");
		close(l.fd);
		return -1;
	}

	l.sa_in.sin_family = AF_INET;
	l.sin_port = htons(conf.port);
	if ( (rc=inet_pton(AF_INET,conf.host,(void *)&(l.sa_in.sin_addr))) <0 ){
		fprintf(stderr, "Illegal address: %s\n", conf.host);
		close(l.fd);
		return -1;
	}

	//setsockopt(l.fd, SOL_SOCKET, SO_REUSEADDR,const void *optval, socklen_t optlen)

	if (bind(l.fd, (struct sockaddr *)&(l.sa_in), sizeof(l.sa_in)) < 0) {
		fprintf(stderr,"bind error!");
		close(l.fd);
		return -1;
	}

	if (listen(l.fd,1024) < 0) {
		fprintf(stderr,"listen error!");
		close(l.fd);
		return -1;		
	}

	return 0;
	
}

void zgx_worker_process_init(int worker)
{
	cpu_set_t mask;
	int			i;
	
	CPU_ZERO(&mask);
	i = 0;
	
	while ( cpu_num ) {
		CPU_SET(i, &mask);
		i++;
		cpu_num --;
	}

	if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
                           sizeof(cpuset_t), &mask) == -1){
		zgx_log(ERROR,"cpu_setaffinity() failed!");
	}
}
void * zgx_worker_process(void *data)
{
	int worker = (int) data;
	
	zgx_worker_process_init(worker);
	setproctitle("%s","work_process");
	
	
}

void * zgx_start_worker_process(void *data, zgx_spawn_proc_pt process)
{
	int retpid;
	
	retpid = fork();
	switch(retpid) {
		case -1:
			zgx_log(ERROR,
                      "fork() failed while spawning \"%s\"", name);	
			return -1;
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
	
}

int main(int argc, char *argv[])
{
	char			*conf_path;
	struct passwd	*pwd;
	FILE			*pidfd;
	zgx_listening_s	*listen;
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
	
	if ( (ret = parse_conf(conf_path)) < 0) {
		return -1;
	}

	cycle_init();

	/* If we're root and we're going to become another user, get the uid/gid
    ** now.
    */
	
	if (getuid() == 0) {
		pwd = getpwnam(conf.user);
		if (!pwd) {
			fprintf(stderr,"unkown user - %s",conf.user);
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

	if ( init_listening_socket(listen) < 0) {
		return -1;
	}
	
	for (i=0;i<conf.process_num,i++) {
		zgx_start_worker_process((void *)(int) i, zgx_worker_process);
	}
	
	
}
