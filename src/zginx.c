#include "zginx.h"

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
int main(int argc, char *argv[])
{
	char			*conf_path;
	struct passwd	*pwd;
	uid_t			uid;
	gid_t			gid;
	char			c;
	int				ret;

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
	
	if ( (ret = make_deamon()) < 0 ) {
		fprintf(stderr,"make daemon error!\n");
		return -1;
	}
	
	
}
