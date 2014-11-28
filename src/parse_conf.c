//#include "zginx.h"
#include "zgx_epoll.h"

configure_t		conf;
int conf_init(char *start, int flag,int len)
{
    char    *value = NULL;

    switch(flag) {
        case 0:
            value = malloc(len+1);
            conf.user = value;
	        strncpy(value,start,len);
            break;
        case 1:
            value = zgx_calloc(len+1);
            conf.host = value;
            strncpy(value,"127.0.0.1",len);
            break;
        case 2:
            value = zgx_calloc(len+1);
            conf.pidfile = value;
            strncpy(value,start,len);
            break;
        case 3:
            value = zgx_calloc(len+1);
            conf.log = value;
            strncpy(value,start,len);
            break;
        case 4:
            value = zgx_calloc(len+1);
            conf.lockfile = value;
            strncpy(value,start,len);
            break;
        default:
            fprintf(stderr,"can't run this default!\n");
            break;

    }

}

int  conf_set_value(char *ptr_start, char *ptr, char *value, int flag)
{
	char *start = ptr_start++;
	char *line  = ptr;
	char *end = NULL;
	int len;

    ++start;
	if ( (end = strchr(line,'\n')) == NULL ) {
		fprintf(stderr,"Can't find the conf value!\n");
		return -1;
	}

    len = ((int)end -(int)start) / sizeof(char);
	//conf.user = malloc(len+1);
    conf_init(start,flag,len);


    return ZGX_OK;
}

int parse_conf(char *conf_file)
{
	FILE	*fp;
	char	*start, *end;
	char	*line;

    line = (char * )zgx_alloc(2048);

	fp = fopen(conf_file, "r");
	if (!fp) {
		fprintf(stderr, "Can't open the file %s !\n",conf_file);
		return -1;
	}

	while (fgets(line,2048,fp) != NULL) {
        if ( (end = strchr(line,'=')) == NULL ) {
			fprintf(stderr,"config file [%s] is not valid!\n",conf_file);
			return -1;
		}

        start = line;
		if (!strncmp("user",start,((int)end-(int)start)/sizeof(char))) {
			if ( conf_set_value(end,line,conf.user,0) < 0) {
				fprintf(stderr,"Can't set [user] config item!\n");
				return -1;
			}
			fprintf(stdout,"user:%s\n",conf.user);
		}

		if (!strncmp("progress_num",start,((int)end-(int)start)/sizeof(char))) {
			end++;
			conf.process_num = atoi(end);
			fprintf(stdout,"startup %d process!\n",conf.process_num);
		}

		if (!strncmp("events",start,((int)end-(int)start)/sizeof(char))) {
			end++;
			conf.events= atoi(end);
			fprintf(stdout,"use epoll %lu events!\n",conf.events);
		}
		
		if (!strncmp("host",start,((int)end-(int)start)/sizeof(char))) {
			if ( conf_set_value(end,line,conf.host,1) < 0) {
				fprintf(stderr,"Can't set [host] config item!\n");
				return -1;
			}

			fprintf(stdout,"host:%s\n",conf.host);
		}
		
		if (!strncmp("port",start,((int)end-(int)start)/sizeof(char))) {
			end++;
			conf.port = atoi(end);
			fprintf(stdout,"use [%d] port!\n",conf.port);
		}

		if (!strncmp("pidfile",start,((int)end-(int)start)/sizeof(char))) {
			if ( conf_set_value(end,line,conf.pidfile,2) < 0) {
				fprintf(stderr,"Can't set [pidfile] config item!\n");
				return -1;
			}

			fprintf(stdout,"pidfile:%s\n",conf.pidfile);
		}

		if (!strncmp("log",start,((int)end-(int)start)/sizeof(char))) {
			if ( conf_set_value(end,line,conf.log,3) < 0) {
				fprintf(stderr,"Can't set [log path] config item!\n");
				return -1;
			}
			fprintf(stdout,"log:%s\n",conf.log);
		}

		if (!strncmp("llevel",start,((int)end-(int)start)/sizeof(char))) {
			end++;
			conf.llevel = atoi(end);
			fprintf(stdout,"use [%d] level!\n",conf.llevel);
		}

		if (!strncmp("connections_n",start,((int)end-(int)start)/sizeof(char))) {
			end++;
			conf.connections_n = atol(end);
			fprintf(stdout,"use [%lu] connections\n",conf.connections_n);
		}

		if (!strncmp("lockfile",start,((int)end-(int)start)/sizeof(char))) {
			if ( conf_set_value(end,line,conf.lockfile,4) < 0) {
				fprintf(stderr,"Can't set [pidfile] config item!\n");
				return -1;
			}

			fprintf(stdout,"lockfile:%s\n",conf.lockfile);
		}
	}

	return ZGX_OK;
}
