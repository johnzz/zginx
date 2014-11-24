#include "zginx.h"

configure_t		conf;

int  conf_set_value(char *ptr_start, char *ptr, char *value)
{
	char *start = ptr_start++;
	char *line  = ptr;
	char *end = NULL;
	int len;
	
	if ( (end = strchr(line,'\0')) == NULL ) {
		fprintf(stderr,"Can't find the conf value!\n");
		return -1;
	}

	len = (int)end-(int)start /sizeof(char);
	conf.user = malloc(len+1);
	strncpy(value,start,len);
	return ZGX_OK;
}

int parse_conf(char *conf_file)
{
	File	*fp;
	char	*start, *end;
	char	line[1024];

	fp = fopen(conf_file,"r");
	if (fp == ZGX_INVALID_FILE) {
		fprintf(stderr, "Can't open the file %s !\n",conf_file);
		return -1;
	}

	while (fgets(line,sizeof(line),fp) != NULL) {
		if ( (end = strchr(line,'=')) == NULL ) {
			fprintf(stderr,"config file [%s] is not valid!\n",conf_file);
			return -1;
		}
		
		start = line;
		if (!strncmp("user",start,((int)end-(int)start)/sizeof(char))) {
			if ( conf_set_value(end,line,conf.user) < 0) {
				fprintf(stderr,"Can't set [user] config item!\n");
				return -1;
			}
		}

		if (!strncmp("progress_num",start,((int)end-(int)start)/sizeof(char))) {
			end++;
			conf.process_num = atoi(end);
			fprintf(stdout,"startup %d process!\n",conf.process_num);
		}
		
		if (!strncmp("host",start,((int)end-(int)start)/sizeof(char))) {
			if ( conf_set_value(end,line,conf.host) < 0) {
				fprintf(stderr,"Can't set [host] config item!\n");
				return -1;
			}
		}
		
		if (!strncmp("port",start,((int)end-(int)start)/sizeof(char))) {
			end++;
			conf.port = atoi(end);
			fprintf(stdout,"use [%d] port!\n",conf.port);
		}

		if (!strncmp("pidfile",start,((int)end-(int)start)/sizeof(char))) {
			if ( conf_set_value(end,line,conf.pidfile) < 0) {
				fprintf(stderr,"Can't set [pidfile] config item!\n");
				return -1;
			}
		}
		
		if (!strncmp("log",start,((int)end-(int)start)/sizeof(char))) {
			if ( conf_set_value(end,line,conf.log) < 0) {
				fprintf(stderr,"Can't set [log path] config item!\n");
				return -1;
			}
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
			if ( conf_set_value(end,line,conf.lockfile) < 0) {
				fprintf(stderr,"Can't set [pidfile] config item!\n");
				return -1;
			}
		}
	}

	return ZGX_OK;	
}