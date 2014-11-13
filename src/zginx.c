#include "zginx.h"

int main(int argc, char *argv[])
{
	char	*conf_path;
	char	c;
	int		ret;

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
	
}
