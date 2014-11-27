#include "zginx.h"

#define  zgx_open(name,mode,create,access) open((const char *)name,mode|create,access)
#define  MAX_TEXT 4096

int zgx_log_init()
{
	int 	lfd;
	int		name_len;
	zgx_open_file_t		*log = (zgx_open_file_t *)malloc(sizeof(zgx_open_file_t));
	
	cycle.file	= log;
	if ( conf.log ) {
		lfd = zgx_open(conf.log,O_WRONLY|O_APPEND,O_CREAT,0644);
		if (lfd < 0) {
			fprintf(stderr,"zgx open [%s] error!",conf.log);
			return -1;
		}
		
		cycle.file->fd = lfd;
		
		log->name = conf.log;
		
	}
	return 0;
}

void zgx_localtime(time_t sec, struct tm *tm)
{
	struct tm	*t;
	t = localtime(&sec);
	tm = t;

	tm->tm_mon++;
    tm->tm_year += 1900;
}

static inline ssize_t	zgx_write(const char *buff,size_t n)
{
	return write(cycle.file->fd,buff,n);
}

void zgx_log(int log_level, const char *fmt, ...)
{
	va_list		args;
	char		slevel[20];
	char		text[MAX_TEXT];
	size_t		len,ret_len;
	ssize_t		n;
	char		prefix[50];
	struct tm	tm;
	time_t		sec;
	struct timeval tv;

	len = sizeof("1970/01/01 01:01:01 [DEBUG] ");
	if (log_level >= conf.llevel) {
		va_start(args, fmt);
		switch (log_level) {
			case 0:
				strcpy(slevel,"DEBUG");
				break;
			case 1:
				strcpy(slevel,"ERROR");
				break;
			case 2:
				strcpy(slevel,"CRIT");
				break;
			default:
				break;
		}

		gettimeofday(&tv,NULL);
		sec = tv.tv_sec;
		zgx_localtime(sec,&tm);
		(void)snprintf(text, len, "%4d/%02d/%02d %02d:%02d:%02d [%s] ",
				tm.tm_year,tm.tm_mon,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec,
				slevel);
		ret_len = vsnprintf(text+len,sizeof(text)-len,fmt,args);
		va_end(args);
		
		text[ret_len+len+1] = '\n';
		n = zgx_write(text,ret_len+len+1);

	}
}

