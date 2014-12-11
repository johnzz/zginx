#include <string.h>
       #include <sys/types.h>
       #include <sys/stat.h>
       #include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <stdio.h>

#define dd(...)  fprintf(stderr, "array_var *** ");\
                fprintf(stderr, __VA_ARGS__);\
                fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__);



#define CRLF  "\r\n"

void main () {
    char file1[] = "1";
    char file2[] = "2";
    ssize_t     size;
    int     fd1,fd2;
    off_t   off;
    char        *buff;
    int         ret = 0;

    //buff = malloc(1000);

    char *str = "654";

    //char    *start = buff;
    //ret = sprintf(buff,"%s %d %s%s","test",10,"ss",CRLF);
    //dd("ret %d, strlen(buff) %d",ret, strlen(buff));


    buff += ret;

    //sprintf(buff,"%s %d %s%s","2test",10,"ss",CRLF);
    //if (start[12] == '2') {
    //    dd("buff[12]%chhh",buff[12]);
    //}

    int i,tmp=0,j=0;
    int mi = 0;
    for (i = 0; i < strlen(str); i++) {
        tmp = 10 *tmp + str[i] - '0';
    }

    printf("tmp %d strlen(str) %d ret %d\n",tmp,strlen(str),ret);

    //dd("buff %s",start);
    off = 1;
    fd1 = open(file1,O_RDWR|O_CREAT|O_APPEND,S_IRWXU|S_IRGRP|S_IROTH);
    fd2 = open(file2,O_RDWR|O_CREAT|O_APPEND,S_IRWXU|S_IRGRP|S_IROTH);

    size = sendfile(fd1,fd2,&off,10);

}
