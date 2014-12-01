BIN = ./bin
CC = gcc
CFLAGS += -DUSE_SSL -DTCP_NOPUSH -I.
DEPS = zginx.h zgx_epoll.h
TARGET = zginx

OBJ = log.o zginx.o parse_conf.o zgx_epoll.o zgx_mutex.o zgx_util.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

# prepare the bin dir
.PHONY : prepare
prepare :
		-mkdir $(BIN)
.PHONY : clean
clean  :
		-rm -rf $(BIN)
