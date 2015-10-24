CC = gcc
LIBS = -lpthread
CFLAGS = -g -w

all:
	make dht
	make server

dht: error.o common.o dht.o
	${CC} ${CFLAGS} ${LIBS} error.o dht.o common.o -odht

server: workqueue.o server.o
	${CC} ${CFLAGS} ${LIBS} -levent workqueue.o server.o -oserver

clean:
	rm *.o
