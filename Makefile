CC = gcc
LIBS = -lpthread
CFLAGS = -g -w

all:
	make dht

dht: workqueue.o error.o common.o dht.o
	${CC} ${CFLAGS} ${LIBS} workqueue.o error.o dht.o common.o -odht

clean:
	rm *.o
