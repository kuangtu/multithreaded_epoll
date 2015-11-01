/*
 * Copyright (C) 2015 Sanchayan Maity <maitysanchayan@gmail.com>
 *
 * Author: Sanchayan Maity <maitysanchayan@gmail.com>
 *						   <smaity1@hawk.iit.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef COMMON_H
#define COMMON_H

#include <arpa/inet.h>
#include <assert.h>
#include <bits/socket.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "workqueue.h"

/* #define DEBUG */

/* Connection backlog (# of backlogged connections to accept). */
#define CONNECTION_BACKLOG		1024	//SOMAXCONN

/*
  * Protocol is as follows:
  * Byte 0: Always 'C'
  * Byte 1: Always 'S'
  * Byte 2: Command PUT, GET or DEL
  * Byte 3: Error response CMD_OK or CMD_ERR
  * Byte 4: Key length: In this case file length (We expect file names will be less than 255 characters)
  * Byte 5 to ....: File name
  * Byte 5 + file name length: Peer id list
  */

/* As per the assignment specification */
#define HEADER_SIZE				4
#define KEY_LENGTH_POS			4
#define KEY_START_POS			5
#define MESSAGE_SIZE			1500
#define SERVER_HASH_TABLE_SIZE	100001
#define MAX_NO_OF_SERVERS		4
#define PEER_HASH_TABLE_SIZE	MAX_NO_OF_SERVERS
#define NO_OF_TEST_ITERATIONS	10000
#define LISTENQ					1024
#define	MAXLINE					4096
#define KEY_SIZE				255
#define READ_BUFFER_SIZE		8192
#define MAX_PEERS				16
#define PEER_ID_SIZE			64
#define MAXEVENTS				2 * MAX_NO_OF_SERVERS
#define NUMBER_OF_WQS			3
#define REPLICATE_DELAY			50000

/* Commands from peers */
#define CMD_PUT					0x01
#define CMD_GET					0x02
#define CMD_DEL					0x03
#define CMD_ERR					0x04
#define CMD_OK					0x05
#define CMD_PEER_REQ			0x06
#define CMD_TRANSFER_COMPLETE	0x07
#define CMD_FILE_REPLICATE		0x08
#define CMD_PEER_REQ_REPLICATE	0x09

/* Behaves similarly to fprintf(stderr, ...), but adds file, line, and function
   information. */
#define errorOut(...) {													\
		fprintf(stderr, "%s:%d: %s():\t", __FILE__, __LINE__, __FUNCTION__); \
		fprintf(stderr, __VA_ARGS__);									\
	}

int listenfd;
socklen_t addr_length;
pthread_t tid;

ssize_t writen(int fd, const void *vptr, size_t n);
ssize_t readn(int fd, void *vptr, size_t n);
int tcp_connect(const char *host, const char *serv);
int tcp_listen(const char *host, const char *server, socklen_t *addrlen);
bool make_socket_nonblocking(int fd);
void *thread_main(void *arg);
int create_thread(int thread_index_number);
void signal_handler(int signal);
void err_dump(const char *, ...);
void err_msg(const char *, ...);
void err_quit(const char *, ...);
void err_ret(const char *, ...);
void err_sys(const char *, ...);

#endif  /* #ifndef COMMON_H */
