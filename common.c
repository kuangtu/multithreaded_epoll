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

#include "common.h"

/*
 * All the below following set of functions are taken from the source code
 * of the book "Unix Network Programming"" by Richard Stevens et. al
 */
ssize_t writen(int fd, const void *vptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;		/* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n);
}

ssize_t	readn(int fd, void *vptr, size_t n)
{
	size_t	nleft;
	ssize_t	nread;
	char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nread = read(fd, ptr, nleft)) < 0) {
			if (errno == EINTR)
				nread = 0;		/* and call read() again */
			else
				return(-1);
		} else if (nread == 0)
			break;				/* EOF */

		nleft -= nread;
		ptr   += nread;
	}
	return(n - nleft);		/* return >= 0 */
}

int tcp_connect(const char *host, const char *serv)
{
	int	sockfd, error, n;
	struct addrinfo	hints, *res, *ressave;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0) {
		printf("tcp_connect error for %s, %s: %s",
				 host, serv, gai_strerror(n));
		return -1;
	}
	ressave = res;

	do {
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd < 0)
			continue;	/* Ignore this one */

		if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0)
			break;		/* Success */

		error = close(sockfd);
		if (error == -1) {
			printf("Close error");
			return -1;
		}
	} while ( (res = res->ai_next) != NULL);

	if (res == NULL) {	/* errno set from final connect() */
		printf("tcp_connect error for %s, %s", host, serv);
		return -1;
	}

	freeaddrinfo(ressave);

	return sockfd;
}

int tcp_listen(const char *host, const char *server, socklen_t *addrlen)
{
	char *ptr;
	int listenfd, backlog, error;
	const int optval = 1;
	struct addrinfo hints, *res, *ressave;

	memset(&hints, 0, sizeof (struct addrinfo));
	hints.ai_flags = AI_PASSIVE;			/* For wildcard IP address */
	hints.ai_family = AF_UNSPEC;			/* Allow IPv4 or IPv6 */	
	hints.ai_socktype = SOCK_STREAM;		/* Stream socket and not datagram socket */

	if ((error = getaddrinfo (host, server, &hints, &res)) != 0)
		err_sys("tcp_listen error for %s, %s: %s",
				host, server, gai_strerror(error));
	ressave = res;

	do {
		listenfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (listenfd < 0)
			continue;			/* We try the next one in case of error */

		error = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
		if (error < 0)
			err_sys("Error with setsockopt");

		if (bind(listenfd, res->ai_addr, res->ai_addrlen) == 0)
			break;				/* Success */

		error = close(listenfd);/* Bind error, close and try next one */
		if (error == -1)
			err_sys("Close error");

	} while ((res = res->ai_next) != NULL);

	if (res == NULL)			/* Error from final socket() or bind() */
		err_sys("tcp_listen error for %s, %s", host, server);

	if ((ptr = getenv("LISTENQ")) != NULL)
		backlog = atoi(ptr);
	else
		backlog = LISTENQ;

	if (listen(listenfd, backlog) < 0)
		err_sys("Listen error");

	if (addrlen)
		*addrlen = res->ai_addrlen;		/* Return size of protocol address */

	freeaddrinfo(ressave);

	return listenfd;
}

void signal_handler(int signal)
{
	_exit(0);	
}
