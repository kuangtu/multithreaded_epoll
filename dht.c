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

/* Table entry */
struct node_t {
	/* Key */
	char *key;
	/* Value of the key */
	char *value;
	/* Next entry in chain */
    struct node_t *next;
};

static struct node_t *hashtable[SERVER_HASH_TABLE_SIZE];

/*
 * We use a read write lock to protect against concurrent
 * write to the hash table. It is ok to have concurrent
 * readers. We do not use a mutex as that will reduce
 * reader concurrency to a single thread at a time.
 */
pthread_rwlock_t ht_lock;

/*
 * Id of server. We use this to pick up appropriate
 * IP/port parameters from the file.
 */
static int server_id;

struct server_p {
	/* IP to which server will bind to */
	char *serverip;
	/* Port on which server will listen */
	char *serverport;
};

/*
 * We use this to store server parameters of the eight
 * servers information read from file
 */
static struct server_p servers[MAX_NO_OF_SERVERS];

/*
 * Struct to carry around server connection specific data
 */
struct server_conn {
	int sockfd;
	bool server_connected;
};
static struct server_conn sconn[MAX_NO_OF_SERVERS];

/*
 * Only one member in structure but we still keep it for easier
 * extension in future.
 */
typedef struct job_d {
	int sockfd;
} job_data;

static int efd;
static struct epoll_event event;
static struct epoll_event *events;
static workqueue_t workqueue;

static volatile bool perf_test_on = false;
unsigned char dir_to_be_shared[KEY_SIZE] = {0};

/*
 * https://en.wikipedia.org/wiki/Jenkins_hash_function
 */
unsigned int jenkins_one_at_a_time_hash(const char *key, size_t len) {
	unsigned int hash, i;

	for(hash = i = 0; i < len; ++i) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash;
}

/*
 * Hash function. Use the above and restrict result as per the table
 * size. We use a non power of 2 to get good hashing. Refer CLRS.
 */
unsigned int hash_server(const char *key, const int key_length) {
	return jenkins_one_at_a_time_hash(key, key_length) % SERVER_HASH_TABLE_SIZE;
}

unsigned int hash_peer(const char *key, const int key_length) {
	return jenkins_one_at_a_time_hash(key, key_length) % PEER_HASH_TABLE_SIZE;
}

/*
 * Get the node data pointer as per the key
 */
struct node_t *hash_table_get(const char *key, const int key_length) {
	struct node_t *np;
	unsigned int hashval;

	hashval = hash_server(key, key_length);

	pthread_rwlock_rdlock(&ht_lock);
	for(np = hashtable[hashval]; np != NULL; np = np->next) {
		if (strncmp(key, np->key, key_length) == 0) {
			pthread_rwlock_unlock(&ht_lock);
			/* We found the key */
			return np;
		}
	}

	pthread_rwlock_unlock(&ht_lock);
	return NULL;
}

/*
 * We determine if the key being added exists. If it does, the
 * new value supersedes the old one, else we create a new entry
 * and add the key/value pair. Return NULL on any error.
 */
struct node_t *hash_table_put(const char *key, const int key_length,
							  const char *value, const int value_length) {
	unsigned int hashval;
	struct node_t *np;

	pthread_rwlock_wrlock(&ht_lock);
	if ((np = hash_table_get(key, key_length)) == NULL) { /* Not found */
		np = (struct node_t *)malloc(sizeof(*np));
		if (np == NULL || (np->key = strndup(key, key_length)) == NULL)
			goto error;

		/* Find the bucket position and add at 'head' location */
		hashval = hash_server(key, key_length);
		np->next = hashtable[hashval];
		hashtable[hashval] = np;
	} else /* Already there */
		free((void *) np->value);	/* Free previous value */
	if ((np->value = strndup(value, value_length)) == NULL)
		goto error;

	return np;

error:
	pthread_rwlock_unlock(&ht_lock);
	return NULL;
}

/*
 * Return 0 on success and 1 on failure
 */
unsigned int hash_table_delete(const char *key, const int key_length) {
	struct node_t *np1, *np2;
	unsigned int hashval;

	hashval = hash_server(key, key_length);

	pthread_rwlock_wrlock(&ht_lock);
	for (np1 = hashtable[hashval], np2 = NULL; np1 != NULL; np2 = np1, np1 = np1->next)
		if (strncmp(key, np1->key, key_length) == 0) {
			/* Found a match */
			free(np1->key);
			free(np1->value);
			if (np2 == NULL)
				/* At the beginning? */
				hashtable[hashval] = np1->next;
			else
				/* In the middle or at the end? */
				np2->next = np1->next;
		free(np1);

		pthread_rwlock_unlock(&ht_lock);
		return 0;
	}

	pthread_rwlock_unlock(&ht_lock);
	return 1;
}

/*
 * Taken from http://stackoverflow.com/questions/9210528/split-string-with-delimiters-in-c
 * We modify it to use strtok_r the MT safe variant. strtok is not MT safe.
 */
unsigned char** str_split(unsigned char* a_str, const char a_delim) {
	unsigned char** result    = 0;
	size_t count     = 0;
	unsigned char* tmp        = a_str;
	unsigned char* last_comma = 0;
	unsigned char* save		 = 0;
	unsigned char delim[2];
	delim[0] = a_delim;
	delim[1] = 0;

	/* Count how many elements will be extracted. */
	while (*tmp) {
		if (a_delim == *tmp) {
			count++;
			last_comma = tmp;
		}
		tmp++;
	}

	/* Add space for trailing token. */
	count += last_comma < (a_str + strlen(a_str) - 1);

	/* Add space for terminating null string so caller
	knows where the list of returned strings ends. */
	count++;

	result = malloc(sizeof(char*) * count);

	if (result) {
		size_t idx  = 0;
		//char* token = strtok(a_str, delim);
		char* token = strtok_r(a_str, delim, &save);

		while (token) {
			*(result + idx++) = strdup(token);
			//token = strtok(0, delim);
			token = strtok_r(0, delim, &save);
		}
		assert(idx == count - 1);
		*(result + idx) = 0;
	}

	return result;
}

/*
 * Handle the request from a peer
 */
static void process_peer_request(struct job *job) {
	job_data *job_wq_data = (job_data *)job->user_data;
	int connfd = job_wq_data->sockfd;
	int fd, ret;
	int status;
	int noBytesRead;
	int noBytesWritten;
	int value_start_pos;
	unsigned int file_bytes_counter;
	char data[MESSAGE_SIZE];
	char filename[KEY_SIZE];
	char readbuffer[READ_BUFFER_SIZE];
	struct node_t *np;
	struct stat statbuffer;
	struct epoll_event event;

	memset(data, 0, MESSAGE_SIZE);
	noBytesRead = readn(connfd, data, MESSAGE_SIZE);
	#ifdef DEBUG
	printf("Bytes read from peer: %d\n", noBytesRead);
	#endif

	if (data[0] == 'C' && data[1] == 'S') {
		value_start_pos = KEY_START_POS + data[KEY_LENGTH_POS];
		switch (data[2]) {
		case CMD_PUT:
			np = hash_table_get(&data[KEY_START_POS], data[KEY_LENGTH_POS]);
			if (np == NULL) {
				if ((hash_table_put(&data[KEY_START_POS], data[KEY_LENGTH_POS],
						&data[value_start_pos + 1], data[value_start_pos])) == NULL)
					data[3] = CMD_ERR;
				else
					data[3] = CMD_OK;
			} else {
					/*
					* File is present with another peer. We concatenate the previous
					* and new peer id before registering in the hash table.
					*/
				char *value = NULL;
					/*
					* 3 is because of one space delimiter in between and two null terminators
					* for each of two strings.
					*/
				value = (char *)malloc(strlen(np->value) + data[value_start_pos] + 3);
				memset(value, 0, strlen(np->value) + data[value_start_pos] + 3);
				if (value != NULL) {
					strncat(value, np->value, strlen(np->value));
					strncat(value, " ", 1);
					strncat(value, &data[value_start_pos + 1], data[value_start_pos]);
					if (hash_table_put(&data[KEY_START_POS], data[KEY_LENGTH_POS],
							value, strlen(value)) == NULL)
						data[3] = CMD_ERR;
					else
						data[3] = CMD_OK;
					free(value);
				} else {
					data[3] = CMD_ERR;
				}
			}
			noBytesWritten = writen(connfd, data, MESSAGE_SIZE);
			break;
		case CMD_GET:
			np = hash_table_get(&data[KEY_START_POS], data[KEY_LENGTH_POS]);
			if (np == NULL) {
				data[3] = CMD_ERR;
			} else {
				data[3] = CMD_OK;
				strncpy(&data[value_start_pos + 1], np->value, strlen(np->value));
			}
			noBytesWritten = writen(connfd, data, MESSAGE_SIZE);
			break;
		case CMD_DEL:
			if (hash_table_delete(&data[KEY_START_POS], data[KEY_LENGTH_POS]))
				data[3] = CMD_ERR;
			else
				data[3] = CMD_OK;
			noBytesWritten = writen(connfd, data, MESSAGE_SIZE);
			break;
		case CMD_PEER_REQ:
		case CMD_PEER_REQ_REPLICATE:
			memset(filename, 0, KEY_SIZE);
			strncpy(filename, dir_to_be_shared, strlen(dir_to_be_shared));
			if (data[2] == CMD_PEER_REQ_REPLICATE) {
				printf("Serving replica request\n");
				strncat(filename, "replica/", 8);
			}
			strncat(filename, &data[KEY_START_POS], data[KEY_LENGTH_POS]);
			filename[strlen(filename) + 1] = '\0';
			#ifdef DEBUG
			printf("File %s request received from peer\n", filename);
			#endif

			memset(readbuffer, 0, READ_BUFFER_SIZE);

			status = stat(filename, &statbuffer);
			if (status != 0) {
				perror("Could not get file info\n");
				goto break1_out;
			}

			file_bytes_counter = 0;
			fd = open(filename, O_RDONLY);
			if (fd == -1) {
				perror("Server: Error opening file");
				goto break1_out;
			} else {
				noBytesRead = noBytesWritten = 0;
				while ((noBytesRead = read(fd, readbuffer, READ_BUFFER_SIZE)) > 0) {
					file_bytes_counter += noBytesRead;
					if (file_bytes_counter == statbuffer.st_size) {
						readbuffer[noBytesRead] = 'E';
						readbuffer[noBytesRead + 1] = 'O';
						readbuffer[noBytesRead + 2] = 'F';
						noBytesWritten = write(connfd, readbuffer, noBytesRead + 3);
						#ifdef DEBUG
						printf("Server: Number of bytes read: %d written: %d\n", noBytesRead + 3, noBytesWritten);
						#endif
						if (noBytesRead + 3 != noBytesWritten)
							perror("Server: Could not write whole buffer");
						goto exit_while_loop;
					}
					noBytesWritten = write(connfd, readbuffer, noBytesRead);
					#ifdef DEBUG
					printf("Server: Number of bytes read: %d written: %d\n", noBytesRead, noBytesWritten);
					#endif
					if (noBytesRead != noBytesWritten)
						perror("Server: Could not write whole buffer");
					memset(readbuffer, 0, READ_BUFFER_SIZE);
				}
			}
exit_while_loop:
			if (noBytesRead == -1)
				perror("Server: Error on reading");
			if (close(fd) == -1)
				perror("Server: Error on closing file");

			break;
break1_out:
			readbuffer[3] = CMD_ERR;
			noBytesWritten = writen(connfd, readbuffer, HEADER_SIZE);
			break;
		case CMD_FILE_REPLICATE:
			memset(filename, 0, KEY_SIZE);
			strncpy(filename, dir_to_be_shared, strlen(dir_to_be_shared));
			strncat(filename, "replica/", 8);
			strncat(filename, &data[KEY_START_POS], data[KEY_LENGTH_POS]);
			filename[strlen(filename) + 1] = '\0';
			#ifdef DEBUG
			printf("File %s request received from peer\n", filename);
			#endif

			memset(readbuffer, 0, READ_BUFFER_SIZE);
			fd = open(filename, O_WRONLY | O_CREAT, 0666);
			if (fd == -1) {
				perror("Server: Error opening file");
				goto break2_out;
			} else {
				noBytesRead = noBytesWritten = 0;
				while ((noBytesRead = read(connfd, readbuffer, READ_BUFFER_SIZE)) > 0) {
					if (readbuffer[0] == 'C' && readbuffer[1] == 'S' &&
						readbuffer[2] == CMD_FILE_REPLICATE && readbuffer[3] == CMD_ERR) {
						printf("Server: Error occured on file server\n");
						goto break_read_loop;
					} else if (readbuffer[noBytesRead - 1] == 'F' &&
							readbuffer[noBytesRead - 2] == 'O' &&
							readbuffer[noBytesRead - 3] == 'E') {
						noBytesWritten = write(fd, readbuffer, noBytesRead - 3);
						if (!perf_test_on)
							printf("File transfer complete\n");
						goto break_read_loop;
					}
					noBytesWritten = write(fd, readbuffer, noBytesRead);
					#ifdef DEBUG
					printf("Server: File: %s Number of bytes read: %d written: %d\n", filename, noBytesRead, noBytesWritten);
					#endif
					if (noBytesRead != noBytesWritten)
						perror("Server: Could not write whole buffer");
					memset(readbuffer, 0, READ_BUFFER_SIZE);
				}
			break_read_loop:
				if (noBytesRead == -1)
					perror("Server: Error on reading");

				if (close(fd) == -1)
					perror("Server: Error on closing file");
			}
			break;
			break2_out:
			readbuffer[3] = CMD_ERR;
			noBytesWritten = writen(connfd, readbuffer, HEADER_SIZE);
			break;
		default:
			break;
		}
		#ifdef DEBUG
		printf("Bytes written by server: %d\n", noBytesWritten);
		#endif
	}

	event.data.fd = connfd;
	event.events = EPOLLIN;
	ret = epoll_ctl(efd, EPOLL_CTL_ADD, connfd, &event);
	if (ret == -1)
		perror("Error with epoll_ctl ADD");
	free(job_wq_data);
	free(job);
}

void *server_thread(void *arg) {
	int listenfd = *((int *)arg);
	socklen_t client_length;
	struct sockaddr *client_address;
	int infd, ret;
	int n, i, j;
	job_t *job;
	job_data *job_wq_data;

	client_address = malloc(addr_length);
	if (!client_address)
		err_sys("Error in allocating memory for client address\n");

	/*
	 * Using https://banu.com/blog/2/how-to-use-epoll-a-complete-example-in-c/
	 * as an example with recommendations from http://csh.rit.edu/~rossdylan/presentations/EpollMT/#1.
	 */
	efd = epoll_create1(0);
	if (efd == -1)
		err_sys("Error with epoll_create1");

	event.data.fd = listenfd;
	event.events = EPOLLIN;
	ret = epoll_ctl(efd, EPOLL_CTL_ADD, listenfd, &event);
	if (ret == -1)
		err_sys("Error with epoll_ctl");

	/* Buffer where events are returned */
	events = calloc(MAXEVENTS, sizeof(event));

	/* The event loop */
	for ( ; ; )	{

		client_length = addr_length;

		n = epoll_wait(efd, events, MAXEVENTS, -1);
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) ||
				(events[i].events & EPOLLHUP) ||
				(!(events[i].events & EPOLLIN))) {
				/*
				 * An error has occured on this fd or the socket is not ready
				 * for reading. Why were we notified then?
				 */
				printf("epoll error\n");
				close(events[i].data.fd);
				for (j = 0; j < MAX_NO_OF_SERVERS; j++)
					if (events[i].data.fd == sconn[i].sockfd) {
						sconn[i].sockfd = -1;
						sconn[i].server_connected = false;
					}
				continue;
			} else if (listenfd == events[i].data.fd) {
				/*
				 * We have a notification on the listening socket, which means
				 * one or more incoming connections.
				 */
				while (1) {
					infd = accept(listenfd, client_address, &client_length);
					if (infd == -1) {
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
							/* We processed all incoming connections */
							break;
						}
						else {
							perror("Error with accept");
							break;
						}
					} else
						printf("Connection accepted\n");

					/*
					 * Make the incoming socket non blocking and add it to
					 * the lists of fds to monitor. In the future when the
					 * read/write calls are made non blocking this will be
					 * required.
					 */
					/*
					if (!make_socket_nonblocking(infd)) {
						perror("Could not make socket nonblocking");
						abort();
					}
					*/

					event.data.fd = infd;
					event.events = EPOLLIN | EPOLLERR | EPOLLHUP;
					ret = epoll_ctl(efd, EPOLL_CTL_ADD, infd, &event);
					if (ret == -1) {
						perror("Error with epoll_ctl");
						abort();
					}
				}
				continue;
			} else {

				if ((job = malloc(sizeof(* job))) == NULL) {
					perror("Failed to allocate memory for job object");
					continue;
				}

				if ((job_wq_data = malloc(sizeof(* job_wq_data))) == NULL) {
					perror("Failed to allocate memory for wq data");
					free(job);
					continue;
				}

				job_wq_data->sockfd = events[i].data.fd;
				job->job_function = process_peer_request;
				job->user_data = job_wq_data;

				/*
				 * In a multi threaded environment epoll is not suppose to monitor
				 * descriptors on which other threads are working. Ideally use of
				 * the EPOLLONESHOT flag should have disabled it for the next epoll_wait
				 * till the worker thread reenables it, however for some reason it seems
				 * not to work. So manually delete the fd from being monitored by epoll
				 * and add it back in the process_peer_request function after it finishes
				 * working with the said descriptor. In future use EPOLLONESHOT after
				 * investigation and finding the fix.
				 */
				ret = epoll_ctl(efd, EPOLL_CTL_DEL, events[i].data.fd, &events[i]);
				if (ret == -1)
					perror("Error with epoll_ctl DEL");

				/* Add the job for processing by workqueue */
				workqueue_add_job(&workqueue, job);
			}
		}
	}
}

void put_at_server(const unsigned char *key, const int key_length,
				   const unsigned char *value, const int value_length) {
	unsigned char data[MESSAGE_SIZE];
	int lserver_id;
	int i, sd;
	char sport[32] = {0};
	int noBytesRead;
	int noBytesWritten;
	bool exit;

	memset(data, 0, MESSAGE_SIZE);
	data[0] = 'C';
	data[1] = 'S';
	data[2] = CMD_PUT;
	data[3] = 0;

	data[KEY_LENGTH_POS] = key_length;
	strncpy(&data[KEY_START_POS], key, key_length);
	data[KEY_START_POS + key_length] = value_length;
	strncpy(&data[KEY_START_POS + key_length + 1], value, value_length);

	lserver_id = hash_peer(&data[KEY_START_POS], key_length);
	#ifdef DEBUG
	if (!perf_test_on)
		printf("PUT Server Id: %d\n", lserver_id);
	#endif

	/*
	 * We achieve replication by also registering all files with the next
	 * server which the hash returned. So if the above hash returns 2, the
	 * values will be replicated at 3 as well. Logic from class lecture.
	 */
	for (i = lserver_id; i <= (lserver_id + 1); i++) {
		if (i == MAX_NO_OF_SERVERS) {
			i = (lserver_id + 1) % MAX_NO_OF_SERVERS;
			exit = true;
		}

		if (!sconn[i].server_connected) {
			sprintf(sport, "%d", atoi(servers[i].serverport));
			sd = tcp_connect(servers[i].serverip, sport);
			sconn[i].sockfd = sd;
			sconn[i].server_connected = true;
		}

		noBytesWritten = writen(sconn[i].sockfd, data, MESSAGE_SIZE);
		#ifdef DEBUG
		printf("Bytes written by peer: %d\n", noBytesWritten);
		#endif
		memset(data, 0, MESSAGE_SIZE);
		noBytesRead = readn(sconn[i].sockfd, data, MESSAGE_SIZE);
		if (noBytesRead < 0) {
			sconn[i].sockfd = -1;
			sconn[i].server_connected = false;
			return;
		}
		#ifdef DEBUG
		printf("Bytes read from server: %d\n", noBytesRead);
		#endif
		if (data[0] == 'C' && data[1] == 'S') {
			if (data[2] == CMD_PUT) {
				if (data[3] == CMD_OK) {
					if (!perf_test_on)
						printf("\nPut operation successful\n");
				} else {
					if (!perf_test_on)
						printf("\nPut operation failed\n");
				}
			}
		}

		if (exit)
			return;
	}
}

void register_with_server(void) {
	struct dirent dirent, *result;
	unsigned char peerid[PEER_ID_SIZE];
	DIR *d;

	memset(peerid, 0, PEER_ID_SIZE);
	strncat(peerid, servers[server_id].serverip, PEER_ID_SIZE);
	strncat(peerid, " ", PEER_ID_SIZE - strlen(peerid));
	strncat(peerid, servers[server_id].serverport, PEER_ID_SIZE - strlen(peerid));

	d = opendir(dir_to_be_shared);
	if (d) {
		/* Use the MT safe reentrant version of readdir */
		while (readdir_r(d, &dirent, &result) == 0) {
			if (result == NULL)
				break;

			/* We check if it is a regular file. See 'man readdir_r' */
			if (result->d_type == DT_REG)
				put_at_server(result->d_name, strlen(result->d_name), peerid, strlen(peerid));
		}
		closedir(d);
	} else {
		perror("Could not open directory");
	}
}

void replicate_at_server(const unsigned char *key, const int key_length) {
	unsigned char data[MESSAGE_SIZE];
	int lserver_id;
	int sd;
	char sport[32] = {0};
	int noBytesRead;
	int noBytesWritten;
	int fd, status;
	unsigned int file_bytes_counter;
	struct stat statbuffer;
	char readbuffer[READ_BUFFER_SIZE];
	char filename[KEY_SIZE];

	memset(filename, 0, KEY_SIZE);
	strncat(filename, dir_to_be_shared, strlen(dir_to_be_shared));
	strncat(filename, key, key_length);
	status = stat(filename, &statbuffer);
	if (status != 0) {
		perror("Could not get file info\n");
		return;
	}

	memset(data, 0, MESSAGE_SIZE);
	data[0] = 'C';
	data[1] = 'S';
	data[2] = CMD_FILE_REPLICATE;
	data[3] = 0;

	data[KEY_LENGTH_POS] = key_length;
	strncpy(&data[KEY_START_POS], key, key_length);

	lserver_id = server_id + 1;
	if (lserver_id == MAX_NO_OF_SERVERS)
		lserver_id = lserver_id % MAX_NO_OF_SERVERS;
	#ifdef DEBUG
	if (!perf_test_on)
		printf("REPLICATE Server Id: %d\n", lserver_id);
	#endif

	if (!sconn[lserver_id].server_connected) {
		sprintf(sport, "%d", atoi(servers[lserver_id].serverport));
		sd = tcp_connect(servers[lserver_id].serverip, sport);
		sconn[lserver_id].sockfd = sd;
		sconn[lserver_id].server_connected = true;
	}

	noBytesWritten = writen(sconn[lserver_id].sockfd, data, MESSAGE_SIZE);
	#ifdef DEBUG
	printf("Bytes written by peer: %d\n", noBytesWritten);
	#endif
	memset(data, 0, MESSAGE_SIZE);

	file_bytes_counter = 0;
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		perror("Peer: Error opening file");
		goto break_out;
	} else {
		noBytesRead = noBytesWritten = 0;
		while ((noBytesRead = read(fd, readbuffer, READ_BUFFER_SIZE)) > 0) {
			file_bytes_counter += noBytesRead;
			if (file_bytes_counter == statbuffer.st_size) {
				readbuffer[noBytesRead] = 'E';
				readbuffer[noBytesRead + 1] = 'O';
				readbuffer[noBytesRead + 2] = 'F';
				noBytesWritten = write(sconn[lserver_id].sockfd, readbuffer, noBytesRead + 3);
				#ifdef DEBUG
				printf("Peer: Number of bytes read: %d written: %d\n", noBytesRead + 3, noBytesWritten);
				#endif
				if (noBytesRead + 3 != noBytesWritten)
					perror("Peer: Could not write whole buffer");
				goto exit_while_loop;
			}
			noBytesWritten = write(sconn[lserver_id].sockfd, readbuffer, noBytesRead);
			#ifdef DEBUG
			printf("Peer: Number of bytes read: %d written: %d\n", noBytesRead, noBytesWritten);
			#endif
			if (noBytesRead != noBytesWritten)
				perror("Peer: Could not write whole buffer");
			memset(readbuffer, 0, READ_BUFFER_SIZE);
		}
	}
exit_while_loop:
	if (noBytesRead == -1)
		perror("Server: Error on reading");
	if (close(fd) == -1)
		perror("Server: Error on closing file");
	return;
break_out:
	readbuffer[3] = CMD_ERR;
	noBytesWritten = writen(sconn[lserver_id].sockfd, readbuffer, HEADER_SIZE);
}

void replicate_with_server(void) {
	struct dirent dirent, *result;
	DIR *d;

	d = opendir(dir_to_be_shared);
	if (d) {
		while (readdir_r(d, &dirent, &result) == 0) {
			if (result == NULL)
				break;

			if (result->d_type == DT_REG) {
				/*
				 * This delay is used as transfer on local system is too
				 * fast and the transfer gets cascaded and written as a
				 * single file on the other end.
				 */
				usleep(REPLICATE_DELAY);
				replicate_at_server(result->d_name, strlen(result->d_name));
			}
		}
		closedir(d);
	} else {
		perror("Could not open directory");
	}
}

void process_data_from_get(unsigned char *peerid,
						   const unsigned char *key, const int key_length) {
	int i, j, k, l;
	char *readbuffer;
	unsigned char **tokens;
	unsigned char peerip[MAX_PEERS][MAX_PEERS];
	unsigned char peerport[MAX_PEERS][MAX_PEERS];
	unsigned char ipvalues[4] = {0};
	unsigned char data[MESSAGE_SIZE];
	unsigned char filename[KEY_SIZE];
	char sport[32] = {0};
	int noBytesRead, noBytesWritten;
	int cur_server_index;
	int peerinput;
	int peerfd;
	int fd;
	bool retrial = false;

	memset(peerip, 0, sizeof(peerip));
	memset(peerport, 0, sizeof(peerport));
	tokens = str_split(peerid, ' ');
	if (tokens) {
		/* We only read in 16 peers max even if we got more */
		for (i = 0, j = 0, k = 0; *(tokens + i) && (i < MAX_PEERS); i++) {
			/*
			 * First will be IP and then port, so IP is always even token and port odd token
			 * For example, the buffer will have 127.0.0.1 98 127.0.0.1 100
			 */
			if ((i % 2) == 0) {
				strncpy(peerip[j], *(tokens + i), strlen(*(tokens + i)));
				peerip[j][strlen(*(tokens+i)) + 1] = '\0';
				j++;
			} else {
				strncpy(peerport[k], *(tokens + i), strlen(*(tokens + i)));
				peerport[k][strlen(*(tokens+i)) + 1] = '\0';
				k++;
			}
		}
		free(tokens);
	}

	/*
	 * If perf tests are running, we just always select the first peer
	 * and just bypass this logic inside "if".
	 */
	if (!perf_test_on) {
		/* Peer select logic */
		loopforuserinput:
		i = 0;
		printf("Available Peers: %d\n", j);
		while (i < j) {
			printf("Peer %d: %s %s\n", i, peerip[i], peerport[i]);
			i++;
		}

		printf("Enter the number of peer you want to connect to: \t");
		scanf("%d", &peerinput);
		if ((peerinput < 0) || (peerinput > j)) {
			printf("Wrong input. Enter again\n\n");
			goto loopforuserinput;
		}
	} else
		peerinput = 0;

#ifdef DEBUG
	printf("Connecting to peer at %s on port %s\n", peerip[peerinput], peerport[peerinput]);
#endif

	peerfd = -1;
	for (l = 0; l < MAX_NO_OF_SERVERS; l++) {
		if ((strcmp(peerip[peerinput], servers[l].serverip) == 0) &&
			(strcmp(peerport[peerinput], servers[l].serverport) == 0))
			if (sconn[l].server_connected) {
				cur_server_index = l;
				peerfd = sconn[l].sockfd;
				#ifdef DEBUG
				printf("Already connected to peer\n");
				#endif
				break;
			}
	}

	if (peerfd == -1) {
		sprintf(sport, "%d", atoi(peerport[peerinput]));
		peerfd = tcp_connect(peerip[peerinput], sport);
	}

retry_connection_to_replica:
	memset(data, 0, MESSAGE_SIZE);
	data[0] = 'C';
	data[1] = 'S';
	if (retrial)
		data[2] = CMD_PEER_REQ_REPLICATE;
	else
		data[2] = CMD_PEER_REQ;
	data[3] = 0;
	data[4] = key_length;
	strncat(&data[KEY_START_POS], key, key_length);

	writen(peerfd, data, MESSAGE_SIZE);

	memset(filename, 0, KEY_SIZE);
	strncat(filename, dir_to_be_shared, strlen(dir_to_be_shared));
	strncat(filename, key, key_length);
	fd = open(filename, O_WRONLY | O_CREAT, 0666);
	if (fd == -1) {
		perror("Error opening file");
		return;
	}

	readbuffer = (char *)malloc(READ_BUFFER_SIZE);
	if (!readbuffer) {
		perror("Could not allocate memory for buffer");
		close(fd);
		return;
	}
	memset(readbuffer, 0, READ_BUFFER_SIZE);

	/*
	 * Receive the file from the peer and write it to the file
	 */
	while ((noBytesRead = read(peerfd, readbuffer, READ_BUFFER_SIZE)) > 0) {
		if (readbuffer[0] == 'C' && readbuffer[1] == 'S' &&
			readbuffer[2] == CMD_PEER_REQ && readbuffer[3] == CMD_ERR) {
			printf("Peer: Error occured on file server\n");
			goto break_read_loop;
		} else if (readbuffer[noBytesRead - 1] == 'F' &&
				   readbuffer[noBytesRead - 2] == 'O' &&
				   readbuffer[noBytesRead - 3] == 'E') {
			noBytesWritten = write(fd, readbuffer, noBytesRead - 3);
			if (!perf_test_on)
				printf("File transfer complete\n");
			goto break_read_loop;
		}
		noBytesWritten = write(fd, readbuffer, noBytesRead);
		#ifdef DEBUG
		printf("Peer: File: %s Number of bytes read: %d written: %d\n", filename, noBytesRead, noBytesWritten);
		#endif
		if (noBytesRead != noBytesWritten)
			perror("Peer: Could not write whole buffer");
		memset(readbuffer, 0, READ_BUFFER_SIZE);
	}

	if (noBytesRead == 0) {
		/* This denotes that the connection was closed somehow */
		printf("Peer selected is down\n");
		peerfd = -1;
		/* Since we are gonna jump back undo whatever needs to be undone */
		close(fd);
		remove(filename);
		free(readbuffer);
		close(sconn[cur_server_index].sockfd);
		sconn[cur_server_index].sockfd = -1;
		sconn[cur_server_index].server_connected = false;
		cur_server_index += 1;
		if (cur_server_index == MAX_NO_OF_SERVERS)
			cur_server_index = cur_server_index % MAX_NO_OF_SERVERS;
		if (sconn[cur_server_index].server_connected) {
			printf("Using existing connection for replica\n");
			peerfd = sconn[cur_server_index].sockfd;
		}
		else {
			printf("Establishing new connection\n");
			memset(sport, 0, 32);
			sprintf(sport, "%d", atoi(servers[cur_server_index].serverport));
			peerfd = tcp_connect(servers[cur_server_index].serverip, sport);
		}
		retrial = true;
		printf("Connecting to replica on node %d\n", cur_server_index);
		goto retry_connection_to_replica;
	}

break_read_loop:
	if (noBytesRead == -1)
		perror("Peer: Error on reading");

	if (close(fd) == -1)
		perror("Peer: Error on closing file");

	free(readbuffer);
	readbuffer = NULL;
}

void get_from_server(const unsigned char *key, const int key_length) {
	unsigned char data[MESSAGE_SIZE];
	char sport[32] = {0};
	int sd;
	int lserver_id;
	int peerid_start_pos;
	int noBytesRead;
	int noBytesWritten;
	bool retried = false;

	memset(data, 0, MESSAGE_SIZE);
	data[0] = 'C';
	data[1] = 'S';
	data[2] = CMD_GET;
	data[3] = 0;

	data[4] = key_length;
	strncpy(&data[KEY_START_POS], key, key_length);

	lserver_id = hash_peer(&data[KEY_START_POS], key_length);
	#ifdef DEBUG
	if (!perf_test_on)
		printf("GET Server Id: %d\n", lserver_id);
	#endif

retry_connection:
	if (!sconn[lserver_id].server_connected) {
		sprintf(sport, "%d", atoi(servers[lserver_id].serverport));
		sd = tcp_connect(servers[lserver_id].serverip, sport);
		if (sd == -1) {
			if (retried) {
				printf("Get operation failed: Both server nodes down\n");
				return;
			}
			lserver_id += 1;
			if (lserver_id == MAX_NO_OF_SERVERS)
				lserver_id = lserver_id % MAX_NO_OF_SERVERS;
			goto retry_connection;
		}
		sconn[lserver_id].sockfd = sd;
		sconn[lserver_id].server_connected = true;
	}

	noBytesWritten = writen(sconn[lserver_id].sockfd, data, MESSAGE_SIZE);
	if ((noBytesWritten < 0) || (noBytesWritten == 0)) {
		if (retried) {
			printf("Get operation failed: Both server nodes down\n");
			return;
		}
		close(sconn[lserver_id].sockfd);
		sconn[lserver_id].sockfd = -1;
		sconn[lserver_id].server_connected = false;
		lserver_id += 1;
		if (lserver_id == MAX_NO_OF_SERVERS)
			lserver_id = lserver_id % MAX_NO_OF_SERVERS;
		retried = true;
		goto retry_connection;
	}
	#ifdef DEBUG
	printf("Bytes written by peer: %d\n", noBytesWritten);
	#endif
	memset(data, 0x30, MESSAGE_SIZE);
	noBytesRead = readn(sconn[lserver_id].sockfd, data, MESSAGE_SIZE);
	if ((noBytesRead < 0) || (noBytesRead == 0)) {
		if (retried) {
			printf("Get operation failed: Both server nodes down\n");
			return;
		}
		close(sconn[lserver_id].sockfd);
		sconn[lserver_id].sockfd = -1;
		sconn[lserver_id].server_connected = false;
		lserver_id += 1;
		if (lserver_id == MAX_NO_OF_SERVERS)
			lserver_id = lserver_id % MAX_NO_OF_SERVERS;
		retried = true;
		goto retry_connection;
	}
	#ifdef DEBUG
	printf("Bytes read from server: %d\n", noBytesRead);
	#endif
	if (data[0] == 'C' && data[1] == 'S') {
		if (data[2] == CMD_GET) {
			if (data[3] == CMD_OK) {
				if (!perf_test_on) {
					printf("\nGet operation successful\n");
				}
				peerid_start_pos = KEY_START_POS + data[KEY_LENGTH_POS] + 1;
				process_data_from_get(&data[peerid_start_pos], key, key_length);
			} else {
				if (!perf_test_on) {
					printf("\nGet operation failed\n");
				}
			}
		}
	}
}

/*
 * This function is added solely for the purpose of testing by seperating
 * the SEARCH operation from OBTAIN for timing measurements.
 */
void test_get_from_server(const unsigned char *key, const int key_length) {
	unsigned char data[MESSAGE_SIZE];
	char sport[32] = {0};
	int sd;
	int lserver_id;
	int peerid_start_pos;
	int noBytesRead;
	int noBytesWritten;
	bool retried = false;

	memset(data, 0, MESSAGE_SIZE);
	data[0] = 'C';
	data[1] = 'S';
	data[2] = CMD_GET;
	data[3] = 0;

	data[4] = key_length;
	strncpy(&data[KEY_START_POS], key, key_length);

	lserver_id = hash_peer(&data[KEY_START_POS], key_length);
	#ifdef DEBUG
	if (!perf_test_on)
		printf("GET Server Id: %d\n", lserver_id);
	#endif

retry_connection:
	if (!sconn[lserver_id].server_connected) {
		sprintf(sport, "%d", atoi(servers[lserver_id].serverport));
		sd = tcp_connect(servers[lserver_id].serverip, sport);
		if (sd == -1) {
			if (retried) {
				printf("Get operation failed: Both server nodes down\n");
				return;
			}
			lserver_id += 1;
			if (lserver_id == MAX_NO_OF_SERVERS)
				lserver_id = lserver_id % MAX_NO_OF_SERVERS;
			goto retry_connection;
		}
		sconn[lserver_id].sockfd = sd;
		sconn[lserver_id].server_connected = true;
	}

	noBytesWritten = writen(sconn[lserver_id].sockfd, data, MESSAGE_SIZE);
	if ((noBytesWritten < 0) || (noBytesWritten == 0)) {
		if (retried) {
			printf("Get operation failed: Both server nodes down\n");
			return;
		}
		close(sconn[lserver_id].sockfd);
		sconn[lserver_id].sockfd = -1;
		sconn[lserver_id].server_connected = false;
		lserver_id += 1;
		if (lserver_id == MAX_NO_OF_SERVERS)
			lserver_id = lserver_id % MAX_NO_OF_SERVERS;
		retried = true;
		goto retry_connection;
	}
	#ifdef DEBUG
	printf("Bytes written by peer: %d\n", noBytesWritten);
	#endif
	memset(data, 0x30, MESSAGE_SIZE);
	noBytesRead = readn(sconn[lserver_id].sockfd, data, MESSAGE_SIZE);
	if ((noBytesRead < 0) || (noBytesRead == 0)) {
		if (retried) {
			printf("Get operation failed: Both server nodes down\n");
			return;
		}
		close(sconn[lserver_id].sockfd);
		sconn[lserver_id].sockfd = -1;
		sconn[lserver_id].server_connected = false;
		lserver_id += 1;
		if (lserver_id == MAX_NO_OF_SERVERS)
			lserver_id = lserver_id % MAX_NO_OF_SERVERS;
		retried = true;
		goto retry_connection;
	}
	#ifdef DEBUG
	printf("Bytes read from server: %d\n", noBytesRead);
	#endif
	if (data[0] == 'C' && data[1] == 'S') {
		if (data[2] == CMD_GET) {
			if (data[3] == CMD_OK) {
				if (!perf_test_on) {
					printf("\nGet operation successful\n");
				}
				/* Commented for purposes of testing.  See comment above */
				/* peerid_start_pos = KEY_START_POS + data[KEY_LENGTH_POS] + 1; */
				/* process_data_from_get(&data[peerid_start_pos], key, key_length); */
			} else {
				if (!perf_test_on) {
					printf("\nGet operation failed\n");
				}
			}
		}
	}
}

void delete_from_server(const unsigned char *key, const int key_length) {
	unsigned char data[MESSAGE_SIZE];
	int lserver_id;
	int i, sd;
	char sport[32] = {0};
	int noBytesRead;
	int noBytesWritten;
	bool exit;

	memset(data, 0, MESSAGE_SIZE);
	data[0] = 'C';
	data[1] = 'S';
	data[2] = CMD_DEL;
	data[3] = 0;

	data[4] = key_length;
	strncpy(&data[KEY_START_POS], key, key_length);

	lserver_id = hash_peer(&data[KEY_START_POS], key_length);
	#ifdef DEBUG
	if (!perf_test_on)
		printf("DEL Server Id: %d\n", lserver_id);
	#endif

	/*
	 * We achieve replication by also registering all files with the next
	 * server which the hash returned. So if the above hash returns 2, the
	 * values will be replicated at 3 as well. Logic from class lecture.
	 */
	for (i = lserver_id; i <= (lserver_id + 1); i++) {
		if (i == MAX_NO_OF_SERVERS) {
			i = (lserver_id + 1) % MAX_NO_OF_SERVERS;
			exit = true;
		}

		if (!sconn[i].server_connected) {
			sprintf(sport, "%d", atoi(servers[i].serverport));
			sd = tcp_connect(servers[i].serverip, sport);
			sconn[i].sockfd = sd;
			sconn[i].server_connected = true;
		}

		noBytesWritten = writen(sconn[i].sockfd, data, MESSAGE_SIZE);
		#ifdef DEBUG
		printf("Bytes written by peer: %d\n", noBytesWritten);
		#endif
		memset(data, 0x30, MESSAGE_SIZE);
		noBytesRead = readn(sconn[i].sockfd, data, MESSAGE_SIZE);
		if (noBytesRead < 0) {
			sconn[i].sockfd = -1;
			sconn[i].server_connected = false;
			return;
		}
		#ifdef DEBUG
		printf("Bytes read from server: %d\n", noBytesRead);
		#endif
		if (data[0] == 'C' && data[1] == 'S') {
			if (data[2] == CMD_DEL) {
				if (data[3] == CMD_OK) {
					if (!perf_test_on) {
						printf("\nDel operation successful\n");
					}
				} else {
					if (!perf_test_on) {
						printf("\nDel operation failed\n");
					}
				}
			}
		}

		if (exit)
			return;
	}
}

void delete_with_server(void) {
	struct dirent dirent, *result;
	unsigned char peerid[PEER_ID_SIZE];
	DIR *d;

	memset(peerid, 0, PEER_ID_SIZE);
	strncat(peerid, servers[server_id].serverip, PEER_ID_SIZE);
	strncat(peerid, " ", PEER_ID_SIZE - strlen(peerid));
	strncat(peerid, servers[server_id].serverport, PEER_ID_SIZE - strlen(peerid));

	d = opendir(dir_to_be_shared);
	if (d) {
		/* Use the MT safe reentrant version of readdir */
		while (readdir_r(d, &dirent, &result) == 0) {
			if (result == NULL)
				break;

			/* We check if it is a regular file. See 'man readdir_r' */
			if (result->d_type == DT_REG)
				delete_from_server(result->d_name, strlen(result->d_name));
		}
		closedir(d);
	} else {
		perror("Could not open directory");
	}
}

void run_register_tests(void) {
	int i;
	char key[KEY_SIZE];
	char filename[KEY_SIZE];
	struct timeval t1, t2;
	double elapsedtime, totalelapsedtime, searchtime;

	perf_test_on = true;
	memset(key, 0, KEY_SIZE);

	/* Run REGISTER tests */
	for (i = 0; i < NO_OF_TEST_ITERATIONS; i++) {
		gettimeofday(&t1, NULL);
		register_with_server();
		gettimeofday(&t2, NULL);
		// compute and print the elapsed time in millisec
		elapsedtime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
		elapsedtime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms
#ifdef DEBUG
		printf("Elapsed time: %f\n", elapsedtime);
#endif
		totalelapsedtime += elapsedtime;
		/* We need to delete from server our previous registration */
		delete_with_server();
	}
	printf("Average Response time for REGISTER requests: %f ms\n", totalelapsedtime / NO_OF_TEST_ITERATIONS);

	perf_test_on = false;
}

void run_search_obtain_tests(void) {
	int i;
	char key[KEY_SIZE];
	char filename[KEY_SIZE];
	struct timeval t1, t2;
	double elapsedtime, totalelapsedtime, searchtime;

	perf_test_on = true;
	memset(key, 0, KEY_SIZE);

	printf("\nEnter name of file which will be used\n");
	printf("for testing SEARCH and OBTAIN operations: \t");
	/* File name is our key */
	scanf("%s", key);

	/* Run SEARCH tests */
	for (i = 0; i < NO_OF_TEST_ITERATIONS; i++) {
		gettimeofday(&t1, NULL);
		test_get_from_server(key, strlen(key));
		gettimeofday(&t2, NULL);
		// compute and print the elapsed time in millisec
		elapsedtime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
		elapsedtime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms
#ifdef DEBUG
		printf("Elapsed time: %f\n", elapsedtime);
#endif
		totalelapsedtime += elapsedtime;
	}
	printf("Average Response time for SEARCH requests: %f ms\n", totalelapsedtime / NO_OF_TEST_ITERATIONS);
	searchtime = totalelapsedtime / NO_OF_TEST_ITERATIONS;

	/* Run OBTAIN tests */
	memset(filename, 0, KEY_SIZE);
	strncat(filename, dir_to_be_shared, strlen(dir_to_be_shared));
	strncat(filename, key, strlen(key));
	for (i = 0; i < NO_OF_TEST_ITERATIONS; i++) {
		gettimeofday(&t1, NULL);
		get_from_server(key, strlen(key));
		gettimeofday(&t2, NULL);
		// compute and print the elapsed time in millisec
		elapsedtime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
		elapsedtime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms
#ifdef DEBUG
		printf("Elapsed time: %f\n", elapsedtime);
#endif
		totalelapsedtime += elapsedtime;
		printf("DEL filename: %s\n", filename);
		if (remove(filename) != 0) {
			perror("File deletion failed for next iteration");
			break;
		}
	}
	printf("Average Response time for OBTAIN requests: %f ms\n", (totalelapsedtime / NO_OF_TEST_ITERATIONS) - searchtime);

	perf_test_on = false;
}

void input_process(void) {
	char key[KEY_SIZE];
	bool exitloop = false;
	int input;

	/*
	 * We run the peer functionality in this main thread
	 */
	memset(key, 0, KEY_SIZE);
	while (!exitloop) {
		printf("\nSelect Operation\n");
		printf("(1) Register (2) Get file\n");
		printf("(3) Run Register tests (4) Run search and obtain tests\n");
		printf("(5) Replicate (6) Exit");
		printf("\nPlease enter your selection (1-6)\t");

		scanf("%d", &input);
		getchar();

		switch (input) {
		case 1:
			register_with_server();
			break;
		case 2:
			printf("Enter file name: \t");
			/* File name is our key */
			scanf("%s", key);
			printf("\n");
			get_from_server(key, strlen(key));
			break;
		case 3:
			run_register_tests();
			break;
		case 4:
			run_search_obtain_tests();
			break;
		case 5:
			replicate_with_server();
			break;
		case 6:
			workqueue_shutdown(&workqueue);
			exitloop = true;
			break;
		default:
			printf("\n\nWrong value: %d\n", input);
			break;
		}

		/* Reset buffers for next iteration */
		memset(key, 0x30, KEY_SIZE);
	}
}

int main(int argc, char *argv[]) {
	FILE *fp;
	int i;
	int error;
	int count_of_servers;
	ssize_t read;
	size_t len = 0;
	char *line = NULL;
	char sport[32] = {0};
	unsigned char **tokens = NULL;

	if (argc != 5) {
		/*
		 * We do not validate or error check any of the arguments
		 * Please enter correct arguments
		 */
		printf("Usage: ./server <serverid#> </path/to/server/conf/file> </dir/to/be/shared> </ip/to/bind/to/>\n");
		exit(1);
	}

	server_id = atoi(argv[1]) - 1;
	if ((server_id < 0) || (server_id > MAX_NO_OF_SERVERS)) {
		printf("Incorrect server id provided\n");
		exit(1);
	}

	strcpy(dir_to_be_shared, argv[3]);

	fp = fopen(argv[2], "r");
	if (fp == NULL) {
		perror("Could not open server configuration file");
		exit(1);
	}

	/*
	 * We now extract the IP and port information of 8 servers
	 * which will be involved in this setup.
	 */
	count_of_servers = 0;
	while ((read = getline(&line, &len, fp)) != -1) {
		sconn[count_of_servers].server_connected = false;
		sconn[count_of_servers].sockfd = -1;

		if (count_of_servers == MAX_NO_OF_SERVERS)
			break;

		tokens = str_split(line, ' ');
		if (tokens) {
			servers[count_of_servers].serverip = *(tokens);
			servers[count_of_servers].serverport = *(tokens + 1);
		}
		free(line);
		line = NULL;

		count_of_servers++;
	}

	fclose(fp);

	if (pthread_rwlock_init(&ht_lock, NULL) != 0) {
		perror("Lock init failed");
		goto free_tokens;
	}

	/* Initialize work queue */
	if (workqueue_init(&workqueue, NUMBER_OF_WQS)) {
		workqueue_shutdown(&workqueue);
		perror("Failed to create workqueue");
		goto free_tokens;
	}

	sprintf(sport, "%d", atoi(servers[server_id].serverport));

	/*
	 * Instead of taking the own IP from server file, we specify the IP
	 * to bind to on the command line. This is done primarily for working
	 * with AWS. On AWS, while it is possible to connect using the public
	 * IP of an EC2 instance to another instance, it is not possible to bind
	 * to the public IP of one's own EC2 instance. So we specify the local IP
	 * to bind to here and public IP will be mentioned in the server configu-
	 * ration file. For example, if an EC2 instance has public IP 52.32.4.155
	 * and local IP as 172.31.9.81 we can bind to 172.31.9.81 while we cannot
	 * bind to 52.32.4.155. However others need to see public IP and we need
	 * to advertise our own public IP but bind to this IP. The rest of the
	 * code uses public IP but we just bind and use the local IP here. We
	 * make this compulsory everywhere local machine or otherwise to keep
	 * consistency and easy handling.
	 */
	listenfd = tcp_listen(argv[4],										//servers[server_id].serverip,
					sport, &addr_length);

	/*
	 * Start the server. We start the server in another thread so
	 * we can accept incoming connections in there for which we block.
	 */
	error = pthread_create(&tid, NULL, &server_thread, (void *)&listenfd);
	if (error != 0) {
		perror("Error in server thread creation");
		goto free_tokens;
	}

	input_process();

	for (i = count_of_servers - 1; i >= 0; --i) {
		free(servers[i].serverip);
		free(servers[i].serverport);
		close(sconn[i].sockfd);
	}

	pthread_rwlock_destroy(&ht_lock);

	return 0;

free_tokens:
	for (i = count_of_servers - 1; i >= 0; --i) {
		free(servers[i].serverip);
		free(servers[i].serverport);
	}

	return -1;
}
