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
void process_peer_request(void *arg) {
	int fd;
	int status;
	int connfd = *((int *)arg);
	char data[MESSAGE_SIZE];
	char filename[KEY_SIZE];
	char readbuffer[READ_BUFFER_SIZE];
	int noBytesRead;
	int noBytesWritten;
	int value_start_pos;
	unsigned int file_bytes_counter;
	struct node_t *np;
	struct stat statbuffer;

	while (true) {
		memset(data, 0, MESSAGE_SIZE);
		noBytesRead = readn(connfd, data, MESSAGE_SIZE);
		if (noBytesRead < 0)
			break;
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
				memset(filename, 0, KEY_SIZE);
				strncpy(filename, dir_to_be_shared, strlen(dir_to_be_shared));
				strncat(filename, &data[KEY_START_POS], data[KEY_LENGTH_POS]);
				filename[strlen(filename) + 1] = '\0';
				#ifdef DEBUG
				printf("File %s request received from peer\n", filename);
				#endif

				memset(readbuffer, 0, READ_BUFFER_SIZE);

				status = stat(filename, &statbuffer);
				if (status != 0) {
					perror("Could not get file info\n");
					goto break_out;
				}

				file_bytes_counter = 0;
				fd = open(filename, O_RDONLY);
				if (fd == -1) {
					perror("Server: Error opening file");
					goto break_out;
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
break_out:
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
	}

	pthread_exit(NULL);
}

void *server_thread(void *arg) {
	int listenfd = *((int *)arg);
	int connfd, error;
	socklen_t client_length;
	struct sockaddr *client_address;

	client_address = malloc(addr_length);
	if (!client_address)
		err_sys("Error in allocating memory for client address\n");

	for ( ; ; )	{
		client_length = addr_length;

		connfd = accept(listenfd, client_address, &client_length);
		if (connfd == -1)
			err_sys("Error with accept");
		else
			printf("Connection accepted\n");

		/*
		 * We create a thread for each incoming connection. We know we
		 * are not gonna do more than 8 nodes for this assignment and this
		 * design serves fine for the requirement at hand. We do not
		 * close the connection. The connection is only ever closed by
		 * the peer on exit.
		 */
		error = pthread_create(&tid, NULL, &process_peer_request, (void *)&connfd);
		if (error != 0) {
			perror("Error in thread creation for peer");
			close(connfd);
		}
	}
}

void put_at_server(const unsigned char *key, const int key_length,
				   const unsigned char *value, const int value_length) {
	unsigned char data[MESSAGE_SIZE];
	int lserver_id;
	int sd;
	char sport[32] = {0};
	int noBytesRead;
	int noBytesWritten;

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
	noBytesRead = readn(sconn[lserver_id].sockfd, data, MESSAGE_SIZE);
	if (noBytesRead < 0) {
		sconn[lserver_id].sockfd = -1;
		sconn[lserver_id].server_connected = false;
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
	} else {
		perror("Could not open directory");
	}
}

void process_data_from_get(const unsigned char *peerid,
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
	int peerinput;
	int peerfd;
	int fd;

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

#ifdef DEBUG
	printf("Connecting to peer at %s on port %s\n", peerip[peerinput], peerport[peerinput]);
#endif

	peerfd = -1;
	for (l = 0; l < MAX_NO_OF_SERVERS; l++) {
		if ((strcmp(peerip[peerinput], servers[l].serverip) == 0) &&
			(strcmp(peerport[peerinput], servers[l].serverport) == 0))
			if (sconn[l].server_connected) {
				peerfd = sconn[l].sockfd;
				#ifdef DEBUG
				printf("Already connected to peer\n");
				#endif
			}
	}

	if (peerfd == -1) {
		sprintf(sport, "%d", atoi(peerport[peerinput]));
		peerfd = tcp_connect(peerip[peerinput], sport);
	}

	memset(data, 0, MESSAGE_SIZE);
	data[0] = 'C';
	data[1] = 'S';
	data[2] = CMD_PEER_REQ;
	data[3] = 0;
	data[4] = key_length;
	strncat(&data[KEY_START_POS], key, key_length);

	writen(peerfd, data, MESSAGE_SIZE);

	memset(filename, 0, KEY_SIZE);
	strncpy(filename, key, key_length);
	fd = open(filename, O_WRONLY | O_CREAT);
	if (fd == -1) {
		perror("Error opening file");
		return;
	}

	readbuffer = (char *)malloc(READ_BUFFER_SIZE);
	if (!readbuffer) {
		perror("Could not allocate memory for buffer");
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
	memset(data, 0x30, MESSAGE_SIZE);
	noBytesRead = readn(sconn[lserver_id].sockfd, data, MESSAGE_SIZE);
	if (noBytesRead < 0) {
		sconn[lserver_id].sockfd = -1;
		sconn[lserver_id].server_connected = false;
		return;
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

void delete_from_server(const unsigned char *key, const int key_length) {
	unsigned char data[MESSAGE_SIZE];
	int lserver_id;
	int sd;
	char sport[32] = {0};
	int noBytesRead;
	int noBytesWritten;

	memset(data, 0, MESSAGE_SIZE);
	data[0] = 'C';
	data[1] = 'S';
	data[2] = CMD_DEL;
	data[3] = 0;

	data[4] = key_length;
	strncpy(&data[KEY_START_POS], key, key_length);

	lserver_id = hash_peer(&data[KEY_START_POS], key_length);
	if (!perf_test_on)
		printf("DEL Server Id: %d\n", lserver_id);

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
	memset(data, 0x30, MESSAGE_SIZE);
	noBytesRead = readn(sconn[lserver_id].sockfd, data, MESSAGE_SIZE);
	if (noBytesRead < 0) {
		sconn[lserver_id].sockfd = -1;
		sconn[lserver_id].server_connected = false;
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
}

void run_perf_tests(void) {
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
		printf("(1) Register (2) Get file (3) Run tests\n");
		printf("(4) Exit");
		printf("\nPlease enter your selection (1-4)\t");

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
			run_perf_tests();
			break;
		case 4:
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
	char **tokens = NULL;
	char sport[32] = {0};

	if (argc != 4) {
		/*
		 * We do not validate or error check any of the arguments
		 * Please enter correct arguments
		 */
		printf("Usage: ./server <serverid#> </path/to/server/conf/file> </dir/to/be/shared>");
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

	sprintf(sport, "%d", atoi(servers[server_id].serverport));
	listenfd = tcp_listen(servers[server_id].serverip,
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
