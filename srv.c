#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include "srv.h"
#include "ft.h"
#include "rip.h"

#define BUFF_LEN 1024
#define TTL_DEFAULT 200
#define TTL_INFINITY -1
#define MAX_ENTRIES 26
#define RIP_REQUEST 1
#define RIP_RESPONSE 2
#define RIP_PORT "520"

void pfail(char *message) {
	perror(message);
	exit(1);
}

int create_socket() {
	struct addrinfo hints, *info;
	int skt, res, optval = 1;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM; // UDP
	hints.ai_flags = AI_PASSIVE; // Local machine's IP
	
	if ((res = getaddrinfo(NULL, RIP_PORT, &hints, &info)) != 0) {
		fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(res));
		exit(1);
	}
	if ((skt = socket(info->ai_family, info->ai_socktype, info->ai_protocol)) < 0) { // Use the same socket to send/receive
		pfail("socket()");
	}
	if (bind(skt, info->ai_addr, info->ai_addrlen) < 0) { // Listen for updates on this port
		pfail("bind()"); 
	}
	freeaddrinfo(info);
	
	struct ip_mreqn multaddr;
	multaddr.imr_multiaddr.s_addr = inet_addr("224.0.0.9");
	multaddr.imr_address.s_addr = INADDR_ANY;
	multaddr.imr_ifindex = 0;
	
	if (setsockopt(skt, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *) &multaddr, (socklen_t) sizeof(multaddr))) { // Join multicast group 244.0.0.9
		pfail("setsockopt()");
	}
	if (setsockopt (skt, SOL_SOCKET, SO_BROADCAST, (void *)&optval, (socklen_t) sizeof(optval))) { // Allow broadcasts
		pfail("setsockopt()");
	}
	return skt;
}

int send_packet(int skt, char *inaddr, char *port, char *buff, int len) {
	int res, sent;
	
	// Get the destination info
	struct addrinfo hints, *info;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((res = getaddrinfo(inaddr, port, &hints, &info)) != 0) {
		fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(res));
		exit(1);
	}
	if ((sent = sendto(skt, buff, len, info->ai_flags, info->ai_addr, info->ai_addrlen)) != len)
		pfail("sendto()");

	freeaddrinfo(info);
	return sent;
}

void build_request(struct rip_msg *ripmsg, int ripver) {
	// Request entire routing table
	ripmsg->command = RIP_REQUEST;
	ripmsg->version = ripver;
	
	struct rip2ent *entry = (struct rip2ent *) ripmsg->entries;
	entry->addr_family = AF_UNSPEC;
	entry->metric = htonl(16); // Infinity
}

int build_response(struct rip_msg *ripmsg, int ripver, ft_entry_t *header) {
	int i = 0;
	ft_entry_t *p;
	struct rip2ent *entry = (struct rip2ent *) ripmsg->entries;
	for (p = header; p != NULL; p = p->next) {
		entry->metric = htonl(p->metric);
		entry->ip_addr = htonl(p->network);
		entry->route_tag = 0;
		
		if (ripver == 2) {
			entry->next_hop = htonl(p->gateway);
			entry->subnet_mask = htonl(p->netmask);
		}
		entry->addr_family = htons(AF_INET); // TODO Store in routing table and send correct version
		entry++;
		i++;
	}
	
	ripmsg->command = RIP_RESPONSE;
	return sizeof(struct rip_msg) + sizeof(struct rip2ent) * i;
}

void merge_entries(struct rip_msg *ripmsg, ft_entry_t **header, int bytes) {
	int i, append;
	ft_entry_t *p;
	struct rip2ent *entries = (struct rip2ent *) ripmsg->entries;
	for (i = 0; i < MAX_ENTRIES && i * sizeof(struct rip2ent) < bytes - sizeof(struct rip_msg); i++) {
		// Find existing entries for this network
		append = 0;
		for (p = *header; p != NULL; p = p->next) {
			if (p->network == ntohl(entries->ip_addr) && p->netmask == ntohl(entries->subnet_mask)) {
				if (p->metric > ntohl(entries->metric) + 1)
					break; // Found a better route for this entry
				else {
					p->ttl = TTL_DEFAULT;
					goto skip; // Ignore this entry
				}
			}
		}
		if (p == NULL) {
			p = ft_new();
			append = 1;
		}
		
		p->ttl = TTL_DEFAULT;
		p->metric = ntohl(entries->metric) + 1;
		p->network = ntohl(entries->ip_addr);
		
		if (ripmsg->version == 2) {
			p->netmask = ntohl(entries->subnet_mask);
			p->gateway = ntohl(entries->next_hop);
		}
		
		if (append) {
			ft_append(header, p);
		}
		
		skip:
		entries++;
	}
	
	printf("New table:\n");
	ft_print(*header);
}

void * send_thread(void *sktp) {
	int i = rand() % 10;
	char buff[BUFF_LEN];
	ft_entry_t *p;
	struct thread_args *args = (struct thread_args *) sktp;
	
	// build_request((struct rip_msg *) buff, 1);
	// send_packet(args->skt, "10.37.211.102", RIP_PORT, buff, sizeof(struct rip_msg) + sizeof(struct rip2ent)); // RIPv1 router
	
	build_request((struct rip_msg *) buff, 2);
	send_packet(args->skt, "10.37.211.101", RIP_PORT, buff, sizeof(struct rip_msg) + sizeof(struct rip2ent)); // RIPv2 router

	while (1) {
		sleep(1);
		
		// Update TTL
		for (p = *args->ft_header; p != NULL; p = p->next) {
			if (p->ttl >= 0) {
				if (--p->ttl == 0)
					ft_remove(args->ft_header, p);
			}
		}
		
		// Send periodic updates
		if (++i > 30) {
			// Broadcast (RIPv1)
			printf("Sending broadcast (255.255.255.255)\n");
			int len = build_response((struct rip_msg *) buff, 1, *args->ft_header);
			send_packet(args->skt, "255.255.255.255", "20000", buff, len);
			
			// Multicast (RIPv2)
			printf("Sending multicast (224.0.0.9)\n");
			((struct rip_msg *) buff)->version = 2;
			send_packet(args->skt, "224.0.0.9", "20000", buff, len);
			i = 0;
		}
	}
}

void * listen_thread(void *sktp) {
	struct thread_args *args = (struct thread_args *) sktp;
	int addrlen = sizeof(struct sockaddr), msglen, rcvd;
	struct sockaddr src_addr;
	char buff[BUFF_LEN], addr[INET_ADDRSTRLEN];
	
	while (1) {
		if ((rcvd = recvfrom(args->skt, buff, sizeof(buff), 0, &src_addr, &addrlen)) < 0)
			pfail("recvfrom()");
			
		struct rip_msg *ripmsg = (struct rip_msg *) buff;
		struct rip2ent *entry = (struct rip2ent *) ripmsg->entries;
		
		inet_ntop(AF_INET, &(((struct sockaddr_in *) &src_addr)->sin_addr), addr, INET_ADDRSTRLEN);
		printf("RECV (type %d): %d bytes from %s\n", ripmsg->command, rcvd, addr);
		
		switch (ripmsg->command) {
		case RIP_REQUEST:
			msglen = build_response(ripmsg, ripmsg->version, *args->ft_header);
			if (sendto(args->skt, ripmsg, msglen, 0, &src_addr, addrlen) != msglen)
				pfail("sendto()");
			break;
		case RIP_RESPONSE:
			merge_entries(ripmsg, args->ft_header, rcvd);
			break;
		default:
			fprintf(stderr, "Bad RIP command\n");
		}
	}
}

int main() {
	pthread_t t1, t2;
	ft_entry_t *ft_header = NULL;
	struct thread_args args = {create_socket(), &ft_header};
	
	/*struct sockaddr_in localhost;
	socklen_t len = sizeof(localhost);
	getsockname(args.skt, (struct sockaddr *) &localhost, &len);*/
	
	// Add local host and basic subnet
	// ft_append(&ft_header, ft_parse(inet_ntoa(&localhost.sin_addr), "255.255.255.255", "0.0.0.0", "0.0.0.0", 0, TTL_INFINITY));
	ft_append(&ft_header, ft_parse("7.239.0.0", "255.255.255.255", "7.239.0.5", "0.0.0.0", 3, TTL_INFINITY));
	ft_append(&ft_header, ft_parse("7.239.5.0", "255.255.255.0", "0.0.0.0", "0.0.0.0", 6, TTL_INFINITY));
	
	pthread_create(&t1, NULL, listen_thread, (void *) &args);
	pthread_create(&t2, NULL, send_thread, (void *) &args);
	pthread_join(t2, NULL);
	pthread_join(t1, NULL);

	ft_free(*args.ft_header);
	close(args.skt);
	return 0;
}
