#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "ft.h"

ft_entry_t * ft_new() {
	ft_entry_t *new = calloc(1, sizeof(ft_entry_t));
	if (new == NULL) {
		fprintf(stderr, "Could not assign memory!\n");
		exit(-1);
	}
	new->next = NULL;
	return new;
}

int ft_remove(ft_entry_t **header, ft_entry_t *entry) {
	ft_entry_t *prev = NULL, *p = *header;
	while (p != NULL) {
		if (p == entry) {
			if (prev == NULL)
				*header = p->next;
			else
				prev->next = p->next;
			free(p);
			return 0;
		}
	
		prev = p;
		p = p->next;
	}
	return 1; // Not found
}

ft_entry_t * ft_parse(char *network, char *netmask, char *gateway, char *interface, unsigned int metric, unsigned int ttl) {
	ft_entry_t *new = ft_new();
	inet_pton(AF_INET, network, &new->network);
	new->network = htonl(new->network);
	inet_pton(AF_INET, netmask, &new->netmask);
	new->netmask = htonl(new->netmask);
	inet_pton(AF_INET, gateway, &new->gateway);
	new->gateway = htonl(new->gateway);
	inet_pton(AF_INET, interface, &new->interface);
	new->interface = htonl(new->interface);
	new->metric = metric;
	new->ttl = ttl;
	return new; 
}

void ft_append(ft_entry_t **header, ft_entry_t *entry) {
	if (*header == NULL) {
		// Empty list
		*header = entry;
	} else {
		ft_entry_t *cur = *header;
		while (cur->next != NULL)
			cur = cur->next;
		cur->next = entry;
	}
}

ft_entry_t * ft_find(ft_entry_t *header, char *pattern) {
	uint32_t addr, bestmask = 0;
	ft_entry_t *rv = NULL;
	inet_pton(AF_INET, pattern, &addr);
	addr = htonl(addr);
	while (header != NULL) {
		if ((header->network & header->netmask) == (addr & header->netmask) && header->netmask > bestmask) {
			bestmask = header->netmask;
			rv = header;
		}
		header = header->next;
	}
	return rv;
}

char * iptos (uint32_t ipaddr) {
   static char ips[16];

   sprintf(ips, "%d.%d.%d.%d",
      (ipaddr >> 24),
      (ipaddr >> 16) & 0xff,
      (ipaddr >>  8) & 0xff,
      (ipaddr      ) & 0xff );
   return ips;
}

void ft_print(ft_entry_t *header) {
	printf("%16s %16s %16s %16s %9s %7s\n", "Network", "Netmask", "Gateway", "Interface", "Metric", "TTL");
	while (header != NULL) {
		printf("%16s ", iptos(header->network));
		printf("%16s ", iptos(header->netmask));
		printf("%16s ", iptos(header->gateway));
		printf("%16s %9d %7d\n", iptos(header->interface), header->metric, header->ttl);
		header = header->next;
	}
}

void ft_printsingle(ft_entry_t *entry) {
	printf("Network: %16s ", iptos(entry->network));
	printf("Netmask: %16s ", iptos(entry->netmask));
	printf("Gateway: %16s ", iptos(entry->gateway));
	printf("Interface: %16s Metric: %9d TTL: %7d\n", iptos(entry->interface), entry->metric, entry->ttl);
}

void ft_free(ft_entry_t *header) {
	ft_entry_t *next;
	while (header != NULL) {
		next = header->next;
		free(header);
		header = next;
	}
}
