#ifndef FT_H
#define FT_H

#include <stdint.h>

typedef struct ft_entry {
	int ttl;
	unsigned int metric;
	uint32_t network, netmask, gateway, interface;
	struct ft_entry *next;
} ft_entry_t;

ft_entry_t * ft_new();

int ft_remove(ft_entry_t **, ft_entry_t *);

ft_entry_t * ft_parse(char *, char *, char *, char *, unsigned int, unsigned int);

void ft_append(ft_entry_t **, ft_entry_t *);

ft_entry_t * ft_find(ft_entry_t *, char *);

void ft_print(ft_entry_t *);

void ft_free(ft_entry_t *);

#endif // FT_H
