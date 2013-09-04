
#ifndef SRV_H
#define SRV_H

#include "ft.h"

struct thread_args {
	int skt;
	ft_entry_t **ft_header;
};

#endif // SRV_H