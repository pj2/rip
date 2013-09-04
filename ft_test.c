#include <stdio.h>
#include <arpa/inet.h>
#include "ft.h"

int main() {
	int i;
	char c, str[INET_ADDRSTRLEN];
	ft_entry_t *header = NULL;
	ft_append(&header, ft_parse("1.1.1.1", "255.255.255.255", "2.2.2.2", "3.3.3.3", 1, 255));
	ft_append(&header, ft_parse("2.2.2.2", "255.255.255.0", "5.5.5.5", "1.2.3.4", 10, 13));	
	ft_append(&header, ft_parse("2.2.2.2", "255.255.255.255", "2.3.1.4", "3.3.3.3", 4, 16));

	while (1) {
		printf("Options: (f)ind next hop, (q)uit\n");
		c = getchar();
		switch (c) {
		case 'f':
			printf("Type network address: ");
			getchar();
			fgets(str, sizeof(str), stdin); 

			i = strlen(str)-1;
			if (str[i] == '\n')
				str[i] = '\0';

			ft_entry_t *found = ft_find(header, str);
			if (found == NULL)
				printf("Not found\n");
			else
				ft_printsingle(found);
			break;
		case 'q':
			ft_free(header);
			return 0;
		default:
			printf("Type 'f' or 'q'\n");
			break;
		}
	}
}
