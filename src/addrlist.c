#define _GNU_SOURCE
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "liballocs_private.h"

#include <stdlib.h>

_Bool addrlist_contains(struct addrlist *l, void *addr)
{
	for (unsigned i = 0; i < l->count; ++i)
	{
		if (l->addrs[i] == addr) return 1;
	}
	return 0;
}
void addrlist_add(struct addrlist *l, void *addr)
{
	if (l->count == l->allocsz)
	{
		++(l->allocsz);
		l->allocsz *= 2;
		l->addrs = realloc(
			l->addrs,
			l->allocsz * sizeof (void*));
	}
	l->addrs[l->count++] = addr;
}
