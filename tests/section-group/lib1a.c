#define _GNU_SOURCE
#include <dlfcn.h>
#include "liballocs.h"

struct s1a
{
	int x;
} s1a;

void *l1a(void)
{
	/* Get our __uniqtype__s1a. */
	struct uniqtype *resolved = dlsym(__liballocs_my_metaobj(), "__uniqtype__s1a");
	/* Return our __uniqtype__int$$32. */
	return resolved->related[0].un.memb.ptr;
}
