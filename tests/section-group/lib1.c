#define _GNU_SOURCE
#include <dlfcn.h>
#include <assert.h>
#include "liballocs.h"

struct s1
{
	int x;
} s1;

extern struct uniqtype *l1a(void);

void *l1(int arg)
{
	/* Get our __uniqtype__s1. */
	struct uniqtype *resolved = dlsym(__liballocs_my_metaobj(), "__uniqtype__s1");
	struct uniqtype *int32 = resolved->related[0].un.memb.ptr;
	
	/* Check that we're using the same "__uniqtype_int$32" as l1a is. */
	assert(l1a() == int32);
	
	/* Pass our pointer up to main(), so it can test globally. */
	return int32;
}
