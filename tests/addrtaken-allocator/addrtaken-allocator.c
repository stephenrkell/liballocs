#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <liballocs.h>

/* Here we test several tricky things. The allocator function
 * is not only static, but called indirectly. This is a bit like
 * how bzip2 does its allocation (default_bzalloc).*/

static void *myalloc(size_t size)
{
	return malloc(size);
}

typedef void*(*alloc_fp)(size_t);
alloc_fp get_allocator(void)
{
	return myalloc;
}

int main(void)
{
	int *is = get_allocator()(42 * sizeof(int));
	assert(is);
	for (int i = 0; i < 42; ++i) is[i] = i;
	struct uniqtype *t = __liballocs_get_alloc_type(is);
	assert(t);
	printf("Type is: %s\n", NAME_FOR_UNIQTYPE(t));
	return 0;
}
