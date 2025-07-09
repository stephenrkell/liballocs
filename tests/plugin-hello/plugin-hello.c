#include <stdio.h>
#include <stdlib.h>
// struct uniqtype;
// extern struct uniqype __uniqtype__int;
#include "allocs.h"

void *fail_alloc(size_t sz)
{
	return NULL;
}
void *fail_calloc(size_t sz, size_t nmemb)
{
	return NULL;
}
void *fail_realloc(void *p, size_t sz)
{
	return NULL;
}

static void *static_fail_alloc(size_t sz)
{
	return NULL;
}

int main(void)
{
	printf("Hello, world (%p, %p)!\n", static_fail_alloc, &__uniqtype__int);
	printf("The type of main is '%s'\n", UNIQTYPE_NAME(__liballocs_get_alloc_type(main)));
	return 0;
}
