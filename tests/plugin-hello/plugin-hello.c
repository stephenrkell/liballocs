#include <stdio.h>
#include <stdlib.h>

void *fail_alloc(size_t sz)
{
	return NULL;
}

static void *static_fail_alloc(size_t sz)
{
	return NULL;
}

struct uniqtype;
extern struct uniqype __uniqtype__int;

int main(void)
{
	printf("Hello, world (%p, %p)!\n", static_fail_alloc, &__uniqtype__int);
	return 0;
}
