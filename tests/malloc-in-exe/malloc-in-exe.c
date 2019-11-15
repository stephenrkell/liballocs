#define _GNU_SOURCE
#include "liballocs.h"
#include <stdio.h>
#include <stdlib.h>

struct uniqtype;
extern struct uniqtype __uniqtype__int;

int main(void)
{
	printf("about to do user malloc()\n");
	void *a = malloc(sizeof (int));
	printf("addr is %p\n", a);
	
	struct uniqtype *t = __liballocs_get_alloc_type(a);
	printf("type is %p\n", t);
	// it's actually an array of 1 int
	assert(UNIQTYPE_IS_ARRAY_TYPE(t)
		&& UNIQTYPE_ARRAY_ELEMENT_TYPE(t) == &__uniqtype__int);
	
	return 0;
}
