#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <liballocs.h>

int main(void)
{
	char *a1 = malloc(42);
	char *a2 = malloc(42 * sizeof (char));
	char *a3 = malloc(42 * sizeof (unsigned char));
	
	struct uniqtype *u1 = __liballocs_get_alloc_type(a1);
	assert(u1);
	struct uniqtype *u2 = __liballocs_get_alloc_type(a2);
	assert(u2);
	struct uniqtype *u3 = __liballocs_get_alloc_type(a3);
	assert(u3);
	
	printf("Got a1 as %s\n", NAME_FOR_UNIQTYPE(u1));
	printf("Got a2 as %s\n", NAME_FOR_UNIQTYPE(u2));
	printf("Got a3 as %s\n", NAME_FOR_UNIQTYPE(u3));
	
	return 0;
}
