#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "liballocs.h"

extern int end;

int main(void)
{
	void *mem = malloc(42);
	assert(mem);
	printf("main is at %p\n", main);
	void *allocsite = __liballocs_get_alloc_site(mem);
	assert(allocsite);
	printf("Got allocsite: %p\n", allocsite);
	assert((char*) allocsite >= (char*) main &&
			(char*) allocsite < (char*) &end);
	allocsite_id_t id = __liballocs_allocsite_id(allocsite);
	printf("Our allocsite id is %u\n", (unsigned) id);
	void *retrieved_allocsite = __liballocs_allocsite_by_id(id);
	printf("Retrieved allocsite with id is %p\n", retrieved_allocsite);
	assert(retrieved_allocsite == allocsite);
	return 0;
}
