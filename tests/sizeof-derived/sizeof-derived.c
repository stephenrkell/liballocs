#define _GNU_SOURCE
#include <stdlib.h>
#include <liballocs.h>
#include <assert.h>

char blah[14];

int main(int argc)
{
	void *obj1 = malloc(argc * sizeof blah);
	struct uniqtype *u = __liballocs_get_alloc_type(obj1);
	assert(u);
	return 0;
}
