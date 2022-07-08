#include <stdlib.h>
#include "liballocs.h"

int *dso_malloc_caller(size_t);

int main(void)
{
	int *chunk = dso_malloc_caller(42 * sizeof (int));
	struct uniqtype *u = __liballocs_get_alloc_type(chunk);
	assert(u);
	chunk[0] = 42;
	return chunk[1];
}
