#include <stdlib.h>

int *dso_malloc_caller(size_t sz)
{
	int *chunk = malloc(sz);
	return chunk;
}
