#include <stdio.h>
#include "liballocs.h"

int main(void)
{
#define THE_STRING "Hello, world!\n"
	const char *s = THE_STRING;
	puts(s);
	/* We don't know the type of string-literal data.
	 * We could perhaps infer it, from the relocation site
	 * if we know *its* type. Here we would need some data-
	 * -flow analysis to figure that out. Anyway, for now
	 * just assert that we can get its base and size. */
	void *base = __liballocs_get_alloc_base(s);
	assert(base);
	size_t size = __liballocs_get_alloc_size(s);
	assert(size >= sizeof THE_STRING);
	return 0;
}
