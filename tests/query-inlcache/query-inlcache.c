#define _GNU_SOURCE
#include <stdio.h>
#include <liballocs.h>

extern unsigned short *pageindex; /* HACK until liballocs.h declares this sanely */
#define likely(cond) __builtin_expect(cond, 1)

int main(void)
{
	/* Query something. */
	for (int i = 0; i < 10; ++i)
	{
		struct uniqtype *u = __liballocs_get_alloc_type_inlcache(main);
		printf("Saw %p\n", u);
	}
	return 0;
}
