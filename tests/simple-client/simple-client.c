#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <liballocs.h>

extern __thread void *__current_allocsite __attribute__((weak));

int main(void)
{
	void *handle = dlopen(NULL, RTLD_NOW);
	printf("Handle is %p\n", handle);
	assert(handle);

	memory_kind k;
	const void *alloc_start;
	unsigned long alloc_size;
	const void *alloc_uniqtype;
	const void *alloc_site;
	struct liballocs_err *err = __liballocs_get_alloc_info(handle, 
        &k, &alloc_start, &alloc_size, &alloc_uniqtype, &alloc_site);

	printf("Saw kind %d, start %p, size %ul, uniqtype %p, alloc site %p\n",
		(int) k, alloc_start, alloc_size, alloc_uniqtype, alloc_site);

	/* Check that referencing built-in uniqtypes works. */
	printf("__uniqtype__void is at %p\n", &__uniqtype__void);

	return 0;
}

