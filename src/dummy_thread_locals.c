#include <stdlib.h>

int __libcrunch_global_init(void);

__thread void *__current_allocsite;
__thread void *__current_allocfn;
__thread size_t __current_allocsz;
__thread int __currently_freeing;

void (__attribute__((constructor)) init)(void)
{
	__libcrunch_global_init();
}
