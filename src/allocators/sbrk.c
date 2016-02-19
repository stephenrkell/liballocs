#define _GNU_SOURCE
#include "liballocs.h"

struct allocator __sbrk_allocator = {
	.k = HEAP
};
