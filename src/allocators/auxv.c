#define _GNU_SOURCE
#include "liballocs.h"

struct allocator __auxv_allocator = {
	.k = STACK
};
