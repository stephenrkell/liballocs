#define _GNU_SOURCE
#include "liballocs.h"

struct allocator __stack_allocator = {
	.k = STACK
};
