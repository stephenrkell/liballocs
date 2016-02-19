#define _GNU_SOURCE
#include "liballocs.h"

struct allocator __alloca_allocator = {
	.k = STACK
};
