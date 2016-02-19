#define _GNU_SOURCE
#include "liballocs.h"

struct allocator __static_allocator = {
	.k = STATIC
};
