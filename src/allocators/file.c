#define _GNU_SOURCE
#include "liballocs.h"

struct allocator __file_allocator = {
	.k = MAPPED_FILE
};
