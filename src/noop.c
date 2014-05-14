#include <stdio.h>

static const int __liballocs_is_initialized = 1;

int __liballocs_global_init(void)
{
	return 0;
}

const void *__liballocs_typestr_to_uniqtype(const void *r)
{
	return NULL;
}

void __index_deep_alloc(void *ptr, int level, unsigned size_bytes) {}
void __unindex_deep_alloc(void *ptr, int level) {}

