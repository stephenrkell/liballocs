#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <link.h>
#include "relf.h"
#include "liballocs_private.h"
#include "pageindex.h"

const char *env_asciiz_start;
const char **env_vector_start;
const char **env_vector_terminator;

const char *argv_asciiz_start;
const char **argv_vector_start;
const char **argv_vector_terminator;

ElfW(auxv_t) *auxv_array_start;
ElfW(auxv_t) *auxv_array_terminator;

void __auxv_allocator_init(void) __attribute__((constructor(101)));
void __auxv_allocator_init(void)
{
	
}

static liballocs_err_t get_info(void * obj, struct big_allocation *maybe_bigalloc, 
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void **out_site)
{
	abort();
}

struct allocator __auxv_allocator = {
	.name = "auxv",
	.is_cacheable = 1,
	.get_info = get_info
};
