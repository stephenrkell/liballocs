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
#include <dlfcn.h>
#include <link.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "relf.h"
#include "vas.h"
#include "liballocs_private.h"
#include "pageindex.h"

static liballocs_err_t get_info(void * obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void **out_site);
	
struct allocator __stack_allocator = {
	.name = "stack",
	.is_cacheable = 0,
	.get_info = get_info
};

static _Bool trying_to_initialize;
static _Bool initialized;

static rlim_t stack_lim_cur;

struct suballocated_chunk_rec; // FIXME: remove once heap_index has been refactored

void __stack_allocator_init(void) __attribute__((constructor(101)));
void __stack_allocator_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		
		// grab the maximum stack size
		struct rlimit rlim;
		int rlret = getrlimit(RLIMIT_STACK, &rlim);
		if (rlret == 0)
		{
			stack_lim_cur = rlim.rlim_cur;
		}
		
		initialized = 1;
		trying_to_initialize = 0;
		
		/* NOTE: we don't add any mappings initially; we rely on the mmap allocator 
		 * to tell us about them. Similarly for new mappings, we rely on the 
		 * mmap trap logic to identify them, by their MAP_GROWSDOWN flag. */
	}
}

void __stack_allocator_notify_init_stack_mapping(void *begin, void *end)
{
	struct big_allocation *b = __liballocs_new_bigalloc(
		begin,
		(char*) end - (char*) begin,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: {
					.data_ptr = NULL,
					.free_func = NULL
				}
			}
		},
		NULL,
		&__stack_allocator
	);
	if (!b) abort();
	
	/* FIXME: is this necessarily right? a GROWSDOWN mapping might actually 
	 * be managed some other way. */
	b->suballocator = &__stackframe_allocator;
}

static liballocs_err_t get_info(void *obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void** out_site)
{
	abort();
}

_Bool __stack_allocator_notify_unindexed_address(const void *ptr)
{
	/* Do we claim it? */
	return 0;
}
