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
#include "liballocs_private.h"
#include "pageindex.h"

struct allocator __sbrk_allocator = {
	.name = "sbrk",
	.is_cacheable = 1
};

static void *executable_end_addr;
static void *data_segment_start_addr;

// glibc-specific HACK!
extern void *__curbrk __attribute__((weak));
static void *current_sbrk(void)
{
	if (&__curbrk) return __curbrk;
	else return sbrk(0);
}

struct big_allocation *bigalloc;

void __sbrk_allocator_init(void) __attribute__((constructor(101)));
void __sbrk_allocator_init(void)
{
	/* Grab the executable's end address
	 * We used to try dlsym()'ing "_end", but that doesn't work:
	 * not all executables have _end and _begin exported as dynamic syms.
	 * Also, we don't want to call dlsym since it might not be safe to malloc.
	 * Instead, get the executable's program headers directly from the auxv. */
	
	char dummy;
	ElfW(auxv_t) *auxv = get_auxv((const char **) environ, &dummy);
	assert(auxv);
	ElfW(auxv_t) *ph_auxv = auxv_lookup(auxv, AT_PHDR);
	ElfW(auxv_t) *phnum_auxv = auxv_lookup(auxv, AT_PHNUM);
	assert(ph_auxv);
	assert(phnum_auxv);
	uintptr_t biggest_seen = 0;
	for (int i = 0; i < phnum_auxv->a_un.a_val; ++i)
	{
		ElfW(Phdr) *phdr = ((ElfW(Phdr)*) ph_auxv->a_un.a_val) + i;
		if (phdr->p_type == PT_LOAD)
		{
			/* We can round down to int because vaddrs *within* an object 
			 * will not be more than 2^31 from the object base. */
			uintptr_t max_plus_one = (int) (phdr->p_vaddr + phdr->p_memsz);
			if (max_plus_one > biggest_seen) biggest_seen = max_plus_one;
			
			if (!(phdr->p_flags & PF_X) &&
				(char*) phdr->p_vaddr > (char*) data_segment_start_addr)
			{
				data_segment_start_addr = (void*) phdr->p_vaddr;
			}
		}
	}
	executable_end_addr = (void*) biggest_seen;
	assert(executable_end_addr != 0);
	assert((char*) executable_end_addr < (char*) BIGGEST_SANE_EXECUTABLE_VADDR);
	
	/* We have a single bigalloc that extends between the end of the executable
	 * and the current program break. Or maybe the soft limit? HMM. */
	bigalloc = __liballocs_new_bigalloc(
		executable_end_addr,
		(char*) current_sbrk() - (char*) executable_end_addr,
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
		&__generic_malloc_allocator
	);
}

_Bool __sbrk_allocator_notify_unindexed_address(const void *ptr)
{
	/* Do we claim it? */
	if ((char*) ptr < (char*) current_sbrk()
			&& (char*) ptr >= (char*) executable_end_addr)
	{
		/* Update our bigalloc */
		return __liballocs_extend_bigalloc(bigalloc, current_sbrk());
	}
	return 0;
}
