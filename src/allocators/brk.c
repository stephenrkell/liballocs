#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
// #include <fcntl.h>     // problem with raw-syscalls conflict
int open(const char *, int, ...);
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include "relf.h"
#include "maps.h"
#include "liballocs_private.h"
#include "raw-syscalls.h"
#include "dlbind.h"

// we always define a __curbrk -- it may override one in glibc, but fine
void *__curbrk;
static const void *last_caller;
static void *current_sbrk(void)
{
	return __curbrk;
}
void __brk_allocator_notify_brk(void *new_curbrk, const void *caller);

struct big_allocation *__brk_bigalloc __attribute__((visibility("hidden")));

static liballocs_err_t get_info(void *obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	if (out_type) *out_type = NULL;
	if (out_base) *out_base = __brk_bigalloc->begin;
	if (out_size) *out_size = (char*) __brk_bigalloc->end - (char*) __brk_bigalloc->begin;
	if (out_site) *out_site = last_caller;
	// success
	return NULL;
}
struct allocator __brk_allocator = {
	.name = "brk",
	.min_alignment = 1, /* brk can begin at any byte */
	.is_cacheable = 1,
	.get_info = get_info
	/* FIXME: meta-protocol implementation */
};

static void set_brk_bigalloc(void)
{
	assert(executable_mapping_sequence_bigalloc);
	// now create the brk bigalloc
	assert(!executable_mapping_sequence_bigalloc->first_child);
	// what is the actual end of the data segment PHDR?
	struct link_map *exe_lment = get_highest_loaded_object_below(executable_mapping_sequence_bigalloc->begin);
	assert(exe_lment);
	ElfW(auxv_t) *at_phdr = auxv_xlookup(get_auxv((const char **) environ, &at_phdr), AT_PHDR);
	ElfW(auxv_t) *at_phnum = auxv_xlookup(get_auxv((const char **) environ, &at_phdr), AT_PHNUM);
	ElfW(Phdr) *phdrs = (ElfW(Phdr) *) at_phdr->a_un.a_val;
	/* Our "data segment mapping" bigalloc is really a *mapping sequence*.
	 * It includes all segments of the executable. What is the "data segment"?
	 * It's really the thing that precedes the "program break"; in other words
	 * it's the LOAD phdr with the highest virtual address. */
	// FIXME: I probably mean "... that is contiguous with the program base address"
	// look for a writable phdr that begins at the data segment base
	ElfW(Phdr) *highest_vaddr_load_phdr = NULL;
	for (ElfW(Phdr) *p = phdrs; p < phdrs + at_phnum->a_un.a_val; ++p)
	{
		if (p->p_type == PT_LOAD
				&& p->p_memsz > 0
				&& (!highest_vaddr_load_phdr || p->p_vaddr > highest_vaddr_load_phdr->p_vaddr))
		{
			highest_vaddr_load_phdr = p;
		}
	}
	if (highest_vaddr_load_phdr)
	{
		uintptr_t phdr_loaded_addr = exe_lment->l_addr + highest_vaddr_load_phdr->p_vaddr;
		uintptr_t phdr_end_addr = phdr_loaded_addr + highest_vaddr_load_phdr->p_memsz;
		// assert that it's contained within the mapping sequence we know about
		assert(phdr_loaded_addr >= executable_mapping_sequence_bigalloc->begin);
		assert(phdr_end_addr <= executable_mapping_sequence_bigalloc->end);
		// found it.
		// so now we know where it ends. create the brk bigalloc where it leaves off
		uintptr_t brk_area_begin_addr = phdr_end_addr;
		__brk_bigalloc = __liballocs_new_bigalloc(
			(void*) brk_area_begin_addr,
			(uintptr_t) executable_mapping_sequence_bigalloc->end - brk_area_begin_addr,
			(struct meta_info) {
				.what = INS_AND_BITS
			},
			executable_mapping_sequence_bigalloc,
			/* allocated_by */ &__brk_allocator
		);
	}
	assert(__brk_bigalloc);
	/* We expect the data segment's suballocator to be malloc, so pre-ordain that.
	 * NOTE that there will also be a nested allocation under it, that is the
	 * static allocator's segment bigalloc. We don't consider the sbrk area
	 * to be a child of that; it's a sibling. FIXME: is this okay? */
	__brk_bigalloc->suballocator = &__generic_malloc_allocator;
}

static void update_brk(void *new_curbrk)
{
	/* If we haven't made the bigalloc yet, sbrk needs no action. */
	if (!executable_mapping_sequence_bigalloc) return;
	/* Tell the mmap allocator to ensure we extend up to the new brk. */
	__mmap_allocator_notify_brk(new_curbrk);
	assert(executable_mapping_sequence_bigalloc);
	assert((char*) executable_mapping_sequence_bigalloc->end >= (char*) new_curbrk);
	assert(__brk_bigalloc);

	/* We also update the metadata. */
	if ((char*) new_curbrk < (char*) __brk_bigalloc->end)
	{
		/* We're contracting. */
		__liballocs_truncate_bigalloc_at_end(__brk_bigalloc, new_curbrk);
	}
	else if ((char*) new_curbrk > (char*) __brk_bigalloc->end)
	{
		/* We're expanding. */
		__liballocs_extend_bigalloc(__brk_bigalloc, new_curbrk);
	}
}

static _Bool initialized;
static _Bool trying_to_initialize;

void __brk_allocator_init(void) __attribute__((constructor(101)));
void __brk_allocator_init(void)
{
	// we are initialized by the mmap allocator
	if (!__mmap_allocator_is_initialized()) return;
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		set_brk_bigalloc();
		update_brk(sbrk(0));
		initialized = 1;
		trying_to_initialize = 0;
	}
}

void __brk_allocator_notify_brk(void *new_curbrk, const void *caller)
{
	if (!initialized)
	{
		/* HMM. This is called in a signal context so it's probably not
		 * safe to just do the init now. But we don't start taking traps until
		 * we're initialized, so that's okay. BUT see the note in
		 * __mmap_allocator_init... before we're initialized, we need
		 * another mechanism to probe for brk updates. */
		return;
	}
	last_caller = caller;
	update_brk(new_curbrk);
}

_Bool __brk_allocator_notify_unindexed_address(void *mem)
{
	if (!__brk_bigalloc) return 0; // can't do anything
	void *old_sbrk = current_sbrk(); // what we *think* sbrk is
	void *new_sbrk = sbrk(0);
	update_brk(new_sbrk); // ... update it to what it actually is
	return ((char *) mem >= (char*) old_sbrk
		&& (char *) mem < (char *) new_sbrk);
}
