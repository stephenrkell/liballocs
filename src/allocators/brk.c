#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
// #include <fcntl.h>	 // problem with raw-syscalls conflict
int open(const char *, int, ...);
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include "relf.h"
#include "maps.h"
#include "liballocs_private.h"
#include "raw-syscalls-defs.h"
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

static void create_brk_bigalloc(void *curbrk)
{
	assert(executable_mapping_bigalloc);
	// now create the brk bigalloc
	// what is the actual end of the data segment PHDR?
	struct link_map *exe_lment = get_highest_loaded_object_below(executable_mapping_bigalloc->begin);
	assert(exe_lment);
	ElfW(auxv_t) *at_phdr = auxv_xlookup(get_auxv((char **) environ, &at_phdr), AT_PHDR);
	ElfW(auxv_t) *at_phnum = auxv_xlookup(get_auxv((char **) environ, &at_phdr), AT_PHNUM);
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
		debug_printf(1, "think we have a data segment phdr %lx-%lx (vs %p-%p)\n",
			(unsigned long) phdr_loaded_addr,
			phdr_end_addr,
			executable_mapping_bigalloc->begin,
			executable_mapping_bigalloc->end);
		// assert that it's contained within the mapping sequence we know about
		assert(phdr_loaded_addr >= (uintptr_t) executable_mapping_bigalloc->begin);
		assert(phdr_end_addr <= (uintptr_t) executable_mapping_bigalloc->end);
		// found it.
		// so now we know where it ends. create the brk bigalloc where it leaves off
		__brk_bigalloc = __liballocs_new_bigalloc(
			(void*) phdr_end_addr,
			(uintptr_t) executable_mapping_bigalloc->end - phdr_end_addr,
			NULL, /* allocator_private */
			NULL, /* allocator_private_free */
			executable_mapping_bigalloc /* parent */,
			/* allocated_by */ &__brk_allocator
		);
	}
	assert(__brk_bigalloc);
	/* We expect the data segment's suballocator to be malloc.
	 * We could pre-ordain that, but for uniformity with other
	 * malloc arenas, we no longer do. The generic_malloc_index.h code
	 * expects to claim the arena by setting 'suballocator'.
	 * NOTE that there will also be a nested allocation under it, that is the
	 * static allocator's segment bigalloc. We don't consider the sbrk area
	 * to be a child of that; it's a sibling. FIXME: is this okay? */
	//__brk_bigalloc->suballocator = &__global_malloc_allocator;
}

static void update_brk(void *new_curbrk)
{
	/* If we haven't made the bigalloc yet, sbrk needs no action. */
	if (!executable_mapping_bigalloc) return;
	assert(__brk_bigalloc);

	/* We also update the metadata. */
	if ((char*) new_curbrk < (char*) __brk_bigalloc->end)
	{
		/* We're contracting. Shrink ourselves first... */
		__liballocs_truncate_bigalloc_at_end(__brk_bigalloc, new_curbrk);
		assert(__brk_bigalloc->end == new_curbrk);
		/* ... THEN tell the mmap allocator to ensure we extend up to the new brk. */
		__mmap_allocator_notify_brk(new_curbrk);
	}
	else if ((char*) new_curbrk > (char*) __brk_bigalloc->end)
	{
		/* We're expanding. Grow the underlying mmap first... */
		__mmap_allocator_notify_brk(new_curbrk);
		/* ... THEN extend ourselves. */
		__liballocs_extend_bigalloc(__brk_bigalloc, new_curbrk);
	}
}

static _Bool initialized;
static _Bool trying_to_initialize;

void (  __attribute__((constructor(102))) __brk_allocator_init)(void)
{
	/* We don't need to be systrap-ready before it makes sense to initialize us.
	 * BUT our brk is liable to go out of sync with reality until we do.
	 * The wild address path should be enough to catch this, though, at least
	 * for queries. For things like malloc hooking, where our brk might edge
	 * into uncharted territory, we may need a slower path in arena_for_userptr.
	 */
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		void *curbrk = sbrk(0);
		/* Make sure the mmap allocator has created a big-enough mapping bigalloc. */
		__mmap_allocator_notify_brk(curbrk); // this is Ok even if mmap allocator is not fully init'd
		/* Do our init. */
		create_brk_bigalloc(curbrk);
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
	/* If the brk is growing, we need to first grow the mmap and
	* then grow brk. If it's contracting, do it the other way around. */
	if ((char*) __curbrk < (char*) new_curbrk)
	{
		__mmap_allocator_notify_brk(new_curbrk);
		update_brk(new_curbrk);
	}
	else
	{
		update_brk(new_curbrk);
		__mmap_allocator_notify_brk(new_curbrk);
	}
}

_Bool __brk_allocator_notify_unindexed_address(const void *mem)
{
	if (!__brk_bigalloc) return 0; // can't do anything
	void *old_sbrk = current_sbrk(); // what we *think* sbrk is
	void *new_sbrk = sbrk(0);
	update_brk(new_sbrk); // ... update it to what it actually is
	return ((uintptr_t) mem >= (uintptr_t) old_sbrk
		&& (uintptr_t) mem < (uintptr_t) new_sbrk);
}
