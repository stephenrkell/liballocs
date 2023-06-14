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
#include "librunt.h"
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
	assert(executable_end_addr);
	/* Is the executable contiguous with the program break? If not, we have another
	 * puzzle on our hands.
	 * I had hoped we could simply check for an equality, that
	 * curbrk == executable_mapping_bigalloc->end
	 *
	 * i.e. that we are running early enough that brk has not yet moved
	 * from its initial value, which I expect to be the end of the data segment.
	 * PROBLEM: the brk can be set to a wacky address.

	 55616a1a9000-55616a1aa000 rw-p 00000000 08:07 3639623                    /var/local/stephen/work/devel/liballocs.git/tests/alloca/alloca
	 55616a1aa000-55616a1ab000 r-xp 00001000 08:07 3639623                    /var/local/stephen/work/devel/liballocs.git/tests/alloca/alloca
	 55616a1ab000-55616a1ac000 r--p 00002000 08:07 3639623                    /var/local/stephen/work/devel/liballocs.git/tests/alloca/alloca
	 55616a1ac000-55616a1ad000 r--p 00002000 08:07 3639623                    /var/local/stephen/work/devel/liballocs.git/tests/alloca/alloca
	 55616a1ad000-55616a1ae000 rw-p 00003000 08:07 3639623                    /var/local/stephen/work/devel/liballocs.git/tests/alloca/alloca
	 7f62bcb3d000-7f62fcb3d000 rw-p 00000000 00:00 0
	 (gdb) print curbrk
	 $10 = (void *) 0x55616a6ff000

	 * ... i.e. it's far from the end of the data segment (according to maps!) but
	 * hasn't been used yet. What does the ELF file say about the end of the segment?
	 * In my example, test case 'alloca''s entry point is 0x55616a1aa340 which is vaddr 0x1340
	 * and its load address is      0x55616a1a9000
	 * and data segment filesz + memsz is 03d60 + 03e8  so vaddr 0x4148 so addr 0x55616a1ad148
	 * which is hundreds of kB distant from the curbrk value.
	 * However, if I run in gdb, the equality does hold!
	 555555558000-555555559000 rw-p 00003000 08:07 3639623                    /var/local/stephen/work/devel/liballocs.git/tests/alloca/alloca
	                 ^- end of executable_mapping_bigalloc: curbrk points here!
	 * This suggests it may be an ASLR thing and the kernel has inserted
	 * a random amount of unmapped space at the end of the data segment. So let's
	 * tolerate a reasonable amount of space here.
	 */
	struct big_allocation *mapping_b = __lookup_bigalloc_top_level(curbrk);
	if (!mapping_b)
	{
		mapping_b = __liballocs_find_mapping_below(curbrk);
		if (!mapping_b)
		{
			write_string("liballocs panic: nothing mapped below curbrk\n");
			abort();
		}
		// we want to extend it to cover curbrk; is this sensible?
		ssize_t gap = (intptr_t) curbrk - (intptr_t) mapping_b->end;
		if (gap >= 0 && gap < (BIGGEST_SANE_USER_ALLOC>>1)) /* allow up to 2GB! too generous? */
		{
			// also check nothing is mapped in the gap?
			// If we scan a 2GB window of pageindex, we might allocate
			// 2bytes * 2^19  i.e. 1MB of memory. That is too much.
			// This is why we thread a linked list through the top-level bigallocs,
			// to allow walking them in address order.
			// (Already memset_bigalloc will do the check, but only in debug mode.)
			struct big_allocation *next = BIDX(mapping_b->next_sib);
			if (!(
				!next || (uintptr_t) next->begin >= (uintptr_t) curbrk)
			)
			{
				write_string("liballocs panic: something occupying the (<2GB) gap between "
					"curbrk and executable data segment\n");
				abort();
			}
		}
	}
	assert(!brk_mapping_bigalloc);
	brk_mapping_bigalloc = mapping_b;
	/* We want the brk area to begin where the attached program binary leaves
	 * off. Is there a file under the mapping? FIXME: what if file bigallocs
	 * have not been created yet? */
	assert(brk_mapping_bigalloc);
	/* Look for a file underneath this bigalloc. Will we have created the files yet?
	 * Probably not. For now we simply create the brk bigalloc from the current
	 * brk value to the end of the mapping. When we create a file bigalloc we will
	 * notice the brk and snap its beginning back to the end of the data segment. */
	void *brk_base_upper_bound = curbrk;
	ssize_t size = (uintptr_t) brk_mapping_bigalloc->end - (uintptr_t) brk_base_upper_bound;
	if (!(size > 0))
	{
		if (size < 0) 
		{
			// ensure the brk mapping bigalloc is at least as big as we need it to be
			_Bool ret = __liballocs_extend_bigalloc(brk_mapping_bigalloc,
				brk_base_upper_bound);
			size = (uintptr_t) brk_mapping_bigalloc->end - (uintptr_t) brk_base_upper_bound;
		}
		if (size == 0)
		{
			void *ret = sbrk(1);
			if (ret == NULL) abort();
			curbrk += 1;
			__mmap_allocator_notify_brk(curbrk);
			size = (uintptr_t) brk_mapping_bigalloc->end - (uintptr_t) brk_base_upper_bound;
		}
	}
	assert(size > 0);
	__brk_bigalloc = __liballocs_new_bigalloc(
		brk_base_upper_bound,
		size,
		NULL, /* allocator_private */
		NULL, /* allocator_private_free */
		brk_mapping_bigalloc /* parent */,
		/* allocated_by */ &__brk_allocator
	);
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
	if (!brk_mapping_bigalloc) return;
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
