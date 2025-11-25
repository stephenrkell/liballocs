#define _GNU_SOURCE
#include <stdio.h>

/* If the malloc doesn't know the size of its own chunks, we have to
 * use a different approach to indexing it. Here we use a very stupid
 * method that suffices for the not-so-fully-featured malloc in glibc's
 * dynamic linker. It may be useful for other similar mallocs too. In
 * short it just keeps a linear sequence of records for every malloc
 * chunk. The sequence is append-only, except that the latest one may
 * be freed. They are kept sorted, although we only re-sort if a new
 * address is appended that is not strictly greater than the last one. */

#include "liballocs_private.h"
#include "linear_malloc_index.h"
#include "donald.h" /* for SYSTEM_LDSO_PATH */

extern struct allocator __ld_so_malloc_allocator;

static struct big_allocation *
ensure_big(void *addr, size_t size)
{
	abort();
}
static struct liballocs_err *
set_type(struct big_allocation *maybe_the_allocation, void *obj, struct uniqtype *new_type)
{
	abort();
}

struct linear_malloc_index_instance *ld_so_malloc_index_info;
static struct linear_malloc_index_instance *arena_info_for_userptr(struct allocator *ignored, void *userptr)
{
	return ld_so_malloc_index_info;
}
static struct linear_malloc_index_instance *ensure_arena_info_for_userptr(
	struct allocator *ignored,
	void *userptr)
{
	return arena_info_for_userptr(ignored, userptr);
}
static struct big_allocation *ensure_bigalloc_for_userptr(
	void *userptr);

/* This is not a typo. We will overwrite the orig_ pointers
 * that were snarfed by allocsld, in favour of our
 * malloc_creating_bigalloc et al. So keep a copy. But *those*
 * want to call the orig_*, so keep a copy.
 */
static void *(*orig_orig_malloc)(size_t);
static void *(*orig_orig_calloc)(size_t, size_t);
static void *(*orig_orig_realloc)(void *, size_t);
static void  (*orig_orig_free)(void*);

static void *malloc_creating_bigalloc(size_t sz)
{
	void *ret = orig_orig_malloc(sz);
	if (ret) ensure_bigalloc_for_userptr(ret);
	return ret;
}
static void *calloc_creating_bigalloc(size_t arg1, size_t arg2)
{
	void *ret = orig_orig_calloc(arg1, arg2);
	if (ret) ensure_bigalloc_for_userptr(ret);
	return ret;
}
static void *realloc_creating_bigalloc(void *ptr, size_t sz)
{
	void *ret = orig_orig_realloc(ptr, sz);
	if (ret) ensure_bigalloc_for_userptr(ret);
	return ret;
}
static void free_creating_bigalloc(void *ptr)
{
	// there may or may not already be a bigalloc -- worth creating one?
	// it's the arena we care about, not the chunk
	ensure_bigalloc_for_userptr(ptr);
	orig_orig_free(ptr);
}
static struct liballocs_err *linear_malloc_get_info(
	struct allocator *a,
	void *obj, struct big_allocation *deepest_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	struct big_allocation *arena;
	if (deepest_bigalloc->allocated_by == &__ld_so_malloc_allocator)
	{
		arena = BIDX(deepest_bigalloc->parent);
	}
	else arena = deepest_bigalloc;
	assert(arena);
	assert(arena->suballocator == &__ld_so_malloc_allocator);
	assert(arena->suballocator_private);
	assert(arena->suballocator_private == ld_so_malloc_index_info);
	struct linear_malloc_rec *found = find_linear_malloc_rec(obj,
		ld_so_malloc_index_info->recs, ld_so_malloc_index_info->nrecs,
		ld_so_malloc_index_info->nrecs_used);

	if (found)
	{
		struct insert *heap_info = insert_for_chunk_and_caller_usable_size(
			found->addr, found->caller_requested_size + found->padding_to_caller_usable_size); // FIXME: wrong size here?
		if (out_base) *out_base = found->addr;
		if (out_size) *out_size = found->caller_requested_size;
		if (out_type && INSERT_IS_WITH_TYPE(heap_info)) *out_type = (struct uniqtype *) UNIQTYPE_UNSHIFT_FROM_INSERT(heap_info);
		if (out_site && !INSERT_IS_WITH_TYPE(heap_info)) *out_site = (void*) (uintptr_t) heap_info->initial.alloc_site;
		return NULL;
	}
	return &__liballocs_err_unindexed_heap_object;
}

static struct liballocs_err *get_info(
	void *obj, struct big_allocation *maybe_the_allocation,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	return linear_malloc_get_info(&__ld_so_malloc_allocator,
		obj, maybe_the_allocation,
		out_type, out_base, out_size, out_site);
}

struct big_allocation *__ld_so_brk_bigalloc __attribute__((visibility("hidden")));
void *ld_so_nominal_caller_address; // which PC do we claim created us?
static liballocs_err_t brk_get_info(void *obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site)
{
	if (!__ld_so_brk_bigalloc) abort(); // we should not be called
	if (out_type) *out_type = NULL;
	if (out_base) *out_base = __ld_so_brk_bigalloc->begin;
	if (out_size) *out_size = (char*) __ld_so_brk_bigalloc->end - (char*) __ld_so_brk_bigalloc->begin;
	if (out_site) *out_site = ld_so_nominal_caller_address;
	// success
	return NULL;
}
struct allocator __ld_so_brk_allocator = {
	.name = "ld.so brk area allocator",
	.min_alignment = 1, /* brk can begin at any byte */
	.is_cacheable = 1,
	.get_info = brk_get_info
	/* FIXME: meta-protocol implementation */
};

static struct big_allocation *ensure_bigalloc_for_userptr(void *addr)
{
	struct big_allocation *found_mapping_b
	= __lookup_bigalloc_from_root(addr , &__mmap_allocator, NULL);
	assert(found_mapping_b);
	if (!found_mapping_b) abort();
	/* The two expected cases are:
	 * - we fall within the ld.so's file mapping sequence but not within the file bigalloc
	 * - we are just some random mmap made not associated with any file.
	 * However, we may also be lumped in with some other file (see below).
	 * In any of these cases, there is no deeper bigalloc -- unless we
	 * created it ourselves!
	 */
	struct big_allocation *found_our_brk_b = __lookup_bigalloc_under_by_suballocator(
		addr, &__ld_so_malloc_allocator, found_mapping_b, NULL);
	if (found_our_brk_b) return found_our_brk_b;
	/* OK, not found so we need to create it. */
	const char *mapped_file
	 = ((struct mapping_sequence *) found_mapping_b->allocator_private)->filename;
	if (!mapped_file)
	{
		/* OK, it's a fully anonymous mapping sequence, so assume the whole mapping
		 * sequence is being used by the ld.so. FIXME: this seems unsound. */
		struct big_allocation *__ld_so_brk_bigalloc = __liballocs_new_bigalloc(
			found_mapping_b->begin,
			(uintptr_t) found_mapping_b->end - (uintptr_t) found_mapping_b->begin,
			NULL, /* allocator_private */
			NULL, /* allocator_private_free */
			found_mapping_b /* parent */,
			/* We effectively have a variant of the brk allocator here...
			 * it is the thing that claims the space between the ld.so file end
			 * and the end of the page. It allocates a singleton only. */
			/* allocated_by */ &__ld_so_brk_allocator
		);
		assert(__ld_so_brk_bigalloc);
		__ld_so_brk_bigalloc->suballocator = &__ld_so_malloc_allocator;
		assert(ld_so_malloc_index_info);
		__ld_so_brk_bigalloc->suballocator_private = ld_so_malloc_index_info;
		return __ld_so_brk_bigalloc;
	}
	// look for a file suballoc
	struct big_allocation *child_b = NULL;
	for (child_b = BIDX(found_mapping_b->first_child);
			child_b;
			child_b = BIDX(child_b->next_sib))
	{
		/* Any bigalloc we find underneath the mapping
		 * is a problem if it overlaps our query address. */
		if ((uintptr_t) child_b->begin <= (uintptr_t) addr && 
				(uintptr_t) child_b->end > (uintptr_t) addr)
		{
			abort();
		}

		if (child_b->allocated_by == &__static_file_allocator)
		{
			struct allocs_file_metadata *file = child_b->allocator_private;
			// OK, we expect this. Check our address falls after the end
			assert((uintptr_t) addr >= file->m.l->l_addr + (uintptr_t) file->m.vaddr_end);
			// Is this file the ld.so? that's really expected; warn if not
			if (0 != strcmp(file->m.filename, realpath_quick(SYSTEM_LDSO_PATH)))
			{
				debug_printf(0,
					"ld.so malloc pseudo-brk area spanning %p "
					"appears to be in mapping extension of unexpected object: "
					"%s (file %p-%p, area %p-%p)\n",
					addr, file->m.filename,
					child_b->begin, child_b->end, child_b->end, found_mapping_b->end);
			}
			// does this file have space in its mapping?
			size_t sz = (uintptr_t) BIDX(child_b->parent)->end - (uintptr_t) child_b->end;
			assert(sz > 0);
			struct big_allocation *__ld_so_brk_bigalloc = __liballocs_new_bigalloc(
				child_b->end,
				sz,
				NULL, /* allocator_private */
				NULL, /* allocator_private_free */
				BIDX(child_b->parent) /* parent */,
				/* We effectively have a variant of the brk allocator here...
				 * it is the thing that claims the space between the ld.so file end
				 * and the end of the page. It allocates a singleton only. */
				/* allocated_by */ &__ld_so_brk_allocator
			);
			assert(__ld_so_brk_bigalloc);
			__ld_so_brk_bigalloc->suballocator = &__ld_so_malloc_allocator;
			assert(ld_so_malloc_index_info);
			__ld_so_brk_bigalloc->suballocator_private = ld_so_malloc_index_info;
			return __ld_so_brk_bigalloc;
		}
	} // end for
	/* If we got here, there were no children or we got to the end of the loop
	 * without finding a static file bigalloc. That means we don't understand
	 * where the ld.so malloc is getting its memory from. */
	abort();
}

__attribute__((constructor(103)))
void __ld_so_malloc_allocator_init(void)
{
	static _Bool done_init = 0;

	if (done_init) return;
	// static_file_allocator should initialize our index ptr for us,
	// calculated from the ld.so's... if it doesn't, it means we have
	// no allocsld, so we have not instrumented ld.so malloc... warn and continue
	if (!ld_so_malloc_index_info)
	{
		debug_printf(0, "no allocsld, so assuming ld.so malloc is not instrumented\n");
		done_init = 1;
		return;
	}

	/* We need a hook s.t. when our detour malloc executes, it will
	 * ensure we have the bigalloc set up. That's a problem... it will
	 * create a new entry in the linear index but the code in allocsld has
	 * no way to create the bigalloc. We could overwrite its orig_* pointers
	 * so that once we're initialized, we add our layer of control. That feels messy...
	 * how do we get hold of the pointers? We could stash pointers to them in the
	 * linear index info.
	 *
	 * Can we delay until query time? No because we still get a "result", just
	 * in the mmap allocator only. We can't even chain a"wild address" handler
	 * (if we had handling/chaining of those in place, which we don't).
	 *
	 * OK, hooking the orig_* functions it is.
	 */
#define snarf_and_swap(frag) \
	orig_orig_ ## frag = *ld_so_malloc_index_info->p_orig_ ## frag; \
	*ld_so_malloc_index_info->p_orig_ ## frag = frag ## _creating_bigalloc;
	snarf_and_swap(malloc)
	snarf_and_swap(calloc)
	snarf_and_swap(realloc)
	snarf_and_swap(free)

	/* We need to set ourselves as the suballocator of... some bigalloc.
	 * does it exist, even?
	 * Previously I thought I could get away with creating at most two arenas here:
	 * - for the address at the end of the ld.so's memsz region
	 * - for whatever address is returned by __minimal_malloc(1)
	 * ... but that's not enough. E.g. I'm seeing some malloc chunks that appear to
	 * be in the brk of liballocs_preload.so. What has happened is that
	 * an anonymous mmap made by the ld.so for malloc purposes
	 * happens to have been placed contiguously after liballocs_preload.so
	 * so the mmap.c code has lumped it in. We should not do this lumping, but
	 * for the mappings we get from the /proc/pid/maps scan, we don't have
	 * much more to go on to get the lumping/bracketing right. For those made later
	 * by dlopen, we preload our own, so we could bracket them together somehow, and
	 * avoid augmenting unless we are in a bracketed sequence like that. Just a
	 * thread-local global that sets bracketing on and off would suffice.
	 * TODO: trapping the mmaps made by the ld.so, and/or doing this bracketing,
	 * seems worthwhile. For now we just tolerate the weird mmap nesting and issue
	 * a warning, above in ensure_arena_bigalloc_at
	 */

	// we walk the array of already-linearly-allocated malloc chunks
	for (unsigned i = 0; i < ld_so_malloc_index_info->nrecs_used; ++i)
	{
		ensure_bigalloc_for_userptr(ld_so_malloc_index_info->recs[i].addr);
	}
	// also a snarf a (probably) text address in the ld.so
	// what's something "guaranteed" to be in the ld.so? best guess: __tls_get_addr
	// FIXME: we should walk the link map ourselves I think and use l->l_ld
	extern void *__tls_get_addr();
	struct big_allocation *found_ld_so_file_b = __lookup_bigalloc_from_root(
		__tls_get_addr, &__static_file_allocator, NULL);
	assert(found_ld_so_file_b);
	ld_so_nominal_caller_address = found_ld_so_file_b->begin;

	done_init = 1;
}
struct allocator __ld_so_malloc_allocator = {
	.name = "ld.so malloc allocator",
	.get_info = get_info,
	.is_cacheable = 1,
	.ensure_big = ensure_big,
	.set_type = set_type,
	.free = NULL
};
