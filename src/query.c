#define _GNU_SOURCE
#include <stdio.h>
#include "liballocs.h"
#include "liballocs_private.h"
#include "generic_malloc_index.h"

/* Effectively an OOL copy of our private inline, with a suitable name and visibility.
 * We undef if because generic_malloc_index.h creates an alias for use inside the liballocs DSO,
 * and we are right here trying to define a bona fide definition (never to be used in the DSO,
 * i.e. where that alias is in scope). See the comment in generic_malloc_index.h. */
#undef __liballocs_extract_and_output_alloc_site_and_type
__attribute__((visibility("protected")))
liballocs_err_t __liballocs_extract_and_output_alloc_site_and_type(
    struct insert *p_ins,
    struct uniqtype **out_type,
    void **out_site
)
{
	return extract_and_output_alloc_site_and_type(p_ins, out_type, out_site);
}

#ifdef __liballocs_get_base
#undef __liballocs_get_base
#endif
#ifdef __liballocs_get_alloc_base
#undef __liballocs_get_alloc_base
#endif
void *
__liballocs_get_base(void *obj)
{
	const void *out;
	/* Try the cache first. */
	struct __liballocs_memrange_cache_entry_s *hit =
		__liballocs_memrange_cache_lookup_notype(&__liballocs_ool_cache,
			obj, 0);
	/* We only want depth-0 cached memranges, i.e. leaf-level. */
	if (hit && hit->depth == 0) return (void*) hit->obj_base;
	/* No hit, so do the full query. */
	size_t sz = 0;
	struct uniqtype *t = NULL;
	struct allocator *a = NULL;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, &a, &out,
		&sz, NULL, NULL);
	if (err && err != &__liballocs_err_unrecognised_alloc_site) return NULL;
	/* We can cache the alloc base and size. */
	if (a && a->is_cacheable) __liballocs_cache_with_type(&__liballocs_ool_cache,
		out, (char*) out + sz, t ? t : pointer_to___uniqtype____uninterpreted_byte,
		0, 1, out);
	return (void*) out;
}
void *__liballocs_get_alloc_base(void *obj) __attribute__((alias("__liballocs_get_base")));
void *alloc_get_base(void *obj) __attribute__((alias("__liballocs_get_base")));

void *
__liballocs_get_alloc_base_with_fill(void *obj, struct allocator **out_a, /*bigalloc_num_t*/ unsigned short *out_num)
{
	const void *out;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, out_a, &out,
		NULL, NULL, NULL);
	if (err) return NULL;
	*out_num = pageindex[PAGENUM(obj)]; /* FIXME: should also check it's precise */
	return (void*) out;
}

#ifdef __liballocs_get_type
#undef __liballocs_get_type
#endif
struct uniqtype * 
__liballocs_get_type(void *obj)
{
	struct uniqtype *out;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, NULL, NULL, 
		NULL, &out, NULL);
	if (err) return NULL;
	return out;
}
#ifdef __liballocs_get_alloc_type
#undef __liballocs_get_alloc_type
#endif
struct uniqtype *__liballocs_get_alloc_type(void *obj) __attribute__((alias("__liballocs_get_type")));

struct uniqtype *
__liballocs_get_alloc_type_with_fill(void *obj, struct allocator **out_a, /*bigalloc_num_t*/ unsigned short *out_num)
{
	struct uniqtype *out;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, out_a, NULL,
		NULL, &out, NULL);
	if (err) return NULL;
	*out_num = pageindex[PAGENUM(obj)]; /* FIXME: should also check it's precise */
	return out;
}

struct uniqtype * 
__liballocs_get_outermost_type(void *obj)
{
	return __liballocs_get_alloc_type(obj);
}
struct uniqtype *
alloc_get_type(void *obj) __attribute__((alias("__liballocs_get_outermost_type")));

struct uniqtype * 
__liballocs_get_inner_type(void *obj, unsigned skip_at_bottom)
{
	struct allocator *a = NULL;
	const void *alloc_start;
	size_t alloc_size_bytes;
	struct uniqtype *u = NULL;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj,
		&a,
		&alloc_start,
		&alloc_size_bytes,
		&u,
		NULL);
	
	if (__builtin_expect(err != NULL, 0)) goto failed;
	unsigned target_offset_within_uniqtype = (char*) obj - (char*) alloc_start;
	if (u->make_precise)
	{
		/* FIXME: should really do a fuller treatment of make_precise, to allow e.g. */
		/* returning a fresh uniqtype into a buffer, and (even) passing mcontext. */
		u = u->make_precise(u,
			NULL, 0,
			(void*) obj, (void*) alloc_start, alloc_size_bytes, __builtin_return_address(0),
			NULL);
		/* FIXME: now ask the meta-alloc protocol to update that object's metadata to this type. */
	}
	
	/* Descend the subobject hierarchy until we can't descend any more. */
	_Bool success = 1;
	struct uniqtype *cur_containing_uniqtype = NULL;
	struct uniqtype_rel_info *cur_contained_pos = NULL;
	while (success)
	{
		success = __liballocs_first_subobject_spanning(
				&target_offset_within_uniqtype, &u, &cur_containing_uniqtype,
				&cur_contained_pos);
	}
	
	return (skip_at_bottom == 0) ? u
		 : (skip_at_bottom == 1) ? cur_containing_uniqtype
		 : NULL; // HACK, horrible, FIXME etc.
failed:
	return NULL;
}

void
__liballocs_set_alloc_type(void *obj, const struct uniqtype *type)
{
	struct big_allocation *maybe_the_allocation;
	struct allocator *a = __liballocs_leaf_allocator_for(obj,
		&maybe_the_allocation);
	if (!a || !a->set_type)
	{
		debug_printf(1, "Failed to set type for object at %p", obj);
		return;
	}
	a->set_type(maybe_the_allocation, obj, (struct uniqtype *) type);
	assert(__liballocs_get_alloc_type(obj) == type);
}

const void *
__liballocs_get_alloc_site(void *obj)
{
	const void *alloc_site = NULL;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, NULL, NULL, 
		NULL, NULL, &alloc_site);
	return (void*) alloc_site;
}
const void *
alloc_get_site(void *obj) __attribute__((alias("__liballocs_get_alloc_site")));

unsigned long
__liballocs_get_alloc_size(void *obj)
{
	unsigned long alloc_size;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, NULL, NULL, 
		&alloc_size, NULL, NULL);
	
	if (err && err != &__liballocs_err_unrecognised_alloc_site) return 0;
	return alloc_size;
}
unsigned long
alloc_get_size(void *obj) __attribute__((alias("__liballocs_get_alloc_size")));

struct allocator *
__liballocs_get_leaf_allocator(void *obj)
{
	struct allocator *a = NULL;
	struct liballocs_err *err = __liballocs_get_alloc_info(obj, &a, NULL, 
		NULL, NULL, NULL);
	// HACK: we can still return an allocator even if we didn't find the
	// object... this will be a hack until we refactor our error reporting
	// to be more allocator-agnostic
	if (err && err != &__liballocs_err_unrecognised_alloc_site
			&& err != &__liballocs_err_unrecognised_static_object) return NULL;
	// FIXME: I think these single-return functions should set errno,
	// for an errno value recorded in the error structure. But is there
	// an appropriate errno value for, say, 'unrecognised static object'?
	// ENOENT?
	return a;
}
struct allocator *
alloc_get_allocator(void *obj) __attribute__((alias("__liballocs_get_leaf_allocator")));

struct mapping_entry *__liballocs_get_memory_mapping(const void *obj,
		struct big_allocation **maybe_out_bigalloc)
{
	struct big_allocation *the_bigalloc = __lookup_bigalloc_top_level(obj);
	if (!the_bigalloc) return NULL;
	assert(the_bigalloc->allocated_by == &__mmap_allocator);
	struct mapping_sequence *seq = the_bigalloc->allocator_private;
	if (!seq)
	{
		/* It's a pool belonging to our own dlmalloc. HMM. Do we pretend it
		 * doesn't exist? */
		return NULL;
	}
	struct mapping_entry *found = __mmap_allocator_find_entry(obj, seq);
	if (found)
	{
		if (maybe_out_bigalloc) *maybe_out_bigalloc = the_bigalloc;
		return found;
	}
	return NULL;
}

/* A basic API for access to "allocator-specific metadata" (see liballocs.h). */
void *__liballocs_get_specific_by_allocator(const void *obj,
		struct allocator *a, struct uniqtype **out_specific_type)
{
	void *start = NULL;
	struct big_allocation *b = __lookup_bigalloc_from_root(obj, a, &start);
	if (b) return b->allocator_private; /* FIXME: also output out_specific_type.
	* For this we will have to delegate to the underlying allocator. */
	return NULL;
}


/* Utility code. Suspiciously convenient for bzip2. */
int __liballocs_add_type_to_block(void *block, struct uniqtype *t)
{
	struct big_allocation *b = NULL;
	struct allocator *a = __liballocs_leaf_allocator_for(block, &b);
	if (!a) return 1;
	struct uniqtype *old_type = NULL;
	void *base;
	size_t sz;
	/* CARE: the bigalloc 'b' is not necessarily the allocation. It might
	 * be the containing bigalloc (test: b->allocated_by == a). Some calls
	 * want the bigalloc whether or not it's the allocation, and some
	 * calls are happy with NULL and want it only if it *is* the allocation.
	 * get_info really wants the bigalloc. */
	liballocs_err_t err = a->get_info(block, b, &old_type, &base, &sz, NULL);
	if (!old_type) return 2;
	if (old_type->make_precise) old_type = old_type->make_precise(old_type,
		NULL, 0, block, block, sz, __builtin_return_address(0), NULL);
	struct uniqtype *new_type = __liballocs_get_or_create_array_type(t, sz / t->pos_maxoff);
	if (!new_type) return 3;
	struct uniqtype *union_type = __liballocs_get_or_create_union_type(2,
		old_type,
		new_type
	);
	/* set_type is happy with NULL */
	err = a->set_type((b->allocated_by == a) ? b : NULL, block, union_type);
	assert(!err);
	struct uniqtype *got_t = __liballocs_get_alloc_type(block);
	assert(got_t == union_type);
	return 0;
}

/* Instantiate inlines from liballocs.h. */
extern inline struct liballocs_err *__liballocs_get_alloc_info(const void *obj, 
	struct allocator **out_allocator, const void **out_alloc_start,
	unsigned long *out_alloc_size_bytes,
	struct uniqtype **out_alloc_uniqtype, const void **out_alloc_site);
