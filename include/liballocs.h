#ifndef LIBALLOCS_H_
#define LIBALLOCS_H_

#ifndef _GNU_SOURCE
#warning "compilation unit is not _GNU_SOURCE; some features liballocs requires may not be available"
#endif

#ifdef __cplusplus
extern "C" {
typedef bool _Bool;
#define INLINE inline
#else
#define INLINE inline __attribute__((gnu_inline))
#endif

#include <sys/types.h>
#include <link.h>
#include "addrmap.h"
#include "heap_index.h"

extern void warnx(const char *fmt, ...); // avoid repeating proto
#ifndef NDEBUG
#include <assert.h>
#endif

#include "uniqtype.h"

#define ALLOC_IS_DYNAMICALLY_SIZED(all, as) \
	((all) != (as))

/* ** begin added for inline get_alloc_info */
#ifdef USE_REAL_LIBUNWIND
#include <libunwind.h>
#else
#include "fake-libunwind.h"
#endif

#include "addrmap.h"
#include "allocsmt.h"

void __liballocs_add_missing_maps(void);
enum object_memory_kind __liballocs_get_memory_kind(const void *obj);
void __liballocs_print_mappings_to_stream_err(void);

extern unsigned long __liballocs_aborted_stack;
extern unsigned long __liballocs_aborted_static;
extern unsigned long __liballocs_aborted_unknown_storage;
extern unsigned long __liballocs_hit_heap_case;
extern unsigned long __liballocs_hit_stack_case;
extern unsigned long __liballocs_hit_static_case;
extern unsigned long __liballocs_aborted_unindexed_heap;
extern unsigned long __liballocs_aborted_unrecognised_allocsite;

/* This API is a mess because there are three different classes of client. 
 * 
 * - extenders (libcrunch)
 * - direct clients (programs linking -lallocs and using our API) 
 * - weak clients (programs that can use liballocs, but run okay without)
 * 
 * The first two are the ones who'll instantiate our inlines and hence
 * generate references to our stuff. Weak clients will just (perhaps)
 * embed our CIL inlines. So it's only stuff in the liballocs_cil_inlines.h 
 * header file that they depend on. We deliberately keep this small, and
 * ideally it will run even without the noop library (i.e. never branch
 * out of line), but the linker currently won't generate the right code
 * without the noop library being present.
 */

// stuff for use by extenders only -- direct/weak clients shouldn't use this
struct addrlist;
int __liballocs_addrlist_contains(struct addrlist *l, void *addr);
void __liballocs_addrlist_add(struct addrlist *l, void *addr);
extern struct addrlist __liballocs_unrecognised_heap_alloc_sites;

Dl_info dladdr_with_cache(const void *addr); //VIS(protected);

extern void *__liballocs_main_bp; // beginning of main's stack frame

extern inline struct uniqtype *allocsite_to_uniqtype(const void *allocsite) __attribute__((gnu_inline,always_inline));
extern inline struct uniqtype * __attribute__((gnu_inline)) allocsite_to_uniqtype(const void *allocsite)
{
	if (!allocsite) return NULL;
	assert(__liballocs_allocsmt != NULL);
	struct allocsite_entry **bucketpos = ALLOCSMT_FUN(ADDR, allocsite);
	struct allocsite_entry *bucket = *bucketpos;
	for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
	{
		if (p->allocsite == allocsite)
		{
			return p->uniqtype;
		}
	}
	return NULL;
}

#define maximum_vaddr_range_size (4*1024) // HACK
struct frame_uniqtype_and_offset
{
	struct uniqtype *u;
	unsigned o;
};
extern inline struct frame_uniqtype_and_offset vaddr_to_uniqtype(const void *vaddr) __attribute__((gnu_inline,always_inline));
extern inline struct frame_uniqtype_and_offset __attribute__((gnu_inline)) vaddr_to_uniqtype(const void *vaddr)
{
	assert(__liballocs_allocsmt != NULL);
	if (!vaddr) return (struct frame_uniqtype_and_offset) { NULL, 0 };
	
	/* We chained the buckets to completely bypass the extra struct layer 
	 * that is frame_allocsite_entry.
	 * This means we can walk the buckets as normal.
	 * BUT we then have to fish out the frame offset.
	 * We do this with a "CONTAINER_OF"-style hack. 
	 * Then we return a *pair* of pointers. */
	
	struct allocsite_entry **initial_bucketpos = ALLOCSMT_FUN(ADDR, (void*)((intptr_t)vaddr | STACK_BEGIN));
	struct allocsite_entry **bucketpos = initial_bucketpos;
	_Bool might_start_in_lower_bucket = 1;
	do 
	{
		struct allocsite_entry *bucket = *bucketpos;
		for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
		{
			/* NOTE that in this memtable, buckets are sorted by address, so 
			 * we would ideally walk backwards. We can't, so we peek ahead at
			 * p->next. */
			if (p->allocsite <= vaddr && 
				(!p->next || ((struct allocsite_entry *) p->next)->allocsite > vaddr))
			{
				struct frame_allocsite_entry *e = (struct frame_allocsite_entry *) (
					(char*) p
					- offsetof(struct frame_allocsite_entry, entry)
				);
				assert(&e->entry == p);
				return (struct frame_uniqtype_and_offset) { p->uniqtype, e->offset_from_frame_base };
			}
			might_start_in_lower_bucket &= (p->allocsite > vaddr);
		}
		/* No match? then try the next lower bucket *unless* we've seen 
		 * an object in *this* bucket which starts *before* our target address. 
		 * In that case, no lower-bucket object can span far enough to reach our
		 * static_addr, because to do so would overlap the earlier-starting object. */
		--bucketpos;
	} while (might_start_in_lower_bucket && 
	  (initial_bucketpos - bucketpos) * allocsmt_entry_coverage < maximum_vaddr_range_size);
	return (struct frame_uniqtype_and_offset) { NULL, 0 };
}
#undef maximum_vaddr_range_size

#define maximum_static_obj_size (256*1024) // HACK
extern inline struct uniqtype *static_addr_to_uniqtype(const void *static_addr, void **out_object_start) __attribute__((gnu_inline,always_inline));
extern inline struct uniqtype * __attribute__((gnu_inline)) static_addr_to_uniqtype(const void *static_addr, void **out_object_start)
{
	assert(__liballocs_allocsmt != NULL);
	if (!static_addr) return NULL;
	struct allocsite_entry **initial_bucketpos = ALLOCSMT_FUN(ADDR, (void*)((intptr_t)static_addr | (STACK_BEGIN<<1)));
	struct allocsite_entry **bucketpos = initial_bucketpos;
	_Bool might_start_in_lower_bucket = 1;
	do 
	{
		struct allocsite_entry *bucket = *bucketpos;
		for (struct allocsite_entry *p = bucket; p; p = (struct allocsite_entry *) p->next)
		{
			/* NOTE that in this memtable, buckets are sorted by address, so 
			 * we would ideally walk backwards. We can't, so we peek ahead at
			 * p->next. */
			if (p->allocsite <= static_addr && 
				(!p->next || ((struct allocsite_entry *) p->next)->allocsite > static_addr)) 
			{
				if (out_object_start) *out_object_start = p->allocsite;
				return p->uniqtype;
			}
			might_start_in_lower_bucket &= (p->allocsite > static_addr);
		}
		/* No match? then try the next lower bucket *unless* we've seen 
		 * an object in *this* bucket which starts *before* our target address. 
		 * In that case, no lower-bucket object can span far enough to reach our
		 * static_addr, because to do so would overlap the earlier-starting object. */
		--bucketpos;
	} while (might_start_in_lower_bucket && 
	  (initial_bucketpos - bucketpos) * allocsmt_entry_coverage < maximum_static_obj_size);
	return NULL;
}
#undef maximum_vaddr_range_size
extern inline _Bool 
__attribute__((always_inline,gnu_inline))
__liballocs_first_subobject_spanning(
	signed *p_target_offset_within_uniqtype,
	struct uniqtype **p_cur_obj_uniqtype,
	struct uniqtype **p_cur_containing_uniqtype,
	struct contained **p_cur_contained_pos) __attribute__((always_inline,gnu_inline));
/* ** end added for inline get_alloc_info */

extern int __liballocs_debug_level;
extern _Bool __liballocs_is_initialized __attribute__((weak));

int __liballocs_global_init(void) __attribute__((weak));
// declare as const void *-returning, to simplify trumptr
const void *__liballocs_typestr_to_uniqtype(const char *typestr) __attribute__((weak));
void *__liballocs_my_typeobj(void) __attribute__((weak));

/* Uniqtypes for signed_char and unsigned_char and so on.
 * 
 * These are part of the API, BUT we don't want them to appear in the preload .so 
 * because then they can't be uniqued w.r.t. the executable.
 * So they go in a nasty .a, and the -lallocs .so is a linker script.
 * That way, an executable linking -lallocs will get them, together with
 * a reference to the liballocs .so. The .so does not define them.
 */

extern struct uniqtype __uniqtype__void/* __attribute__((weak))*/;
extern struct uniqtype __uniqtype__int/* __attribute__((weak))*/;
extern struct uniqtype __uniqtype__unsigned_int/* __attribute__((weak))*/;
extern struct uniqtype __uniqtype__signed_char/* __attribute__((weak))*/;
extern struct uniqtype __uniqtype__unsigned_char/* __attribute__((weak))*/;
extern struct uniqtype __uniqtype____FUN_FROM___FUN_TO_uint$64 /* __attribute__((weak))*/;
// #pragma 
#define __liballocs_uniqtype_of_typeless_functions __uniqtype____FUN_FROM___FUN_TO_uint$64
extern struct uniqtype __uniqtype__long_int;
extern struct uniqtype __uniqtype__unsigned_long_int;
extern struct uniqtype __uniqtype__short_int;
extern struct uniqtype __uniqtype__short_unsigned_int;
extern struct uniqtype __uniqtype____PTR_void;
extern struct uniqtype __uniqtype____PTR_signed_char;
extern struct uniqtype __uniqtype__float;
extern struct uniqtype __uniqtype__double;

#ifdef __GNUC__ // HACK. TODO: dollars are a good idea or not?

	 extern struct uniqtype __uniqtype__float$32;
	 extern struct uniqtype __uniqtype__float$64;
	 extern struct uniqtype __uniqtype__int$16;
	 extern struct uniqtype __uniqtype__int$32;
	 extern struct uniqtype __uniqtype__int$64;
	 extern struct uniqtype __uniqtype__uint$16;
	 extern struct uniqtype __uniqtype__uint$32;
	 extern struct uniqtype __uniqtype__uint$64;
	 extern struct uniqtype __uniqtype__signed_char$8;
	 extern struct uniqtype __uniqtype__unsigned_char$8;

	 extern struct uniqtype __uniqtype____PTR_int$32;
	 extern struct uniqtype __uniqtype____PTR_int$64;
	 extern struct uniqtype __uniqtype____PTR_uint$32;
	 extern struct uniqtype __uniqtype____PTR_uint$64;

	 extern struct uniqtype __uniqtype____PTR_signed_char$8;
	 
#endif

struct liballocs_err;
extern struct liballocs_err __liballocs_err_stack_walk_step_failure;
extern struct liballocs_err __liballocs_err_stack_walk_reached_higher_frame;
extern struct liballocs_err __liballocs_err_stack_walk_reached_top_of_stack;
extern struct liballocs_err __liballocs_err_unknown_stack_walk_problem;
extern struct liballocs_err __liballocs_err_unindexed_heap_object;
extern struct liballocs_err __liballocs_err_unrecognised_alloc_site;
extern struct liballocs_err __liballocs_err_unrecognised_static_object;
extern struct liballocs_err __liballocs_err_object_of_unknown_storage;

const char *__liballocs_errstring(struct liballocs_err *err);

/* We define a dladdr that caches stuff. */
Dl_info dladdr_with_cache(const void *addr);

#ifndef VIS
#define VIS(str) /* always default visibility */
#endif
#define DEFAULT_ATTRS VIS(protected)

/* Iterate over all uniqtypes in a given shared object. */
int __liballocs_iterate_types(void *typelib_handle, 
		int (*cb)(struct uniqtype *t, void *arg), void *arg) DEFAULT_ATTRS;
/* Our main API: query allocation information for a pointer */
extern inline struct liballocs_err *__liballocs_get_alloc_info(const void *obj, 
	memory_kind *out_memory_kind, const void **out_alloc_start,
	unsigned long *out_alloc_size_bytes,
	struct uniqtype **out_alloc_uniqtype, const void **out_alloc_site) DEFAULT_ATTRS __attribute__((gnu_inline,hot));
extern INLINE _Bool __liballocs_find_matching_subobject(signed target_offset_within_uniqtype,
	struct uniqtype *cur_obj_uniqtype, struct uniqtype *test_uniqtype, 
	struct uniqtype **last_attempted_uniqtype, signed *last_uniqtype_offset,
		signed *p_cumulative_offset_searched) DEFAULT_ATTRS __attribute__((hot));
/* Some inlines follow at the bottom. */

/* Public API for l0index / mappings. */
typedef struct mapping_flags
{
	unsigned kind:4; // UNKNOWN, STACK, HEAP, STATIC, ...
	unsigned r:1;
	unsigned w:1;
	unsigned x:1;
} mapping_flags_t;
_Bool mapping_flags_equal(mapping_flags_t f1, mapping_flags_t f2);
enum mapping_info_kind { DATA_PTR, INS_AND_BITS };
union mapping_info_union
{
	const void *data_ptr;
	struct 
	{
		struct insert ins;
		unsigned is_object_start:1;
		unsigned npages:20;
		unsigned obj_offset:7;
	} ins_and_bits;
};
struct mapping_info {
	struct mapping_flags f;
	enum mapping_info_kind what;
	/* PRIVATE i.e. change-prone impl details beyond here! */
	union mapping_info_union un;
};
/* Will be defined as an alias of mapping_lookup. */
struct mapping_info *__liballocs_mapping_lookup(const void *obj);

/* our own private assert */
extern inline void
__attribute__((always_inline,gnu_inline))
__liballocs_private_assert (_Bool cond, const char *reason, 
	const char *f, unsigned l, const char *fn)
{
#ifndef NDEBUG
	if (!cond) __assert_fail(reason, f, l, fn);
#endif
}

extern inline void 
__attribute__((always_inline,gnu_inline))
__liballocs_ensure_init(void)
{
	//__liballocs_private_assert(__liballocs_check_init() == 0, "liballocs init", 
	//	__FILE__, __LINE__, __func__);
	if (__builtin_expect(! & __liballocs_is_initialized, 0))
	{
		/* This means that we're not linked with libcrunch. 
		 * There's nothing we can do! */
		__liballocs_private_assert(0, "liballocs presence", 
			__FILE__, __LINE__, __func__);
	}
	if (__builtin_expect(!__liballocs_is_initialized, 0))
	{
		/* This means we haven't initialized.
		 * Try that now (it won't try more than once). */
		int ret = __liballocs_global_init();
		__liballocs_private_assert(ret == 0, "liballocs init", 
			__FILE__, __LINE__, __func__);
	}
}

/* Here "walk" is primarily walking "down". We do a little walking along,
 * in the case of unions. We do both iteratively. */
extern inline int 
__liballocs_walk_subobjects_spanning(
	const signed target_offset_within_u,
	struct uniqtype *u, 
	int (*cb)(struct uniqtype *spans, signed span_start_offset, unsigned depth,
		struct uniqtype *containing, struct contained *contained_pos, 
		signed containing_span_start_offset, void *arg),
	void *arg
	)
__attribute__((always_inline,gnu_inline));

inline int 
__liballocs_walk_subobjects_spanning_rec(
	signed accum_offset, unsigned accum_depth,
	const signed target_offset_within_u,
	struct uniqtype *u, 
	int (*cb)(struct uniqtype *spans, signed span_start_offset, unsigned depth,
		struct uniqtype *containing, struct contained *contained_pos, 
		signed containing_span_start_offset, void *arg),
	void *arg
	);

extern inline int 
__attribute__((always_inline,gnu_inline))
__liballocs_walk_subobjects_spanning(
	const signed target_offset_within_u,
	struct uniqtype *u, 
	int (*cb)(struct uniqtype *spans, signed span_start_offset, unsigned depth,
		struct uniqtype *containing, struct contained *contained_pos, 
		signed containing_span_start_offset, void *arg),
	void *arg
	)
{
	return __liballocs_walk_subobjects_spanning_rec(
		/* accum_offset */ 0, /* accum_depth */ 0, 
		target_offset_within_u, u, cb, arg);
}

inline int 
__liballocs_walk_subobjects_spanning_rec(
	signed accum_offset, unsigned accum_depth,
	const signed target_offset_within_u,
	struct uniqtype *u, 
	int (*cb)(struct uniqtype *spans, signed span_start_offset, unsigned depth, 
		struct uniqtype *containing, struct contained *contained_pos, 
		signed containing_span_start_offset, void *arg),
	void *arg
	)
{
	signed ret = 0;
	/* Calculate the offset to descend to, if any. This is different for 
	 * structs versus arrays. */
	if (u->is_array)
	{
		struct contained *element_contained_in_u = &u->contained[0];
		struct uniqtype *element_uniqtype = element_contained_in_u->ptr;
		signed div = target_offset_within_u / element_uniqtype->pos_maxoff;
		signed mod = target_offset_within_u % element_uniqtype->pos_maxoff;
		if (element_uniqtype->pos_maxoff != 0 && u->array_len > div)
		{
			signed skip_sz = div * element_uniqtype->pos_maxoff;
			__liballocs_private_assert(target_offset_within_u < u->pos_maxoff,
				"offset not within subobject", __FILE__, __LINE__, __func__);
			int ret = cb(element_uniqtype, accum_offset + skip_sz, accum_depth + 1u, 
				u, element_contained_in_u, accum_offset, arg);
			if (ret) return ret;
			// tail-recurse
			else return __liballocs_walk_subobjects_spanning_rec(
				accum_offset + (div * element_uniqtype->pos_maxoff), accum_depth + 1u,
				mod, element_uniqtype, cb, arg);
		} 
		else // element's pos_maxoff == 0 || num_contained <= target_offset / element's pos_maxoff 
		{}
	}
	else // struct/union case
	{
		signed num_contained = u->nmemb;
		int lower_ind = 0;
		int upper_ind = num_contained;
		while (lower_ind + 1 < upper_ind) // difference of >= 2
		{
			/* Bisect the interval */
			int bisect_ind = (upper_ind + lower_ind) / 2;
			__liballocs_private_assert(bisect_ind > lower_ind, "progress", __FILE__, __LINE__, __func__);
			if (u->contained[bisect_ind].offset > target_offset_within_u)
			{
				/* Our solution lies in the lower half of the interval */
				upper_ind = bisect_ind;
			} else lower_ind = bisect_ind;
		}

		if (lower_ind + 1 == upper_ind)
		{
			/* We found one offset */
			__liballocs_private_assert(u->contained[lower_ind].offset <= target_offset_within_u,
				"offset underapproximates", __FILE__, __LINE__, __func__);

			/* ... but we might not have found the *lowest* index, in the 
			 * case of a union. Scan backwards so that we have the lowest. 
			 * FIXME: need to account for the element size? Or here are we
			 * ignoring padding anyway? */
			signed offset = u->contained[lower_ind].offset;
			for (;
					lower_ind > 0 && u->contained[lower_ind-1].offset == offset;
					--lower_ind);
			// now we have the lowest lower_ind
			// scan forwards!
			for (int i_ind = lower_ind; i_ind < u->nmemb
					&& u->contained[i_ind].offset == offset;
					++i_ind)
			{
				if (target_offset_within_u < u->pos_maxoff)
				{
					int ret = cb(u->contained[i_ind].ptr, accum_offset + offset,
							accum_depth + 1u, u, &u->contained[i_ind], accum_offset, arg);
					if (ret) return ret;
					else
					{
						ret = __liballocs_walk_subobjects_spanning_rec(
							accum_offset + offset, accum_depth + 1u,
							target_offset_within_u - offset, u->contained[i_ind].ptr, cb, arg);
						if (ret) return ret;
					}
				}
			}
		}
		else /* lower_ind >= upper_ind */
		{
			// this should mean num_contained == 0
			__liballocs_private_assert(num_contained == 0,
				"no contained objects", __FILE__, __LINE__, __func__);
		}
	}
	
	return ret;
}

extern inline _Bool 
__liballocs_first_subobject_spanning(
	signed *p_target_offset_within_uniqtype,
	struct uniqtype **p_cur_obj_uniqtype,
	struct uniqtype **p_cur_containing_uniqtype,
	struct contained **p_cur_contained_pos) __attribute__((always_inline,gnu_inline));

extern inline _Bool 
__attribute__((always_inline,gnu_inline))
__liballocs_first_subobject_spanning(
	signed *p_target_offset_within_uniqtype,
	struct uniqtype **p_cur_obj_uniqtype,
	struct uniqtype **p_cur_containing_uniqtype,
	struct contained **p_cur_contained_pos)
{
	struct uniqtype *cur_obj_uniqtype = *p_cur_obj_uniqtype;
	signed target_offset_within_uniqtype = *p_target_offset_within_uniqtype;
	/* Calculate the offset to descend to, if any. This is different for 
	 * structs versus arrays. */
	if (cur_obj_uniqtype->is_array)
	{
		signed num_contained = cur_obj_uniqtype->array_len;
		struct uniqtype *element_uniqtype = cur_obj_uniqtype->contained[0].ptr;
		if (element_uniqtype->pos_maxoff != 0 && 
				num_contained > target_offset_within_uniqtype / element_uniqtype->pos_maxoff)
		{
			*p_cur_containing_uniqtype = cur_obj_uniqtype;
			*p_cur_contained_pos = &cur_obj_uniqtype->contained[0];
			*p_cur_obj_uniqtype = element_uniqtype;
			*p_target_offset_within_uniqtype = target_offset_within_uniqtype % element_uniqtype->pos_maxoff;
			return 1;
		} else return 0;
	}
	else // struct/union case
	{
		signed num_contained = cur_obj_uniqtype->nmemb;

		int lower_ind = 0;
		int upper_ind = num_contained;
		while (lower_ind + 1 < upper_ind) // difference of >= 2
		{
			/* Bisect the interval */
			int bisect_ind = (upper_ind + lower_ind) / 2;
			__liballocs_private_assert(bisect_ind > lower_ind, "bisection progress", 
				__FILE__, __LINE__, __func__);
			if (cur_obj_uniqtype->contained[bisect_ind].offset > target_offset_within_uniqtype)
			{
				/* Our solution lies in the lower half of the interval */
				upper_ind = bisect_ind;
			} else lower_ind = bisect_ind;
		}

		if (lower_ind + 1 == upper_ind)
		{
			/* We found one offset */
			__liballocs_private_assert(cur_obj_uniqtype->contained[lower_ind].offset <= target_offset_within_uniqtype,
				"offset underapproximates", __FILE__, __LINE__, __func__);

			/* ... but we might not have found the *lowest* index, in the 
			 * case of a union. Scan backwards so that we have the lowest. 
			 * FIXME: need to account for the element size? Or here are we
			 * ignoring padding anyway? */
			while (lower_ind > 0 
				&& cur_obj_uniqtype->contained[lower_ind-1].offset
					 == cur_obj_uniqtype->contained[lower_ind].offset)
			{
				--lower_ind;
			}
			*p_cur_contained_pos = &cur_obj_uniqtype->contained[lower_ind];
			*p_cur_containing_uniqtype = cur_obj_uniqtype;
			*p_cur_obj_uniqtype
			 = cur_obj_uniqtype->contained[lower_ind].ptr;
			/* p_cur_obj_uniqtype now points to the subobject's uniqtype. 
			 * We still have to adjust the offset. */
			*p_target_offset_within_uniqtype
			 = target_offset_within_uniqtype - cur_obj_uniqtype->contained[lower_ind].offset;

			return 1;
		}
		else /* lower_ind >= upper_ind */
		{
			// this should mean num_contained == 0
			__liballocs_private_assert(num_contained == 0,
				"no contained objects", __FILE__, __LINE__, __func__);
			return 0;
		}
	}
}

#ifndef __cplusplus
extern 
#endif
inline
_Bool 
__liballocs_find_matching_subobject(signed target_offset_within_uniqtype,
	struct uniqtype *cur_obj_uniqtype, struct uniqtype *test_uniqtype, 
	struct uniqtype **last_attempted_uniqtype, signed *last_uniqtype_offset,
		signed *p_cumulative_offset_searched)
#ifndef __cplusplus
__attribute__((gnu_inline))
#endif
;

#ifndef __cplusplus
extern 
__attribute__((gnu_inline))
#endif
inline
_Bool 
__liballocs_find_matching_subobject(signed target_offset_within_uniqtype,
	struct uniqtype *cur_obj_uniqtype, struct uniqtype *test_uniqtype, 
	struct uniqtype **last_attempted_uniqtype, signed *last_uniqtype_offset,
		signed *p_cumulative_offset_searched)
{
	if (target_offset_within_uniqtype == 0 && (!test_uniqtype || cur_obj_uniqtype == test_uniqtype)) return 1;
	else
	{
		/* We might have *multiple* subobjects spanning the offset. 
		 * Test all of them. */
		struct uniqtype *containing_uniqtype = NULL;
		struct contained *contained_pos = NULL;
		
		signed sub_target_offset = target_offset_within_uniqtype;
		struct uniqtype *contained_uniqtype = cur_obj_uniqtype;
		
		_Bool success = __liballocs_first_subobject_spanning(
			&sub_target_offset, &contained_uniqtype,
			&containing_uniqtype, &contained_pos);
		// now we have a *new* sub_target_offset and contained_uniqtype
		
		if (!success) return 0;
		
		if (p_cumulative_offset_searched) *p_cumulative_offset_searched += contained_pos->offset;
		
		if (last_attempted_uniqtype) *last_attempted_uniqtype = contained_uniqtype;
		if (last_uniqtype_offset) *last_uniqtype_offset = sub_target_offset;
		do {
			assert(containing_uniqtype == cur_obj_uniqtype);
			_Bool recursive_test = __liballocs_find_matching_subobject(
					sub_target_offset,
					contained_uniqtype, test_uniqtype, 
					last_attempted_uniqtype, last_uniqtype_offset, p_cumulative_offset_searched);
			if (__builtin_expect(recursive_test, 1)) return 1;
			// else look for a later contained subobject at the same offset
			signed subobj_ind = contained_pos - &containing_uniqtype->contained[0];
			assert(subobj_ind >= 0);
			assert(subobj_ind == 0 || subobj_ind < containing_uniqtype->nmemb);
			if (__builtin_expect(
					containing_uniqtype->nmemb <= subobj_ind + 1
					|| containing_uniqtype->contained[subobj_ind + 1].offset != 
						containing_uniqtype->contained[subobj_ind].offset,
				1))
			{
				// no more subobjects at the same offset, so fail
				return 0;
			} 
			else
			{
				contained_pos = &containing_uniqtype->contained[subobj_ind + 1];
				contained_uniqtype = contained_pos->ptr;
			}
		} while (1);
		
		assert(0);
	}
}

extern inline 
struct liballocs_err * 
__attribute__((always_inline,gnu_inline)) 
__liballocs_get_alloc_info
	(const void *obj, 
	memory_kind *out_memory_kind,
	const void **out_alloc_start,
	unsigned long *out_alloc_size_bytes,
	struct uniqtype **out_alloc_uniqtype, 
	const void **out_alloc_site) __attribute__((always_inline,gnu_inline));

extern inline 
struct liballocs_err *
__attribute__((always_inline,gnu_inline)) 
__liballocs_get_alloc_info
	(const void *obj, 
	memory_kind *out_memory_kind,
	const void **out_alloc_start,
	unsigned long *out_alloc_size_bytes, 
	struct uniqtype **out_alloc_uniqtype, 
	const void **out_alloc_site)
{
	struct liballocs_err *err = 0;

	memory_kind k = get_object_memory_kind(obj);
	if (__builtin_expect(k == UNKNOWN, 0))
	{
		k = __liballocs_get_memory_kind(obj);
		if (__builtin_expect(k == UNKNOWN, 0))
		{
			// still unknown? we have one last trick, if not blacklisted
			_Bool blacklisted = 0;//check_blacklist(obj);
			if (!blacklisted)
			{
				__liballocs_add_missing_maps();
				k = __liballocs_get_memory_kind(obj);
				if (k == UNKNOWN)
				{
					__liballocs_print_mappings_to_stream_err();
					// completely wild pointer or kernel pointer
					//debug_printf(1, "liballocs saw wild pointer %p from caller %p\n", obj,
					//	__builtin_return_address(0));
					//consider_blacklisting(obj);
				}
			}
		}
	}
	void *object_start = NULL;
	if (out_alloc_site) *out_alloc_site = 0; // will likely get updated later
	if (out_memory_kind) *out_memory_kind = k;
	/* These are shared between the heap case and the alloca-subcase of the stack case, 
	 * so we declare them here. */
	struct suballocated_chunk_rec *containing_suballoc;
	size_t alloc_chunksize;
	struct insert *heap_info;
	uintptr_t alloc_site_addr = 0;
	switch(k)
	{
		case STACK:
		{
			++__liballocs_hit_stack_case;
#define BEGINNING_OF_STACK (STACK_BEGIN - 1)
			// we want to walk a sequence of vaddrs!
			// how do we know which is the one we want?
			// we can get a uniqtype for each one, including maximum posoff and negoff
			// -- yes, use those
			/* We declare all our variables up front, in the hope that we can rely on
			 * the stack pointer not moving between getcontext and the sanity check.
			 * FIXME: better would be to write this function in C90 and compile with
			 * special flags. */
			unw_cursor_t cursor, saved_cursor, prev_saved_cursor;
			unw_word_t higherframe_sp = 0, sp, higherframe_bp = 0, bp = 0, ip = 0, higherframe_ip = 0, callee_ip __attribute__((unused));
			int unw_ret;
			unw_context_t unw_context;

			unw_ret = unw_getcontext(&unw_context);
			unw_init_local(&cursor, /*this->unw_as,*/ &unw_context);

			unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &higherframe_sp);
#ifndef NDEBUG
			unw_word_t check_higherframe_sp;
			// sanity check
#ifdef UNW_TARGET_X86
			__asm__ ("movl %%esp, %0\n" :"=r"(check_higherframe_sp));
#else // assume X86_64 for now
			__asm__("movq %%rsp, %0\n" : "=r"(check_higherframe_sp));
#endif
			assert(check_higherframe_sp == higherframe_sp);
#endif
			unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &higherframe_ip);

			_Bool at_or_above_main = 0;
			do
			{
				callee_ip = ip;
				prev_saved_cursor = saved_cursor;	// prev_saved_cursor is the cursor into the callee's frame 
													// FIXME: will be garbage if callee_ip == 0
				saved_cursor = cursor; // saved_cursor is the *current* frame's cursor
					// and cursor, later, becomes the *next* (i.e. caller) frame's cursor

				/* First get the ip, sp and symname of the current stack frame. */
				unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &ip); assert(unw_ret == 0);
				unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &sp); assert(unw_ret == 0); // sp = higherframe_sp
				// try to get the bp, but no problem if we don't
				unw_ret = unw_get_reg(&cursor, UNW_TDEP_BP, &bp); 
				_Bool got_bp = (unw_ret == 0);
				_Bool got_higherframe_bp = 0;
				/* Also do a test about whether we're in main, above which we want to
				 * tolerate unwind failures more gracefully. NOTE: this is just for
				 * debugging; we don't normally pay any attention to this. 
				 */
				at_or_above_main |= 
					(
						(got_bp && bp >= (uintptr_t) __liballocs_main_bp)
					 || (sp >= (uintptr_t) __liballocs_main_bp) // NOTE: this misses the in-main case
					);

				/* Now get the sp of the next higher stack frame, 
				 * i.e. the bp of the current frame. NOTE: we're still
				 * processing the stack frame ending at sp, but we
				 * hoist the unw_step call to here so that we can get
				 * the *bp* of the current frame a.k.a. the caller's bp 
				 * (without demanding that libunwind provides bp, e.g. 
				 * for code compiled with -fomit-frame-pointer). 
				 * This means "cursor" is no longer current -- use 
				 * saved_cursor for the remainder of this iteration!
				 * saved_cursor points to the deeper stack frame. */
				int step_ret = unw_step(&cursor);
				if (step_ret > 0)
				{
					unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &higherframe_sp); assert(unw_ret == 0);
					// assert that for non-top-end frames, BP --> saved-SP relation holds
					// FIXME: hard-codes calling convention info
					if (got_bp && !at_or_above_main && higherframe_sp != bp + 2 * sizeof (void*))
					{
						// debug_printf(2, "Saw frame boundary with unusual sp/bp relation (higherframe_sp=%p, bp=%p != higherframe_sp + 2*sizeof(void*))", 
						// 	higherframe_sp, bp);
					}
					unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &higherframe_ip); assert(unw_ret == 0);
					// try to get the bp, but no problem if we don't
					unw_ret = unw_get_reg(&cursor, UNW_TDEP_BP, &higherframe_bp); 
					got_higherframe_bp = (unw_ret == 0) && higherframe_bp != 0;
				}
				/* NOTE that -UNW_EBADREG happens near the top of the stack where 
				 * unwind info gets patchy, so we should handle it mostly like the 
				 * BEGINNING_OF_STACK case if so... but only if we're at or above main
				 * (and anyway, we *should* have that unwind info, damnit!).
				 */
				else if (step_ret == 0 || (at_or_above_main && step_ret == -UNW_EBADREG))
				{
					higherframe_sp = BEGINNING_OF_STACK;
					higherframe_bp = BEGINNING_OF_STACK;
					got_higherframe_bp = 1;
					higherframe_ip = 0x0;
				}
				else
				{
					// return value <1 means error

					err = &__liballocs_err_stack_walk_step_failure;
					goto abort_stack;
					break;
				}
				
				// useful variables at this point: sp, ip, got_bp && bp, 
				// higherframe_sp, higherframe_ip, 
				// callee_ip

				// now do the stuff
				
				/* NOTE: here we are doing one vaddr_to_uniqtype per frame.
				 * Can we optimise this, by ruling out some frames just by
				 * their bounding sps? YES, I'm sure we can. FIXME: do this!
				 * The difficulty is in the fact that frame offsets can be
				 * negative, i.e. arguments exist somewhere in the parent
				 * frame. */
				/* 0. if our target address is greater than higherframe_bp,
				 * -- i.e. *higher* in the stack than the top of the next frame 
				 * -- continue (it's in a frame we haven't yet reached!)
				 */
				if (got_higherframe_bp && (uintptr_t) obj > higherframe_bp)
				{
					continue;
				}
				
				// (if our target address is *lower* than sp, we'll abandon the walk, below)
				
				// 1. get the frame uniqtype for frame_ip
				struct frame_uniqtype_and_offset s = vaddr_to_uniqtype((void *) ip);
				struct uniqtype *frame_desc = s.u;
				if (!frame_desc)
				{
					// no frame descriptor for this frame; that's okay!
					// e.g. our liballocs frames should (normally) have no descriptor
					continue;
				}
				// 2. what's the frame base? it's the higherframe stack pointer
				unsigned char *frame_base = (unsigned char *) higherframe_sp;
				// 2a. what's the frame *allocation* base? It's the frame_base *minus*
				// the amount that s told us. 
				unsigned char *frame_allocation_base = frame_base - s.o;
				// 3. is our candidate addr between frame_allocation_base and that+posoff?
				if ((unsigned char *) obj >= frame_allocation_base
					&& (unsigned char *) obj < frame_allocation_base + frame_desc->pos_maxoff)
				{
					object_start = frame_allocation_base;
					if (out_alloc_start) *out_alloc_start = object_start;
					if (out_alloc_uniqtype) *out_alloc_uniqtype = frame_desc;
					if (out_alloc_site) *out_alloc_site = (void*)(intptr_t) ip; // HMM -- is this the best way to represent this?
					if (out_alloc_size_bytes) *out_alloc_size_bytes = frame_desc->pos_maxoff;
					goto out_success;
				}
				// have we gone too far? we are going upwards in memory...
				// ... so if our current frame (not higher frame)'s 
				// numerically lowest (deepest) addr 
				// is still higher than our object's addr, we must have gone past it
				if (frame_allocation_base > (unsigned char *) obj)
				{
					containing_suballoc = NULL;
					heap_info = lookup_object_info(obj, (void**) out_alloc_start, 
						&alloc_chunksize, &containing_suballoc);
					if (heap_info)
					{
						/* It looks like this is an alloca chunk, so proceed. */
						goto do_alloca_as_if_heap;
					}
					
					err = &__liballocs_err_stack_walk_reached_higher_frame;
					goto abort_stack;
				}

				assert(step_ret > 0 || higherframe_sp == BEGINNING_OF_STACK);
			} while (higherframe_sp != BEGINNING_OF_STACK);
			// if we hit the termination condition, we've failed
			if (higherframe_sp == BEGINNING_OF_STACK)
			{
				err = &__liballocs_err_stack_walk_reached_top_of_stack;
				goto abort_stack;
			}
		#undef BEGINNING_OF_STACK
		break; // end case STACK
		abort_stack:
			if (!err) err = &__liballocs_err_unknown_stack_walk_problem;
			++__liballocs_aborted_stack;
			return err;
		} // end case STACK
		case HEAP:
		{
			++__liballocs_hit_heap_case;
			/* For heap allocations, we look up the allocation site.
			 * (This also yields an offset within a toplevel object.)
			 * Then we translate the allocation site to a uniqtypes rec location.
			 * (For direct calls in eagerly-loaded code, we can cache this information
			 * within uniqtypes itself. How? Make uniqtypes include a hash table with
			 * initial contents mapping allocsites to uniqtype recs. This hash table
			 * is initialized during load, but can be extended as new allocsites
			 * are discovered, e.g. indirect ones.)
			 */
			containing_suballoc = NULL;
			heap_info = lookup_object_info(obj, (void**) out_alloc_start, 
					&alloc_chunksize, &containing_suballoc);
			if (!heap_info)
			{
				err = &__liballocs_err_unindexed_heap_object;
				++__liballocs_aborted_unindexed_heap;
				return err;
			}
			assert(get_object_memory_kind(heap_info) == HEAP
				|| get_object_memory_kind(heap_info) == UNKNOWN); // might not have seen that maps yet
			alloc_site_addr = heap_info->alloc_site;
			assert(!alloc_site_addr
				|| __liballocs_get_memory_kind((void*) alloc_site_addr) == STATIC
				|| (__liballocs_add_missing_maps(),
					 __liballocs_get_memory_kind((void*) alloc_site_addr) == STATIC));

			/* Now we have a uniqtype or an allocsite. For long-lived objects 
			 * the uniqtype will have been installed in the heap header already.
			 * This is the expected case.
			 */
		do_alloca_as_if_heap:
			;
			struct uniqtype *alloc_uniqtype;
			if (__builtin_expect(heap_info->alloc_site_flag, 1))
			{
				if (out_alloc_site) *out_alloc_site = NULL;
				/* Clear the low-order bit, which is available as an extra flag 
				 * bit. libcrunch uses this to track whether an object is "loose"
				 * or not. Loose objects have */
				alloc_uniqtype = (struct uniqtype *)((uintptr_t)(heap_info->alloc_site) & ~0x1ul);
			}
			else
			{
				/* Look up the allocsite's uniqtype, and install it in the heap info 
				 * (on NDEBUG builds only, because it reduces debuggability a bit). */
				uintptr_t alloc_site_addr = heap_info->alloc_site;
				void *alloc_site = (void*) alloc_site_addr;
				if (out_alloc_site) *out_alloc_site = alloc_site;
				alloc_uniqtype = allocsite_to_uniqtype(alloc_site/*, heap_info*/);
				/* Remember the unrecog'd alloc sites we see. */
				if (!alloc_uniqtype && alloc_site && 
						!__liballocs_addrlist_contains(&__liballocs_unrecognised_heap_alloc_sites, alloc_site))
				{
					__liballocs_addrlist_add(&__liballocs_unrecognised_heap_alloc_sites, alloc_site);
				}
#ifdef NDEBUG
				// install it for future lookups
				// FIXME: make this atomic using a union
				// Is this in a loose state? NO. We always make it strict.
				// The client might override us by noticing that we return
				// it a dynamically-sized alloc with a uniqtype.
				// This means we're the first query to rewrite the alloc site,
				// and is the client's queue to go poking in the insert.
				heap_info->alloc_site_flag = 1;
				heap_info->alloc_site = (uintptr_t) alloc_uniqtype /* | 0x0ul */;
#endif
			}

			if (out_alloc_size_bytes) *out_alloc_size_bytes = alloc_chunksize - sizeof (struct insert);
			
			// if we didn't get an alloc uniqtype, we abort
			if (!alloc_uniqtype) 
			{
				err = &__liballocs_err_unrecognised_alloc_site;
				if (__builtin_expect(k == HEAP, 1))
				{
					++__liballocs_aborted_unrecognised_allocsite;
				}
				else ++__liballocs_aborted_stack;
				return err;
			}
			// else output it
			if (out_alloc_uniqtype) *out_alloc_uniqtype = alloc_uniqtype;
			break;
		}
		case STATIC:
		{
			++__liballocs_hit_static_case;
//			/* We use a blacklist to rule out static addrs that map to things like 
//			 * mmap()'d regions (which we never have typeinfo for)
//			 * or uninstrumented libraries (which we happen not to have typeinfo for). */
//			_Bool blacklisted = check_blacklist(obj);
//			if (blacklisted)
//			{
//				// FIXME: record blacklist hits separately
//				err = &__liballocs_err_unrecognised_static_object;
//				++__liballocs_aborted_static;
//				goto abort;
//			}
			struct uniqtype *alloc_uniqtype = static_addr_to_uniqtype(obj, &object_start);
			if (out_alloc_uniqtype) *out_alloc_uniqtype = alloc_uniqtype;
			if (!alloc_uniqtype)
			{
				err = &__liballocs_err_unrecognised_static_object;
				++__liballocs_aborted_static;
//				consider_blacklisting(obj);
				return err;
			}
			
			// else we can go ahead
			if (out_alloc_start) *out_alloc_start = object_start;
			if (out_alloc_site) *out_alloc_site = object_start;
			if (out_alloc_size_bytes) *out_alloc_size_bytes = alloc_uniqtype->pos_maxoff;
			break;
		}
		case UNKNOWN:
		case MAPPED_FILE:
		default:
		{
			err = &__liballocs_err_object_of_unknown_storage;
			++__liballocs_aborted_unknown_storage;
			return err;
		}
	}
	
out_success:
	return NULL;
}

// extern inline 
// struct liballocs_err * 
// __attribute__((always_inline,gnu_inline)) 
// __liballocs_get_alloc_info
// 	(const void *obj, 
// 	memory_kind *out_memory_kind,
// 	const void **out_alloc_start,
// 	unsigned long *out_alloc_size_bytes,
// 	struct uniqtype **out_alloc_uniqtype, 
// 	const void **out_alloc_site) __attribute__((always_inline,gnu_inline));

/* We define a more friendly API for simple queries.
 * NOTE that we don't make these functions inline. They are still fast, internally,
 * because they make an inlined call to __liballocs_get_alloc_info.
 * BUT we don't want to make them inline themselves, because this complicates linking
 * to liballocs quite a bit. Specifically, if we inline them into callers, then 
 * callers need to link against lots of internals of liballocs which would otherwise
 * have hidden visibility. We would have to add mocked-up versions of all this stuff
 * to the noop library if we wanted this to work. Recall also that linking -lallocs does
 * *not* work! You really need to preload liballocs for it to work. */

// struct bounds {
// 	void *begin;
// 	void *end;
// };
// 
// extern inline 
// __attribute__((always_inline,gnu_inline)) 
// struct bounds 
// get_alloc_bounds(void *obj, struct uniqtype *type_bound)
// {
// 	/* We consider the pointer */
// }

struct uniqtype * 
__liballocs_get_alloc_type(void *obj);

struct uniqtype * 
__liballocs_get_outermost_type(void *obj);

struct uniqtype * 
__liballocs_get_type_inside(void *obj, struct uniqtype *t);

struct uniqtype * 
__liballocs_get_innermost_type(void *obj);


// struct uniqtype * 
// get_outermost_type(void *obj, struct uniqtype *bound)
// {
// 	
// }
// 
// void *
// get_alloc_site(void *obj)
// {
// 	
// }

#ifdef __cplusplus
} // end extern "C"
#endif

#endif
