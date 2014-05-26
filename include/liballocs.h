#ifndef LIBALLOCS_H_
#define LIBALLOCS_H_

#ifdef __cplusplus
extern "C" {
typedef bool _Bool;
#endif

#include "addrmap.h"

extern void warnx(const char *fmt, ...); // avoid repeating proto
#ifndef NDEBUG
#include <assert.h>
#endif

/* Copied from dumptypes.cpp */
struct uniqtype_cache_word 
{
	unsigned long addr:47;
	unsigned flag:1;
	unsigned bits:16;
};

struct contained {
	signed offset;
	struct uniqtype *ptr;
} contained;

struct uniqtype
{
	struct uniqtype_cache_word cache_word;
	const char *name;
	unsigned short pos_maxoff; // 16 bits
	unsigned short neg_maxoff; // 16 bits
	unsigned nmemb:12;         // 12 bits -- number of `contained's (always 1 if array)
	unsigned is_array:1;       // 1 bit
	unsigned array_len:19;     // 19 bits; 0 means undetermined length
	struct contained contained[]; // there's always at least one of these, even if nmemb == 0
};
#define UNIQTYPE_IS_SUBPROGRAM(u) \
(((u) != (struct uniqtype *) &__uniqtype__void) && \
((u)->pos_maxoff == 0) && \
((u)->neg_maxoff == 0) && !(u)->is_array)

#define MAGIC_LENGTH_POINTER ((1u << 19) - 1u)
#define UNIQTYPE_IS_POINTER_TYPE(u) \
((u)->is_array && (u)->array_len == MAGIC_LENGTH_POINTER)

extern int __liballocs_debug_level;
extern _Bool __liballocs_is_initialized __attribute__((weak));

int __liballocs_global_init(void) __attribute__((weak));
// declare as const void *-returning, to simplify trumptr
const void *__liballocs_typestr_to_uniqtype(const char *typestr) __attribute__((weak));
void *__liballocs_my_typeobj(void) __attribute__((weak));

/* Uniqtypes for signed_char and unsigned_char -- we declare them as int 
 * to avoid the need to define struct uniqtype in this header file. */

extern struct uniqtype __uniqtype__signed_char __attribute__((weak));
extern struct uniqtype __uniqtype__unsigned_char __attribute__((weak));
extern struct uniqtype __uniqtype__void __attribute__((weak));
extern struct uniqtype __uniqtype__int __attribute__((weak));

/* Iterate over all uniqtypes in a given shared object. */
int __liballocs_iterate_types(void *typelib_handle, int (*cb)(struct uniqtype *t, void *arg), void *arg);
/* Our main API: query allocation information for a pointer */
_Bool __liballocs_get_alloc_info(const void *obj, const void *test_uniqtype, 
	const char **out_reason, const void **out_reason_ptr,
	memory_kind *out_memory_kind, const void **out_object_start,
	unsigned *out_block_element_count,
	struct uniqtype **out_alloc_uniqtype, const void **out_alloc_site,
	signed *out_target_offset_within_uniqtype);
_Bool __liballocs_find_matching_subobject(signed target_offset_within_uniqtype,
	struct uniqtype *cur_obj_uniqtype, struct uniqtype *test_uniqtype, 
	struct uniqtype **last_attempted_uniqtype, signed *last_uniqtype_offset,
		signed *p_cumulative_offset_searched);
/* Some more inlines follow at the bottom. */

/* our own private assert */
static inline void 
(__attribute__((always_inline,gnu_inline)) __liballocs_private_assert) (_Bool cond, const char *reason, 
	const char *f, unsigned l, const char *fn)
{
#ifndef NDEBUG
	if (!cond) __assert_fail(reason, f, l, fn);
#endif
}

static inline void (__attribute__((always_inline,gnu_inline)) __liballocs_ensure_init) (void)
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
		int ret = __liballocs_global_init ();
		__liballocs_private_assert(ret == 0, "liballocs init", 
			__FILE__, __LINE__, __func__);
	}
}

static inline _Bool __liballocs_first_subobject_spanning(
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
		unsigned num_contained = cur_obj_uniqtype->array_len;
		struct uniqtype *element_uniqtype = cur_obj_uniqtype->contained[0].ptr;
		unsigned target_element_index
		 = target_offset_within_uniqtype / element_uniqtype->pos_maxoff;
		if (num_contained > target_element_index)
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
		unsigned num_contained = cur_obj_uniqtype->nmemb;

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

#ifdef __cplusplus
} // end extern "C"
#endif

#endif
