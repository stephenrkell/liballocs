#ifndef LIBALLOCS_MALLOC_META_H_
#define LIBALLOCS_MALLOC_META_H_

/* NOTE: this file gets included by liballocs_cil_inlines.h
 * so needs to be written to be tolerant of many versions of C.
 * FIXME: why is it included from there? Should not be necessary? */

#ifndef offsetof
#define __liballocs_defined_offsetof
#define offsetof(type, member) (__builtin_offsetof(type, member))
#endif

#ifndef MALLOC_ALIGN
#define MALLOC_ALIGN 16  /* We assume chunks are aligned to a this-many byte boundary */
#endif

/* HACK: copied from memtable.h. */
/* Thanks to Martin Buchholz -- <http://www.wambold.com/Martin/writings/alignof.html> */
#ifndef ALIGNOF
#if __STDC_VERSION__ >= 201112L
#define ALIGNOF _Alignof
#else
/* Clang barfs at offsetof in a constant expression, e.g. _Static_assert:
 * "cast that performs the conversions of a reinterpret_cast is not allowed in a constant expression"
 * --- so we avoid this on Clang. */
#ifdef __clang__
#define ALIGNOF(type) __builtin_offsetof (struct { char c; type member; }, member)
#else
#define ALIGNOF(type) offsetof (struct { char c; type member; }, member)
#endif
#endif
#endif
#ifndef PAD_TO_ALIGN
#define PAD_TO_ALIGN(n, a) 	((0 == ((n) % (a))) ? (n) : (n) + (a) - ((n) % (a)))
#endif

/* Add the size of struct insert, and round this up to the align of struct insert.
 * This ensure we always have room for an *aligned* struct insert. */
#define CHUNK_SIZE_WITH_TRAILER(sz, trailer_t, trailer_align_t) \
    PAD_TO_ALIGN(sz + sizeof (trailer_t), ALIGNOF(trailer_align_t))

/* Inserts describing objects have user addresses */
#define INSERT_DESCRIBES_OBJECT(ins) \
	(ins->with_type.alloc_site_id || (char*)((uintptr_t)((unsigned long long)(ins->initial.alloc_site))) >= MINIMUM_USER_ADDRESS)
#define INSERT_IS_NULL(p_ins) (!INSERT_IS_WITH_TYPE(p_ins) && p_ins->initial.alloc_site == 0)

/* What's the most space that a malloc insert will use?
 * We use this figure to guess when an alloc has been satisfied with mmap().
 * Making it too big hurts performance but not correctness. */
#define MAXIMUM_MALLOC_HEADER_OVERHEAD 16


#if LIFETIME_POLICIES > 4
#error "Variable size lifetime policies not fully supported yet"
#endif

struct insert {
	union {
		struct insert_initial {
			unsigned short unused:16; /* Always Zero, branch union on this */
			unsigned long  alloc_site:48;
		} initial;
		struct insert_with_type {
			  signed short alloc_site_id:15; /* may be zero; -1 means "no/unknown alloc site" */
			unsigned char  always_1:1;
			unsigned long  uniqtype_shifted:44;  /* uniqtype ptrs are 8-byte-aligned and have top bit 0 => this field is ((unsigned long) u)>>3 */
			unsigned char  lifetime_policies:4; // should never be zero 0000 should be that it is freed when and only when parent is freed.
		} with_type;
	};
} __attribute((packed));

#define UNIQTYPE_SHIFT_FOR_INSERT(u)       (((unsigned long) (u)) >> 3)
#define UNIQTYPE_UNSHIFT_FROM_INSERT(bits) ((struct uniqtype *)(((unsigned long) (bits)) << 3))

static inline /*size_t*/ unsigned long caller_usable_size_for_chunk_and_usable_size(void *userptr,
	/*size_t*/ unsigned long alloc_usable_size)
{
	return alloc_usable_size - sizeof (struct insert);
}

typedef unsigned long /*size_t*/ sizefn_t(void*);

static inline struct insert *
insert_for_chunk_and_caller_usable_size(void *userptr, /*size_t*/ unsigned long caller_usable_size)
{
	/*uintptr_t*/ unsigned long long insertptr
	 = (unsigned long long)((char*) userptr + caller_usable_size);
	return (struct insert *)insertptr;
}
static inline /*size_t*/ unsigned long caller_usable_size_for_chunk(void *userptr, sizefn_t *sizefn)
{
	return caller_usable_size_for_chunk_and_usable_size(userptr,
			sizefn(userptr));
}
static inline struct insert *insert_for_chunk(void *userptr, sizefn_t *sizefn)
{
	return insert_for_chunk_and_caller_usable_size(userptr,
		caller_usable_size_for_chunk(userptr, sizefn));
}


#define LIFETIME_POLICY_FLAG(id) (0x1 << (id))
#define INSERT_IS_WITH_TYPE(ins) (ins->initial.unused != 0)

/* By convention lifetime policy 0 is the manual deallocation policy */
#define MANUAL_DEALLOCATION_POLICY 0
#define MANUAL_DEALLOCATION_FLAG LIFETIME_POLICY_FLAG(MANUAL_DEALLOCATION_POLICY)
/* Manual deallocation is not an "attached" policy */
#define HAS_LIFETIME_POLICIES_ATTACHED(lti) ((lti) & ~(MANUAL_DEALLOCATION_FLAG))
typedef struct insert lifetime_insert_t;
static inline lifetime_insert_t *lifetime_insert_for_chunk(void *userptr, sizefn_t *sizefn)
{
	return insert_for_chunk(userptr,sizefn);
}
#define INSERT_TYPE struct insert

#endif
