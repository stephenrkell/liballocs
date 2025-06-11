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
#define ALIGNOF(type) offsetof (struct { char c; type member; }, member)
#endif
#endif
#ifndef PAD_TO_ALIGN
#define PAD_TO_ALIGN(n, a) 	((0 == ((n) % (a))) ? (n) : (n) + (a) - ((n) % (a)))
#endif

/* Add the size of struct insert, and round this up to the align of struct insert.
 * This ensure we always have room for an *aligned* struct insert. */
#define CHUNK_SIZE_WITH_TRAILER(sz, trailer_t, trailer_align_t) \
    PAD_TO_ALIGN(sz + sizeof (trailer_t), ALIGNOF(trailer_align_t))

/* Inserts describing objects have user addresses. They may have the flag set or unset. */
#define INSERT_DESCRIBES_OBJECT(ins) \
	(!((ins)->alloc_site) || (char*)((uintptr_t)((unsigned long long)((ins)->alloc_site))) >= MINIMUM_USER_ADDRESS)
#define INSERT_IS_NULL(p_ins) (!(p_ins)->alloc_site && !(p_ins)->alloc_site_flag)

/* What's the most space that a malloc insert will use?
 * We use this figure to guess when an alloc has been satisfied with mmap().
 * Making it too big hurts performance but not correctness. */
#define MAXIMUM_MALLOC_HEADER_OVERHEAD 16

struct insert
{
	unsigned alloc_site_flag:1;
	unsigned long alloc_site:47;
#if 0
	union __attribute__((packed))
	{
		unsigned lowbits:3; /* FIXME: do these really coincide with low-order of allocsite? */
	};
#endif
	union __attribute__((packed))
	{
		unsigned bits:16; /* used to store alloc site in compact form */
	} un;
#ifdef USE_LIFETIME_POLICIES
	unsigned long unused;
#endif
} __attribute__((packed));

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


/* Chunks can also have lifetime policies attached, if we are built
 * with support for this.
 *
 * Ideally we could pack all this into 64 bits:
 * -uniqtype        (44 bits)
 * -allocsite idx   (~14 bits? not sure how many bona-fide allocation sites large programs may have)
 *      -- one trick might be to bin the allocation sites by uniqtype, so that
 *         when the uniqtype is present, only a per-uniqtype idx is needed.
 *         Currently allocsites are sorted by address, so we can bsearch them,
 *         so we'd need a separate set of indexes grouping by type. Maybe the uniqtype
 *         can even point to its allocsites?
 * -one bit per lifetime policy (~6 bits?).
 *
 * When we get rid of the memtable in favour of the bitmap,
 * we should be able to fit this in.
 * For now, strip out the lifetime policies support.
 */
typedef /*LIFETIME_INSERT_TYPE*/ unsigned char lifetime_insert_t;
#define LIFETIME_POLICY_FLAG(id) (0x1 << (id))
/* By convention lifetime policy 0 is the manual deallocation policy */
#define MANUAL_DEALLOCATION_POLICY 0
#define MANUAL_DEALLOCATION_FLAG LIFETIME_POLICY_FLAG(MANUAL_DEALLOCATION_POLICY)
/* Manual deallocation is not an "attached" policy */
#define HAS_LIFETIME_POLICIES_ATTACHED(lti) ((lti) & ~(MANUAL_DEALLOCATION_FLAG))

#if 0
/* srk: I think extended inserts need to go away. Instead any build of
 * liballocs will have a single insert type that it is using, and that build
 * will or won't support lifetime policies features. That may prove too
 * draconian but I'd like to try it for now, to conserve complexity. */
struct extended_insert
{
	lifetime_insert_t lifetime;
#ifdef PRECISE_REQUESTED_ALLOCSIZE
	/* Include any padding inserted such that
	 * usable_size - insert_size = requested_size */
	unsigned char insert_size;
#endif
	/* The base insert is at the end because we want interoperabiliy between
	 * allocators using extended_insert and allocators only using insert.
	 * See insert_for_chunk. */
	struct insert base;
} __attribute__((packed)); /* Alignment from the end guaranteed by ourselves */
struct uniqtype;
static inline struct extended_insert *extended_insert_for_chunk(void *userptr, sizefn_t *sizefn)
{
	return /*NULL*/ (void*)0; /* FIXME: restore this */
}
#endif
static inline lifetime_insert_t *lifetime_insert_for_chunk(void *userptr, sizefn_t *sizefn)
{
	return (void*)0; /* FIXME: restore this */ /* &extended_insert_for_chunk(userptr, sizefn)->lifetime; */
}
#define INSERT_TYPE struct insert

#endif
