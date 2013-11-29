#ifndef LIBCRUNCH_H_
#define LIBCRUNCH_H_

/* x86_64 only, for now */
#if !defined(__x86_64__) && !defined(X86_64)
#error Unsupported architecture.
#endif

#include "memtable.h"
#include "heap_index.h"
#include "allocsmt.h"
#include <stdint.h>
#include "addrmap.h"

static inline void __attribute__((gnu_inline)) __libcrunch_ensure_init(void);

#include "libcrunch.h"

inline struct rec *allocsite_to_uniqtype(const void *allocsite)
{
	assert(__libcrunch_allocsmt != NULL);
	struct allocsite_entry **bucketpos = ALLOCSMT_FUN(ADDR, allocsite);
	struct allocsite_entry *bucket = *bucketpos;
	for (struct allocsite_entry *p = bucket; p; p = p->next)
	{
		if (p->allocsite == allocsite) return p->uniqtype;
	}
}

#define maximum_vaddr_range_size (4*1024) // HACK
inline struct rec *vaddr_to_uniqtype(const void *vaddr)
{
	assert(__libcrunch_allocsmt != NULL);
	struct allocsite_entry **initial_bucketpos = ALLOCSMT_FUN(ADDR, (void*)((intptr_t)vaddr | STACK_BEGIN));
	struct allocsite_entry **bucketpos = initial_bucketpos;
	do 
	{
		struct allocsite_entry *bucket = *bucketpos;
		for (struct allocsite_entry *p = bucket; p; p = p->next)
		{
			if (p->allocsite <= vaddr) return p->uniqtype;
		}
		// no match? then try the next lower bucket
		--bucketpos;
	} while ((initial_bucketpos - bucketpos) * allocsmt_entry_coverage < maximum_vaddr_range_size);
	return NULL;
}
#undef maximum_vaddr_range_size

#define maximum_static_obj_size (64*1024) // HACK
inline struct rec *static_addr_to_uniqtype(const void *static_addr, void **out_object_start)
{
	assert(__libcrunch_allocsmt != NULL);
	struct allocsite_entry **initial_bucketpos = ALLOCSMT_FUN(ADDR, (void*)((intptr_t)static_addr | (STACK_BEGIN<<1)));
	struct allocsite_entry **bucketpos = initial_bucketpos;
	do 
	{
		struct allocsite_entry *bucket = *bucketpos;
		for (struct allocsite_entry *p = bucket; p; p = p->next)
		{
			if (p->allocsite <= static_addr) 
			{
				if (out_object_start) *out_object_start = p->allocsite;
				return p->uniqtype;
			}
		}
		// no match? then try the next lower bucket
		--bucketpos;
	} while ((initial_bucketpos - bucketpos) * allocsmt_entry_coverage < maximum_static_obj_size);
	return NULL;
}
#undef maximum_vaddr_range_size

/* avoid dependency on libc headers (in this header only) */
void __assert_fail(const char *assertion, 
	const char *file, unsigned int line, const char *function);
void warnx(const char *fmt, ...);
unsigned long malloc_usable_size (void *ptr);
int strcmp(const char *, const char *);

/* our own private assert */
static inline void __libcrunch_private_assert(_Bool cond, const char *reason, 
	const char *f, unsigned l, const char *fn)
{
	if (!cond) __assert_fail(reason, f, l, fn);
}

inline int __attribute__((gnu_inline)) __libcrunch_check_init(void)
{
	if (__builtin_expect(!&__libcrunch_is_initialized, 0))
	{
		/* This means that we're not linked with libcrunch. 
		 * There's nothing we can do! */
		return -1;
	}
	if (__builtin_expect(!__libcrunch_is_initialized, 0))
	{
		/* This means we haven't opened the uniqtypes library. 
		 * Try that now (it won't try more than once). */
		return __libcrunch_global_init();
	}
	
	return 0;
}

static inline void  __attribute__((gnu_inline)) __libcrunch_ensure_init(void)
{
	__libcrunch_private_assert(__libcrunch_check_init() == 0, "libcrunch init", 
		__FILE__, __LINE__, __func__);
}

// forward decls
int __is_aU(const void *obj, const struct rec *uniqtype);
inline int (__attribute__((always_inline)) __is_a3)(const void *obj, const char *typestr, const struct rec **maybe_uniqtype);
inline int (__attribute__((always_inline)) __is_a)(const void *obj, const char *typestr);

extern const struct rec *__libcrunch_uniqtype_void;
/* counters */
extern unsigned long __libcrunch_begun;
extern unsigned long __libcrunch_aborted_init;
extern unsigned long __libcrunch_aborted_stack;
extern unsigned long __libcrunch_aborted_static;
extern unsigned long __libcrunch_aborted_typestr;
extern unsigned long __libcrunch_aborted_unknown_storage;
extern unsigned long __libcrunch_aborted_unindexed_heap;
extern unsigned long __libcrunch_aborted_unrecognised_allocsite;
extern unsigned long __libcrunch_failed;
extern unsigned long __libcrunch_trivially_succeeded_null;
extern unsigned long __libcrunch_trivially_succeeded_void;
extern unsigned long __libcrunch_succeeded;

// FIXME: inlining here and __builtin_return_address are a mess.

/** This version lets the caller supply a local (cached) location 
 * where the uniqtype will be stored if set. */
inline int (__attribute__((always_inline)) __is_a3)(const void *obj, const char *typestr, const struct rec **maybe_uniqtype)
	
{
	/* All we do is convert typestr to a uniqtype. For this, we need to
	 * ensure we have a handle on the uniqtypes library. We do this 
	 * initialization on a slow path here, rather than in a static
	 * constructor, because this code is supposed to be inlineable.
	 * Adding one constructor per object file would be a waste, with 
	 * potential for nontrivial startup time cost. */
	const struct rec *r = NULL;
	if (__libcrunch_check_init() == -1) goto abort;
	
	/* Now we have a working handle with which to lookup uniqued types, */
	/* we can look up the uniqtype by name. */
	if (maybe_uniqtype)
	{
		/* the uniqtype may be cached there... */
		if (*maybe_uniqtype)
		{
			r = *maybe_uniqtype;
		}
		else // not cached
		{
			r = *maybe_uniqtype = __libcrunch_typestr_to_uniqtype(typestr);
		}
	}
	else r = __libcrunch_typestr_to_uniqtype(typestr);
	
	// if we get a null result, it means we got a typestring that
	// doesn't denote any type that was reified as a uniqtype. 
	
	/* Now delegate. */
	if (__builtin_expect(r == NULL, 0))
	{
		warnx("Aborted __is_a(%p, %p), reason: %s: %s\n", obj, r, 
			"unrecognised typename", typestr);
		++__libcrunch_begun;
		++__libcrunch_aborted_typestr;
		return 1;
	}
	return __is_aU(obj, r);

	__assert_fail("unreachable", __FILE__, __LINE__, __func__);
abort:
	++__libcrunch_begun;
	++__libcrunch_aborted_init;
	warnx("Aborted __is_a(%p, %p) at %p, reason: %s\n", obj, r, 
		&&abort /* we are inlined, right? */, "init failure");
	return 1;

}

/* Version based on dlsym(). */
inline int (__attribute__((always_inline)) __is_a)(const void *obj, const char *typestr)
{
	return __is_a3(obj, typestr, (void*)0);
}

#endif
