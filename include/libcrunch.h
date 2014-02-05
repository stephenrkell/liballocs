#ifndef LIBCRUNCH_H_
#define LIBCRUNCH_H_

/* public interface to libcrunch */
extern void warnx(const char *fmt, ...); // avoid repeating proto

/* Copied from dumptypes.cpp */
struct rec; // opaque

extern int __libcrunch_debug_level;
extern _Bool __libcrunch_is_initialized __attribute__((weak));
#ifdef LIBCRUNCH_EXTENDED_COUNTS
extern unsigned long __libcrunch_aborted_init __attribute__((weak));
extern unsigned long __libcrunch_trivially_succeeded __attribute__((weak));
#endif
extern unsigned long __libcrunch_begun __attribute__((weak));
extern unsigned long __libcrunch_aborted_typestr __attribute__((weak));

int __libcrunch_global_init(void) __attribute__((weak));
struct rec *__libcrunch_typestr_to_uniqtype(const char *typestr) __attribute__((weak));
void *__libcrunch_my_typeobj(void) __attribute__((weak));
int __is_a_internal(const void *obj, const void *uniqtype) __attribute__((weak));

/* Uniqtypes for signed_char and unsigned_char -- we declare them as int 
 * to avoid the need to define struct rec in this header file. */

extern int __uniqtype__signed_char __attribute__((weak));
extern int __uniqtype__unsigned_char __attribute__((weak));

/* The main public API to libcrunch is through several small functions 
 * which are *always* inlined. NOTE: repeat these in trumptr.ml so that
 * the instrumentation can add them to code which doesn't include this header. */

/* Initialize if not already done. Return 0 if all okay, -1 otherwise. */
extern inline int __attribute__((always_inline,gnu_inline)) __libcrunch_check_init(void)
{
	if (__builtin_expect(!&__libcrunch_is_initialized, 0))
	{
		/* This means that we're not linked with libcrunch. 
		 * There's nothing we can do! */
		return -1;
	}
	if (__builtin_expect(!__libcrunch_is_initialized, 0))
	{
		/* This means we haven't initialized.
		 * Try that now (it won't try more than once). */
		return __libcrunch_global_init();
	}
	
	return 0;
}

/* our own private assert */
static inline void __libcrunch_private_assert(_Bool cond, const char *reason, 
	const char *f, unsigned l, const char *fn)
{
#ifndef NDEBUG
	if (!cond) __assert_fail(reason, f, l, fn);
#endif
}

static inline void  __attribute__((gnu_inline)) __libcrunch_ensure_init(void)
{
	__libcrunch_private_assert(__libcrunch_check_init() == 0, "libcrunch init", 
		__FILE__, __LINE__, __func__);
}

#ifdef LIBCRUNCH_EXTENDED_COUNTS
#define LIBCRUNCH_BASIC_CHECKS \
	do { \
		++__libcrunch_begun; \
		/* Check for init first, else we can't use the counts. */ \
		if (__builtin_expect((__libcrunch_check_init() == -1), 0)) \
		{ \
			++__libcrunch_begun; \
			++__libcrunch_aborted_init; \
			return 1; \
		} \
		if (!obj) \
		{ \
			++__libcrunch_begun; \
			++__libcrunch_trivially_succeeded; \
			return 1; \
		} \
	} while (0)
#else
#define LIBCRUNCH_BASIC_CHECKS \
	do { \
		if (!obj) \
		{ \
			return 1; \
		} \
		if (__builtin_expect((__libcrunch_check_init() == -1), 0)) \
		{ \
			return 1; \
		} \
	} while (0)
#endif

extern inline int __attribute__((always_inline,gnu_inline)) __is_aU(const void *obj, struct rec *r)
{
	LIBCRUNCH_BASIC_CHECKS;
	
	/* Null uniqtype means __is_aS got a bad typestring, OR we're not 
	 * linked with enough uniqtypes data. */
	if (__builtin_expect(r == NULL, 0))
	{
		++__libcrunch_begun;
		if (__libcrunch_debug_level > 0) warnx("Aborted __is_a(%p, %p), reason: %\n", obj, r, 
			"unrecognised typename (see stack trace)");
		++__libcrunch_aborted_typestr;
		return 1;
	}
	
	if (r == (void*) &__uniqtype__signed_char || r == (void*) &__uniqtype__unsigned_char)
	{
#ifdef LIBCRUNCH_EXTENDED_COUNTS
		++__libcrunch_begun;
		++__libcrunch_trivially_succeeded;
#endif
		return 1;
	}
	
	// now we're really started
	++__libcrunch_begun;
	return __is_a_internal(obj, r);
}

extern inline int __attribute__((always_inline,gnu_inline)) __is_aS(const void *obj, const char *typestr)
{
	LIBCRUNCH_BASIC_CHECKS;
	
	struct rec * r = __libcrunch_typestr_to_uniqtype(typestr);

	return __is_aU(obj, r);
}

#endif
