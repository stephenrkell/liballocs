#ifndef LIBCRUNCH_H_
#define LIBCRUNCH_H_

/* public interface to libcrunch */
extern void warnx(const char *fmt, ...); // avoid repeating proto

/* Copied from dumptypes.cpp */
struct uniqtype; // opaque

extern int __libcrunch_debug_level;
extern _Bool __libcrunch_is_initialized __attribute__((weak));
#ifdef LIBCRUNCH_EXTENDED_COUNTS
extern unsigned long __libcrunch_aborted_init __attribute__((weak));
extern unsigned long __libcrunch_trivially_succeeded __attribute__((weak));
#endif
extern unsigned long __libcrunch_begun __attribute__((weak));
extern unsigned long __libcrunch_aborted_typestr __attribute__((weak));

int __libcrunch_global_init(void) __attribute__((weak));
// declare as const void *-returning, to simplify trumptr
const void *__libcrunch_typestr_to_uniqtype(const char *typestr) __attribute__((weak));
void *__libcrunch_my_typeobj(void) __attribute__((weak));
int __is_a_internal(const void *obj, const void *uniqtype) __attribute__((weak));
int __like_a_internal(const void *obj, const void *uniqtype) __attribute__((weak));
int __check_args_internal(const void *obj, int nargs, ...) __attribute__((weak));

/* Uniqtypes for signed_char and unsigned_char -- we declare them as int 
 * to avoid the need to define struct uniqtype in this header file. */

extern int __uniqtype__signed_char __attribute__((weak));
extern int __uniqtype__unsigned_char __attribute__((weak));
extern int __uniqtype__void __attribute__((weak));

/* The main public API to libcrunch is through several small functions 
 * which are *always* inlined. NOTE: repeat these in trumptr.ml so that
 * the instrumentation can add them to code which doesn't include this header. */

// if we're not compiling under CIL, include the things that trumptr would define
#ifndef CIL
#include "libcrunch_cil_inlines.h"
#endif

/* our own private assert */
static inline void 
(__attribute__((always_inline,gnu_inline)) __libcrunch_private_assert) (_Bool cond, const char *reason, 
	const char *f, unsigned l, const char *fn)
{
#ifndef NDEBUG
	if (!cond) __assert_fail(reason, f, l, fn);
#endif
}

static inline void (__attribute__((always_inline,gnu_inline)) __libcrunch_ensure_init) (void)
{
	__libcrunch_private_assert(__libcrunch_check_init() == 0, "libcrunch init", 
		__FILE__, __LINE__, __func__);
}

#endif
