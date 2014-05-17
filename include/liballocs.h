#ifndef LIBALLOCS_H_
#define LIBALLOCS_H_

extern void warnx(const char *fmt, ...); // avoid repeating proto

/* Copied from dumptypes.cpp */
struct uniqtype; // opaque

extern int __liballocs_debug_level;
extern _Bool __liballocs_is_initialized __attribute__((weak));

int __liballocs_global_init(void) __attribute__((weak));
// declare as const void *-returning, to simplify trumptr
const void *__liballocs_typestr_to_uniqtype(const char *typestr) __attribute__((weak));
void *__liballocs_my_typeobj(void) __attribute__((weak));
int __is_a_internal(const void *obj, const void *uniqtype) __attribute__((weak));
int __like_a_internal(const void *obj, const void *uniqtype) __attribute__((weak));
int __check_args_internal(const void *obj, int nargs, ...) __attribute__((weak));

/* Uniqtypes for signed_char and unsigned_char -- we declare them as int 
 * to avoid the need to define struct uniqtype in this header file. */

extern int __uniqtype__signed_char __attribute__((weak));
extern int __uniqtype__unsigned_char __attribute__((weak));
extern int __uniqtype__void __attribute__((weak));

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

#endif
