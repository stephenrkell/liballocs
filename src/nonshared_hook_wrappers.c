#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <malloc.h>

#include <errno.h>
#include <link.h>
#include "relf.h"

/* Hide these symbols */
#define HIDDEN __attribute__((visibility("hidden")))
#define HOOK_ATTRIBUTES HIDDEN

/* Prototype the hook_* functions. */
#undef HOOK_PREFIX
#define HOOK_PREFIX(i) hook_ ## i
#include "hook_protos.h"
#undef HOOK_PREFIX
/* Prototype the __terminal_hook_* functions. */
#define HOOK_PREFIX(i) __terminal_ ## i
#include "hook_protos.h"

/* This is like the usual wrap hooks, except we use libdl to 
 * get the __real_ function. It's useful when the __real_ function
 * is itself link-time-wrapped (--wrap __real_malloc)
 * for insertion of another layer of wrappers. In such a situation,
 * a reference to __real_malloc would bind us back to the top-level
 * __wrap_malloc, and a reference to __real___real_malloc would bind
 * to __real_malloc which is an undefined symbol (it's never actually
 * defined). Attempts to --defsym __real_malloc don't work, because
 * they are themselves subject to wrapping: --defsym __real_malloc=malloc
 * will give us __wrap_malloc again.
 *
 * The fact that our terminating case uses libdl is now a source of the
 * usual problems: are we on a callchain from within libdl, e.g. dlsym()
 * doing its calloc()? If so, we should ourselves be sure not to call 
 * dlsym(). Two solutions suggest themselves: using our own dlsym() that never
 * allocates, or ensuring the first call through all these hooks (which
 * is the only one that should need dlsym()) does not itself come from dlsym. */

void __terminal_hook_init(void) {}

void * __terminal_hook_malloc(size_t size, const void *caller)
{
	static void *(*real_malloc)(size_t);
	if (!real_malloc) real_malloc = fake_dlsym(RTLD_DEFAULT, "__real_malloc");
	if (!real_malloc) real_malloc = fake_dlsym(RTLD_DEFAULT, "malloc"); // probably infinite regress...
	if (!real_malloc) abort();
	return real_malloc(size);
}
void __terminal_hook_free(void *ptr, const void *caller)
{
	static void (*real_free)(void*);
	if (!real_free) real_free = fake_dlsym(RTLD_DEFAULT, "__real_free");
	if (!real_free) real_free = fake_dlsym(RTLD_DEFAULT, "free"); // probably infinite regress...
	if (!real_free) abort();
	real_free(ptr);
}
void * __terminal_hook_realloc(void *ptr, size_t size, const void *caller)
{
	static void *(*real_realloc)(void*, size_t);
	if (!real_realloc) real_realloc = fake_dlsym(RTLD_DEFAULT, "__real_realloc");
	if (!real_realloc) real_realloc = fake_dlsym(RTLD_DEFAULT, "realloc"); // probably infinite regress...
	if (!real_realloc) abort();
	return real_realloc(ptr, size);
}
void * __terminal_hook_memalign(size_t boundary, size_t size, const void *caller)
{
	static void *(*real_memalign)(size_t, size_t);
	if (!real_memalign) real_memalign = fake_dlsym(RTLD_DEFAULT, "__real_memalign");
	if (!real_memalign) real_memalign = fake_dlsym(RTLD_DEFAULT, "memalign"); // probably infinite regress...
	if (!real_memalign) abort();
	return real_memalign(boundary, size);
}

/* These are our actual hook stubs. */
void *__wrap___real_malloc(size_t size)
{
	void *ret;
	ret = hook_malloc(size, __builtin_return_address(0));
	return ret;
}
void *__wrap___real_calloc(size_t nmemb, size_t size)
{
	void *ret;
	ret = hook_malloc(nmemb * size, __builtin_return_address(0));
	if (ret) bzero(ret, nmemb * size);
	return ret;
}
void __wrap___real_free(void *ptr)
{
	hook_free(ptr, __builtin_return_address(0));
}
void *__wrap___real_realloc(void *ptr, size_t size)
{
	void *ret;
	ret = hook_realloc(ptr, size, __builtin_return_address(0));
	return ret;
}
void *__wrap___real_memalign(size_t boundary, size_t size)
{
	void *ret;
	ret = hook_memalign(boundary, size, __builtin_return_address(0));
	return ret;
}
int __wrap___real_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	void *ret;
	ret = hook_memalign(alignment, size, __builtin_return_address(0));
	
	if (!ret) return EINVAL; // FIXME: check alignment, return ENOMEM/EINVAL as appropriate
	else
	{
		*memptr = ret;
		return 0;
	}
}
size_t __mallochooks_malloc_usable_size(void *ptr)
{
	return malloc_usable_size(ptr);
}
size_t __real_malloc_usable_size(void *ptr)
{
	return malloc_usable_size(ptr);
}
/* Some impls don't provide posix_memalign. */
size_t __real_posix_memalign(void **memptr, size_t alignment, size_t size) __attribute__((weak));
size_t __real_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	void *ret = __terminal_hook_memalign(alignment, size, __builtin_return_address(0));
	if (!ret) return EINVAL; // FIXME: check alignment, return ENOMEM/EINVAL as appropriate
	else
	{
		*memptr = ret;
		return 0;
	}
}
