/* What we don't (yet) trap: 
 * 
 *  fork(), vfork(), clone()     -- FIXME: do we care about the fork-without-exec case?
 */


#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <assert.h>
#include <sys/types.h>
/* We make very heavy use of malloc_usable_size in heap_index. But we also 
 * override it -- twice! -- once in mallochooks, to intercept the early_malloc
 * case, and once here to intercept the stack (alloca) case. 
 * 
 * We want to be very careful with the visibility of this symbol, so that references
 * we make always go straight to our definition, not via the PLT. So declare it
 * as protected. NOTE that it will always make at least one call through the PLT, 
 * because the underlying logic is in libc. FIXME: all this is messed up and doesn't
 * seem to work. What we want is to avoid two PLT indirections (one is unavoidable). */
size_t malloc_usable_size(void *ptr) /*__attribute__((visibility("protected")))*/;
size_t __real_malloc_usable_size(void *ptr) /*__attribute__((visibility("protected")))*/;
size_t __wrap_malloc_usable_size(void *ptr) __attribute__((visibility("protected")));
size_t __mallochooks_malloc_usable_size(void *ptr) __attribute__((visibility("protected")));
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include "liballocs_private.h"
#include "relf.h"
#include "raw-syscalls.h"

/* We should be safe to use it once malloc is initialized. */
// #define safe_to_use_bigalloc (__liballocs_is_initialized)
#define safe_to_use_bigalloc (pageindex)
#define safe_to_call_dlsym (safe_to_call_malloc)

/* some signalling to malloc hooks */
_Bool __avoid_libdl_calls;

/* NOTE that our wrappers are all init-on-use. This is because 
 * we might get called very early, and even if we're not trying to
 * intercept the early calls, we still need to be able to delegate. 
 * For that, we need our underyling function pointers. */

/* NOTE / HACK / glibc-specificity: we know about two different mmap entry 
 * points: mmap and mmap64. 
 * 
 * on x86-64, mmap64 has 8-byte size_t length and 8-byte off_t offset.
 * on x86-64, mmap has 8-byte size_t length and 8-byte off_t offset.
 * So I think the differences are only on 32-bit platforms. 
 * For now, just alias mmap64 to mmap. */

/* Stop gcc from tail-call-opt'ing the __mallochooks_ call, because 
 * it has made it impossible to debug linkage problems. */
#pragma GCC push_options
#pragma GCC optimize("no-optimize-sibling-calls")

size_t __wrap_malloc_usable_size (void *ptr) __attribute__((visibility("protected")));
size_t malloc_usable_size (void *ptr) __attribute__((alias("__wrap_malloc_usable_size"),visibility("default")));
size_t __wrap_malloc_usable_size (void *ptr)
{
	/* We use this all the time in heap_index. 
	 * BUT because heap_index addresses can be on the stack too, 
	 * in the case of alloca, we need to intercept this case
	 * and handle it appropriately. 
	 * 
	 * How can we detect the stack case quickly?
	 * We could just ask the pageindex.
	 * 
	 * If we wanted a faster-but-less-general common case, 
	 * - If ptr is on the same page as our thread's rsp, 
	 *   it's definitely a stack pointer.
	 * - If ptr is within MAXIMUM_STACK_SIZE of our thread's rsp, 
	 *   it's *probably* a stack ptr, but to be certain it seems
	 *   that we still have to consult the l0 index.
	 * - Can we *rule out* the stack case quickly?
	 *   HMM... all this is only using the same tricks we have in 
	 *   get_object_memory_kind, so use that.
	 * 
	 */
	void *sp;
	 #ifdef UNW_TARGET_X86
		__asm__ ("movl %%esp, %0\n" :"=r"(sp));
	#else // assume X86_64 for now
		__asm__("movq %%rsp, %0\n" : "=r"(sp));
	#endif

	_Bool is_stack = (__lookup_top_level_allocator(ptr) == &__stack_allocator);
	
	if (is_stack)
	{
		return *(((unsigned long *) ptr) - 1);
	}
	else return //__real_malloc_usable_size(ptr);
       	__mallochooks_malloc_usable_size(ptr);
}
#pragma GCC pop_options

extern int _etext;
static 
_Bool
is_self_call(const void *caller)
{
	static char *our_load_addr;
	if (!our_load_addr) our_load_addr = (char*) get_highest_loaded_object_below(&is_self_call)->l_addr;
	if (!our_load_addr) abort(); /* we're supposed to be preloaded, not executable */
	static char *text_segment_end;
	if (!text_segment_end) text_segment_end = get_local_text_segment_end();
	return ((char*) caller >= our_load_addr && (char*) caller < text_segment_end);
}

/* Libraries that extend us can define this to control mmap placement policy. */
void __liballocs_nudge_mmap(void **p_addr, size_t *p_length, int *p_prot, int *p_flags,
                  int *p_fd, off_t *p_offset, const void *caller) __attribute__((weak));

/* For most of the process we rely on symbol overriding to observe mmap calls. 
 * However, we have another trick for ld.so and libc mmap syscalls.
 * We *never* delegate to the underlying (RTLD_NEXT) mmap; we always do it
 * ourselves. This ensures that the handling is an either-or; exactly one of these
 * paths (preload or systrap) should be hit. We must take care to do the
 * (logically) same things in both. */
void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
	/* We always nudge, even for mmaps we do ourselves. This is because 
	 * the nudge function implements some global placement policy that even
	 * our memtables must adhere to. */
	if (&__liballocs_nudge_mmap)
	{
		__liballocs_nudge_mmap(&addr, &length, &prot, &flags, &fd, &offset, __builtin_return_address(0));
	}

	void *ret = (void*) (uintptr_t) syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
	/* We only start hooking mmap after we read /proc, which is also when we 
	 * enable the systrap stuff. */
	if (!__liballocs_systrap_is_initialized || length > BIGGEST_BIGALLOC
		//|| 
		//	(is_self_call(__builtin_return_address(0))
		//	&& )
		// ... actually, observing our own mmaps might be... okay? CARE, because
		// the mmap allocator does call malloc itself, for its metadata, so we might
		// become reentrant at this point, which we *don't* want. Note that we're
		// not in a signal handler here; this path is only for LD_PRELOAD-based hooking,
		// and we don't trap our own mmap syscalls, so things are slightly less hairy than
		// they otherwise might be.
		// Current approach: mmap allocator tests for private malloc active, and 
		// just does a more minimalist metadata-free bigalloc creation in such cases.
		// FIXME: whatever we decide to do here, also do it for mremap and munmap
	)
	{
		// skip hooking logic
		return ret;
	}
	
	if (ret != MAP_FAILED)
	{
		__mmap_allocator_notify_mmap(ret, addr, length, prot, flags, fd, offset, __builtin_return_address(0));
	}
	return ret;
}
void *mmap64(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset) __attribute__((alias("mmap")));

int munmap(void *addr, size_t length)
{
	static int (*orig_munmap)(void *, size_t);
	if (!orig_munmap)
	{
		orig_munmap = dlsym(RTLD_NEXT, "munmap");
		assert(orig_munmap);
	}
	
	if (!safe_to_use_bigalloc || is_self_call(__builtin_return_address(0)))
	{
		return orig_munmap(addr, length);
	}
	else
	{
		int ret = orig_munmap(addr, length);
		if (ret == 0)
		{
			__mmap_allocator_notify_munmap(addr, length, __builtin_return_address(0));
		}
		return ret;
	}
}

void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags, ... /* void *new_address */)
{
	static void *(*orig_mremap)(void *, size_t, size_t, int, ...);
	va_list ap;
	if (!orig_mremap)
	{
		orig_mremap = dlsym(RTLD_NEXT, "mremap");
		assert(orig_mremap);
	}
	
	void *new_address = MAP_FAILED;
	if (flags & MREMAP_FIXED)
	{
		va_start(ap, flags);
		new_address = va_arg(ap, void *);
		va_end(ap);
	}
	
#define orig_call ((flags & MREMAP_FIXED)  \
			? orig_mremap(old_addr, old_size, new_size, flags, new_address) \
			: orig_mremap(old_addr, old_size, new_size, flags))
	
	if (!safe_to_use_bigalloc || is_self_call(__builtin_return_address(0))) 
	{
		return orig_call;
	}
	else
	{
		void *ret = orig_call;
		if (ret != MAP_FAILED)
		{
			__mmap_allocator_notify_mremap_after(ret, old_addr, old_size, 
					new_size, flags, new_address, __builtin_return_address(0));
		}
		return ret;
	}
#undef orig_call
}

// HACK: call out to libcrunch if it's linked in
extern void  __attribute__((weak)) __libcrunch_scan_lazy_typenames(void*);

void *(*orig_dlopen)(const char *, int) __attribute__((visibility("hidden")));
void *dlopen(const char *filename, int flag)
{
	write_string("Blah3000\n");
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	write_string("Blah3001\n");
	if (!orig_dlopen) // happens if we're called before liballocs init
	{
		write_string("Blah3002\n");
		orig_dlopen = dlsym(RTLD_NEXT, "dlopen");
		if (!orig_dlopen) abort();
		write_string("Blah3003\n");
	}
	write_string("Blah3004\n");

	void *ret = NULL;
	_Bool file_already_loaded = 0;
	/* FIXME: inherently racy, but does any client really race here? */
	if (filename) 
	{
		write_string("Blah3004.5\n");
		const char *file_realname_raw = realpath_quick(filename);
		if (!file_realname_raw) 
		{
			/* The file does not exist. */
			goto skip_load;
		}
		const char *file_realname = private_strdup(file_realname_raw);
		write_string("Blah3004.6\n");
		for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
		{
			write_string("Blah3004.7\n");
			const char *lm_ent_realname = dynobj_name_from_dlpi_name(l->l_name, (void*) l->l_addr);
			write_string("Blah3004.8\n");
			file_already_loaded |= (l->l_name && 
					(0 == strcmp(lm_ent_realname, file_realname)));
			if (file_already_loaded) break;
		}
		free((void*) file_realname);
	}
	write_string("Blah3005\n");
	
	ret = orig_dlopen(filename, flag);
skip_load:
	if (we_set_flag) __avoid_libdl_calls = 0;
		
	/* Have we just opened a new object? If filename was null, 
	 * we haven't; if ret is null; we haven't; if NOLOAD was passed,
	 * we haven't. Otherwise we rely on the racy logic above. */
	if (filename != NULL && ret != NULL && !(flag & RTLD_NOLOAD) && !file_already_loaded)
	{
		write_string("Blah3006\n");
		if (__libcrunch_scan_lazy_typenames) __libcrunch_scan_lazy_typenames(ret);

		__static_allocator_notify_load(ret);

		/* Also load the types and allocsites for this object. These callbacks
		 * also have to be tolerant of already-loadedness. */
		int ret_types = dl_for_one_object_phdrs(ret, load_types_for_one_object, NULL);
		assert(ret_types == 0);
	#ifndef NO_MEMTABLE
		int ret_allocsites = dl_for_one_object_phdrs(ret, load_and_init_allocsites_for_one_object, NULL);
		assert(ret_allocsites == 0);
		int ret_stackaddr = dl_for_one_object_phdrs(ret, link_stackaddr_and_static_allocs_for_one_object, NULL);
		assert(ret_stackaddr == 0);
	#endif
	}
	write_string("Blah3007\n");

	return ret;
}

int dlclose(void *handle)
{
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	static int (*orig_dlclose)(void *);
	if(!orig_dlclose)
	{
		orig_dlclose = dlsym(RTLD_NEXT, "dlclose");
		orig_dlopen = dlsym(RTLD_NEXT, "dlopen");
		assert(orig_dlclose);
	}
	
	if (!safe_to_use_bigalloc)
	{
		if (we_set_flag) __avoid_libdl_calls = 0;
		return orig_dlclose(handle);
	}
	else
	{
		char *copied_filename = strdup(((struct link_map *) handle)->l_name);
		assert(copied_filename != NULL);
		
		int ret = orig_dlclose(handle);
		/* NOTE that a successful dlclose doesn't necessarily unload 
		 * the library! To see whether it's really unloaded, we use 
		 * dlopen *again* with RTLD_NOLOAD. */
		if (ret == 0)
		{
			// was it really unloaded?
			void *h = orig_dlopen(copied_filename, RTLD_LAZY | RTLD_NOLOAD);
			if (h == NULL)
			{
				// yes, it was unloaded
				__static_allocator_notify_unload(copied_filename);
			}
			else 
			{
				// it wasn't unloaded, so we do nothing
			}
		}
	
	// out:
		free(copied_filename);
		if (we_set_flag) __avoid_libdl_calls = 0;
		return ret;
	}
}

static char *our_dlerror;
char *dlerror(void)
{
	static char *(*orig_dlerror)(void);
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dlerror)
	{
		if (__avoid_libdl_calls && !we_set_flag) orig_dlerror = fake_dlsym(RTLD_NEXT, "dlerror");
		else orig_dlerror = dlsym(RTLD_NEXT, "dlerror");
		if (!orig_dlerror) abort();
	}
	char *orig_err = orig_dlerror(); // clear the original error
	char *ret = our_dlerror ? our_dlerror : orig_err;
	if (our_dlerror) our_dlerror = NULL;
	
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

/* Q. How on earth do we override dlsym?
 * A. We use relf.h's fake_dlsym. */
void *dlsym(void *handle, const char *symbol)
{
	static char *(*orig_dlsym)(void *handle, const char *symbol);
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dlsym)
	{
		orig_dlsym = fake_dlsym(RTLD_NEXT, "dlsym");
		if (orig_dlsym == (void*) -1)
		{
			our_dlerror = "symbol not found";
			orig_dlsym = NULL;
		}
		if (!orig_dlsym) abort();
	}
	
	void *ret = orig_dlsym(handle, symbol);
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

int dladdr(const void *addr, Dl_info *info)
{
	static int(*orig_dladdr)(const void *, Dl_info *);
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dladdr)
	{
		if (__avoid_libdl_calls && !we_set_flag) abort();
		orig_dladdr = dlsym(RTLD_NEXT, "dladdr");
		if (!orig_dladdr) abort();
	}
	int ret = orig_dladdr(addr, info);
	
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

void *dlvsym(void *handle, const char *symbol, const char *version)
{
	static void *(*orig_dlvsym)(void *, const char*, const char*);
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dlvsym)
	{
		if (__avoid_libdl_calls && !we_set_flag) abort();
		orig_dlvsym = dlsym(RTLD_NEXT, "dlvsym");
		if (!orig_dlvsym) abort();
	}
	void *ret = orig_dlvsym(handle, symbol, version);
	
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

/* FIXME: do the stuff here that we do for dlopen above. */
void *dlmopen(long nsid, const char *file, int mode)
{
	static void *(*orig_dlmopen)(long, const char*, int);
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dlmopen)
	{
		if (__avoid_libdl_calls && !we_set_flag) abort();
		orig_dlmopen = dlsym(RTLD_NEXT, "dlmopen");
		if (!orig_dlmopen) abort();
	}
	void *ret = orig_dlmopen(nsid, file, mode);
	
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

int dladdr1(const void *addr, Dl_info *info, void **extra, int flags)
{
	static int(*orig_dladdr1)(const void*, Dl_info *, void**, int);
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	
	if (!orig_dladdr1)
	{
		if (__avoid_libdl_calls && !we_set_flag) abort();
		orig_dladdr1 = dlsym(RTLD_NEXT, "dladdr1");
		if (!orig_dladdr1) abort();
	}
	int ret = orig_dladdr1(addr, info, extra, flags);
	
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

struct dl_phdr_info;
int dl_iterate_phdr(
                 int (*callback) (struct dl_phdr_info *info,
                                  size_t size, void *data),
                 void *data)
{
	write_string("Blah8\n");
	static int(*orig_dl_iterate_phdr)(int (*) (struct dl_phdr_info *info,
		size_t size, void *data), void*);
	
	_Bool we_set_flag = 0;
	if (!__avoid_libdl_calls) { we_set_flag = 1; __avoid_libdl_calls = 1; }
	write_string("Blah9\n");
	
	if (!orig_dl_iterate_phdr)
	{
		write_string("Blah10\n");
		if (__avoid_libdl_calls && !we_set_flag) abort();
		write_string("Blah11\n");
		orig_dl_iterate_phdr = dlsym(RTLD_NEXT, "dl_iterate_phdr");
		write_string("Blah12\n");
		if (!orig_dl_iterate_phdr) abort();
	}
	write_string("Blah13\n");
	struct link_map *l = get_highest_loaded_object_below(__builtin_return_address(0));
	write_string("Blah13.5\n");
	fprintf(stderr, "dl_iterate_phdr called from %s+0x%x\n", l->l_name, 
		(unsigned) ((char*) __builtin_return_address(0) - (char*) l->l_addr));
	fflush(stderr);
	int ret = orig_dl_iterate_phdr(callback, data);
	write_string("Blah14\n");
	
	if (we_set_flag) __avoid_libdl_calls = 0;
	return ret;
}

static void init(void) __attribute__((constructor));
static void init(void)
{
	/* We have to initialize these in a constructor, because if we 
	 * do it lazily we might find that the first call is in an 
	 * "avoid libdl" context. HMM, but then we just use fake_dlsym
	 * to get the original pointer and call that. so doing it lazily
	 * is okay, it seems. */
	write_string("Hello from preload init!\n");
	
}

void abort(void) __attribute__((visibility("protected")));
void abort(void)
{
	/* Give ourselves time to attach a debugger. */
	write_string("Aborting program ");
	raw_write(2, get_exe_basename(), strlen(get_exe_basename()));
	write_string(", pid ");
	int pid = raw_getpid();
	char a;
	a = '0' + ((pid / 10000) % 10); raw_write(2, &a, 1);
	a = '0' + ((pid / 1000) % 10); raw_write(2, &a, 1);
	a = '0' + ((pid / 100) % 10); raw_write(2, &a, 1);
	a = '0' + ((pid / 10) % 10); raw_write(2, &a, 1);
	a = '0' + (pid % 10); raw_write(2, &a, 1);
	write_string(", from address ");
	write_ulong((unsigned long) __builtin_return_address(0));
	write_string(", in 10 seconds\n");

	sleep(10);
	raw_kill(pid, 6);
	__builtin_unreachable();
}
