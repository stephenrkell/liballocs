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
 * case, and once here to intercept the fast case. 
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

/* We should be safe to use it once malloc is initialized. */
// #define safe_to_use_mappings (__liballocs_is_initialized)
#define safe_to_use_mappings (l0index)
#define safe_to_call_dlsym (safe_to_call_malloc)

/* some signalling to malloc hooks */
_Bool __avoid_calling_dl_functions;

static const char *filename_for_fd(int fd)
{
	/* We read from /proc into a thread-local buffer. */
	static char __thread out_buf[8192];
	
	static char __thread proc_path[4096];
	int ret = snprintf(proc_path, sizeof proc_path, "/proc/%d/fd/%d", getpid(), fd);
	assert(ret > 0);
	ret = readlink(proc_path, out_buf, sizeof out_buf);
	assert(ret != -1);
	out_buf[ret] = '\0';
	
	return out_buf;
}

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
	 * We could just ask the l0index.
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

	_Bool is_stack = (__liballocs_get_memory_kind(ptr) == STACK);
	
	if (is_stack)
	{
		return *(((unsigned long *) ptr) - 1);
	}
	else return //__real_malloc_usable_size(ptr);
       	__mallochooks_malloc_usable_size(ptr);
}
#pragma GCC pop_options

/* Libraries that extend us can define this to control mmap placement policy. */
void __liballocs_nudge_mmap(void **p_addr, size_t *p_length, int *p_prot, int *p_flags,
                  int *p_fd, off_t *p_offset, const void *caller) __attribute__((weak));

void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
	/* HACK: let through the memtable mmaps and other things that 
	 * run before our constructor. These will get called *very* early,
	 * before malloc is initialized, hence before it's safe to call
	 * libdl. Therefore, instead of orig_mmap, we use syscall() 
	 * in these cases.
	 */

	if (!safe_to_use_mappings || !safe_to_call_dlsym)
	{
		// call via syscall and skip hooking logic
		return (void*) (uintptr_t) syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
	}

	static void *(*orig_mmap)(void *, size_t, int, int, int, off_t);
	if (!orig_mmap)
	{
		orig_mmap = dlsym(RTLD_NEXT, "mmap");
		assert(orig_mmap);
	}
	
	if (&__liballocs_nudge_mmap)
	{
		__liballocs_nudge_mmap(&addr, &length, &prot, &flags, &fd, &offset, __builtin_return_address(0));
	}
	void *ret = orig_mmap(addr, length, prot, flags, fd, offset);
	if (ret != MAP_FAILED)
	{
		mapping_flags_t f = { .kind = (fd == -1) ? HEAP : MAPPED_FILE, 
			.r = (flags & PROT_READ), 
			.w = (flags & PROT_WRITE),
			.x = (flags & PROT_EXEC) 
		};
		const char *data_ptr = (fd == -1) ? NULL : filename_for_fd(fd);
		/* Add to the prefix tree */
		mapping_add(ret, ROUND_UP_TO_PAGE_SIZE(length), f, data_ptr);
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
	
	if (!safe_to_use_mappings) return orig_munmap(addr, length);
	else
	{
		int ret = orig_munmap(addr, length);
		if (ret == 0)
		{
			mapping_del(addr, ROUND_UP_TO_PAGE_SIZE(length));
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
	
	void *new_address;
	if (flags & MREMAP_FIXED)
	{
		va_start(ap, flags);
		new_address = va_arg(ap, void *);
		va_end(ap);
	}
	
#define orig_call ((flags & MREMAP_FIXED)  \
			? orig_mremap(old_addr, old_size, new_size, flags, new_address) \
			: orig_mremap(old_addr, old_size, new_size, flags))
	
	if (!safe_to_use_mappings) 
	{
		return orig_call;
	}
	else
	{
		void *ret = orig_call;
		if (ret != MAP_FAILED)
		{
			struct mapping_info *cur = mapping_lookup(old_addr);
			assert(cur != NULL);
			struct mapping_info saved = *cur;
			mapping_del(old_addr, ROUND_UP_TO_PAGE_SIZE(old_size));
			mapping_add_full(ret, ROUND_UP_TO_PAGE_SIZE(new_size), &saved);
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
	if (!orig_dlopen) // happens if we're called before liballocs init
	{
		__avoid_calling_dl_functions = 1;
		orig_dlopen = dlsym(RTLD_NEXT, "dlopen");
		__avoid_calling_dl_functions = 0;
		assert(orig_dlopen);
	}
	
	if (!__liballocs_is_initialized) return orig_dlopen(filename, flag);
	else
	{
		__avoid_calling_dl_functions = 1;
		void *ret = orig_dlopen(filename, flag);
		__avoid_calling_dl_functions = 0;
		
		/* Have we just opened a new object? If filename was null, 
		 * we haven't; if ret is null; we haven't; if NOLOAD was passed,
		 * we haven't. Otherwise we *might* have done, but we still
		 * can't be sure. We'll have to make __liballocs_add_all_mappings_cb
		 * tolerant of re-adding. */
		if (filename != NULL && ret != NULL && !(flag & RTLD_NOLOAD))
		{
			if (__libcrunch_scan_lazy_typenames) __libcrunch_scan_lazy_typenames(ret);
		
			/* Note that in general we will get one mapping for every 
			 * LOAD phdr. So we use dl_iterate_phdr. */
			int dlpi_ret = dl_iterate_phdr(__liballocs_add_all_mappings_cb, 
				((struct link_map *) ret)->l_name);
			assert(dlpi_ret != 0);
		
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

		return ret;
	}
}

#define MAX_MAPPINGS 16
struct amapping
{
	void *base;
	size_t size;
};
struct amapping_set
{
	const char *filename;
	void *handle;
	int nmappings;
	struct amapping mappings[MAX_MAPPINGS];
};

static int gather_mappings_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct amapping_set *mappings = (struct amapping_set *) data;
	const char *filename = mappings->filename;
	if (0 == strcmp(filename, info->dlpi_name))
	{
		// this is the file we care about, so iterate over its phdrs
		for (int i = 0; i < info->dlpi_phnum; ++i)
		{
			// if this phdr's a LOAD and matches our filename, 
			if (info->dlpi_phdr[i].p_type == PT_LOAD)
			{
				assert(mappings->nmappings < MAX_MAPPINGS);
				/* Mappings always get rounded up to page size. */
				uintptr_t base = MAPPING_BASE_FROM_PHDR_VADDR(((struct link_map *) mappings->handle)->l_addr,
						info->dlpi_phdr[i].p_vaddr);
				uintptr_t end = MAPPING_END_FROM_PHDR_VADDR(((struct link_map *) mappings->handle)->l_addr,
						info->dlpi_phdr[i].p_vaddr, info->dlpi_phdr[i].p_memsz);
				mappings->mappings[mappings->nmappings++] = (struct amapping) { (void*) base, end - base };
			}
		}
	
		// can stop now
		return 1;
	} // else keep going
	else return 0;
}

int dlclose(void *handle)
{
	static int (*orig_dlclose)(void *);
	static void *(*orig_dlopen)(const char *, int);
	if(!orig_dlclose)
	{
		orig_dlclose = dlsym(RTLD_NEXT, "dlclose");
		orig_dlopen = dlsym(RTLD_NEXT, "dlopen");
		assert(orig_dlclose);
	}
	
	if (!safe_to_use_mappings) return orig_dlclose(handle);
	else
	{
		char *copied_filename = strdup(((struct link_map *) handle)->l_name);
		assert(copied_filename != NULL);
		
		/* Use dl_iterate_phdr to gather the mappings that we will 
		 * remove from the tree *if* the dlclose() actually unloads
		 * the library. */
		struct amapping_set mappings;
		mappings.filename = copied_filename;
		mappings.handle = handle;
		mappings.nmappings = 0;
		int dlpi_ret = dl_iterate_phdr(gather_mappings_cb, &mappings);
		assert(dlpi_ret != 0);
		
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
				for (int i = 0; i < mappings.nmappings; ++i)
				{
					mapping_del(mappings.mappings[i].base, 
						mappings.mappings[i].size);
				}
			}
			else 
			{
				// it wasn't unloaded, so we do nothing
			}
		}
	
	// out:
		free(copied_filename);
		return ret;
	}
}
