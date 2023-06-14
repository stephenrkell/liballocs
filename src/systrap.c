#define _GNU_SOURCE
#include <stddef.h>
#include <alloca.h>
#include <assert.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <link.h>
#include "systrap.h"
#include "raw-syscalls-defs.h"
#include "vas.h"
#include "maps.h"
#include "pageindex.h"
#include "relf.h"

/* Our secret private channel with libdlbind. This must always be linked in,
 * even in libcrunch stubs. */
extern __thread const char *dlbind_open_active_on __attribute__((weak,visibility("hidden")));
/* While weak thread-locals don't actually work (on x86-64).... */
extern int dlbind_dummy __attribute__((weak));

/* NOTE: We also get linked in from libcrunch's stubs file, which lacks most of liballocs.
 * (Read that again. It lacks most of liballocs, not just most of libcrunch.)
 * We used to say "so only call out to the hooks if they're present". But now we define
 * our own nudger, and libcrunch wraps it (or not). */
void __liballocs_nudge_mmap(void **p_addr, size_t *p_length, int *p_prot, int *p_flags,
                  int *p_fd, off_t *p_offset, const void *caller);
void __liballocs_nudge_open(const char **p_pathname, int *p_flags, mode_t *p_mode, const void *caller);
void __liballocs_nudge_openat(int *p_dirfd, const char **p_pathname, int *p_flags, mode_t *p_mode, const void *caller);
void __mmap_allocator_notify_munmap(void *addr, size_t length, void *caller) __attribute__((weak));
void __mmap_allocator_notify_mremap_before(void *old_addr, size_t old_size, size_t new_size, int flags, void *new_address, void *caller)
			__attribute__((weak));
void __mmap_allocator_notify_mremap_after(void *ret, void *old_addr, size_t old_size, size_t new_size, int flags, void *new_address, void *caller)
			__attribute__((weak));
void __mmap_allocator_notify_mmap(void *ret, void *requested_addr, size_t length, int prot, int flags,
                  int fd, off_t offset, void *caller)
			__attribute__((weak));
void __mmap_allocator_notify_mprotect(void *addr, size_t len, int prot)
			__attribute__((weak));
void __mmap_allocator_notify_brk(void *new_curbrk) __attribute__((weak));
void __brk_allocator_notify_brk(void *new_curbrk, const void *caller) __attribute__((weak));
_Bool __static_file_allocator_notify_brk(void *new_curbrk) __attribute__((weak));
_Bool __static_segment_allocator_notify_brk(void *new_curbrk) __attribute__((weak));
extern _Bool __liballocs_is_initialized __attribute__((weak));
int __liballocs_global_init(void);
_Bool is_meta_object_for_lib(struct link_map *maybe_types, struct link_map *l, const char *meta_suffix)
			__attribute__((visibility("hidden")));
/* avoid standard headers */
char *realpath(const char *path, char *resolved_path);
int snprintf(char *str, size_t size, const char *format, ...);
int open(const char *pathname, int flags, ...);
int close(int fd);

#define GUESS_CALLER(s) \
   generic_syscall_get_ip(s)

/*	( (&pageindex && pageindex[ ((uintptr_t) (((s)->saved_context->uc.uc_mcontext).MC_REG(rsp, RSP))) >> LOG_PAGE_SIZE ] != 0) \
		? *(void**) ((uintptr_t) (((s)->saved_context->uc.uc_mcontext).MC_REG(rsp, RSP))) \
		: (void*) (((s)->saved_context->uc.uc_mcontext).MC_REG(rip, RIP)) ) */

void brk_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void brk_replacement(struct generic_syscall *s, post_handler *post)
{
	/* Linux gives us the old value on failure, and the new value on success. 
	 * In other words it always gives us the current sbrk. */
	void *brk_asked_for = (void*) s->args[0];
	/* HMM. Can I do a raw syscall here? It's an out-of-line call, but
	 * within DSO. So it should not be trapped. Right? */
	void *brk_returned = raw_brk(brk_asked_for);
	if (&__brk_allocator_notify_brk) __brk_allocator_notify_brk(brk_returned,
		GUESS_CALLER(s));
	
	/* Do the post-handling and resume. */
	post(s, (long) brk_returned, 1);
}

void mmap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void mmap_replacement(struct generic_syscall *s, post_handler *post)
{
	/* Unpack the mmap arguments. */
	void *addr = (void*) s->args[0];
	size_t length = s->args[1];
	int prot = s->args[2];
	int flags = s->args[3];
	int fd = s->args[4];
	off_t offset = s->args[5];

	void *caller = GUESS_CALLER(s);
	/* Nudge them. */
	__liballocs_nudge_mmap(&addr, &length, &prot, &flags, 
			&fd, &offset, caller);
	
	void *ret = raw_mmap(addr, length, prot, flags, fd, offset);
	/* If it did something, notify the allocator.
	 * HACK: not sure if/where this is documented, but I've seen mmap() return
	 * a "negative" number that is not -1. So we consider any return value that
	 * is less than PAGE_SIZE below (void*)-1 to be an error value. */
	if (!MMAP_RETURN_IS_ERROR(ret) && &__mmap_allocator_notify_mmap)
	{
		__mmap_allocator_notify_mmap(ret, addr, length, prot, flags, fd, offset,
			caller);
	}

	/* Do the post-handling and resume. */
	post(s, (long) ret, 1);
}

void munmap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void munmap_replacement(struct generic_syscall *s, post_handler *post)
{
	/* Unpack the mmap arguments. */
	void *addr = (void*) s->args[0];
	size_t length = s->args[1];
	
	/* Do the call. */
	int ret = raw_munmap(addr, length);
	
	/* If it did something, notify the allocator. */
	if (ret == 0 && &__mmap_allocator_notify_munmap) __mmap_allocator_notify_munmap(addr, length, 
		GUESS_CALLER(s));
	
	/* Do the post-handling and resume. */
	post(s, ret, 1);
}

void mremap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void mremap_replacement(struct generic_syscall *s, post_handler *post)
{
	/* Unpack the mremap arguments. */
	void *old_addr = (void*) s->args[0];
	size_t old_length = s->args[1];
	size_t new_length = s->args[2];
	int flags = s->args[3];
	void *maybe_new_address = (void*) s->args[4];
	
	/* Pre-notify the allocator. This is so it can grab the "prot". */
	if (&__mmap_allocator_notify_mremap_before)
	{
		__mmap_allocator_notify_mremap_before(old_addr, old_length, new_length, flags,
			maybe_new_address, GUESS_CALLER(s));
	}
	
	/* Do the call. */
	void *ret = raw_mremap(old_addr, old_length, new_length, flags, maybe_new_address);
	// FIXME: also nudge mremaps
	
	/* Whether or not it did something, notify the allocator. */
	if (&__mmap_allocator_notify_mremap_after)
	{
		__mmap_allocator_notify_mremap_after(ret, old_addr, old_length, new_length, flags, 
			maybe_new_address, GUESS_CALLER(s));
	}
	
	/* Do the post-handling and resume. */
	post(s, (long) ret, 1);
}

void mprotect_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void mprotect_replacement(struct generic_syscall *s, post_handler *post)
{
	/* Unpack the mprotect arguments. */
	void *addr = (void*) s->args[0];
	size_t length = s->args[1];
	int prot = s->args[2];
	
	int ret = raw_mprotect(addr, length, prot);
	
	if (ret == 0 && &__mmap_allocator_notify_mprotect)
	{
		__mmap_allocator_notify_mprotect(addr, length, prot);
	}

	post(s, ret, 1);
}

void open_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void open_replacement(struct generic_syscall *s, post_handler *post)
{
	/* Unpack the arguments */
	const char *path = (const char *) s->args[0];
	int flags = s->args[1];
	mode_t mode = s->args[2];
	
	/* Nudge them. */
	__liballocs_nudge_open(&path, &flags, &mode, GUESS_CALLER(s));
	
	int ret = raw_open(path, flags, mode);
	
	/* Do the post-handling and resume. */
	post(s, ret, 1);
}

void openat_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void openat_replacement(struct generic_syscall *s, post_handler *post)
{
	/* Unpack the arguments */
	int dirfd = (int) s->args[0];
	const char *path = (const char *) s->args[1];
	int flags = s->args[2];
	mode_t mode = s->args[3];

	/* Nudge them. */
	__liballocs_nudge_openat(&dirfd, &path, &flags, &mode, GUESS_CALLER(s));

	int ret = raw_openat(dirfd, path, flags, mode);

	/* Do the post-handling and resume. */
	post(s, ret, 1);
}

static int maybe_trap_map_cb(struct maps_entry *ent, char *linebuf, void *interpreter_fname_as_void)
{
	const char *interpreter_fname = (const char *) interpreter_fname_as_void;
	if (ent->x == 'x'
#ifdef GUESS_RELEVANT_SYSCALL_SITES
			&& (
				0 == strcmp(interpreter_fname, ent->rest)
				|| 0 == strcmp(basename(ent->rest), "libdl.so.2")
			)
#else
		/* Just don't trap ourselves. Use this function's address to test */
		// NOTE: yes, this is correct. If the mapping spans us, skip it.
		&& !(
			(unsigned char *) ent->first <= (unsigned char *) maybe_trap_map_cb
			&& (unsigned char *) ent->second > (unsigned char *) maybe_trap_map_cb
			)
#endif
		)
	{
		/* It's an executable mapping we want to blanket-trap, so trap it. */
		trap_one_executable_region((unsigned char *) ent->first, (unsigned char *) ent->second,
			ent->rest, ent->w == 'w', ent->r == 'r');
	}
	
	return 0;
}

static _Bool trap_syscalls_in_symbol_named(const char *name, struct link_map *l,
	ElfW(Sym) *dynsym, ElfW(Sym) *dynsym_end, const unsigned char *dynstr, const unsigned char *dynstr_end)
{
	ElfW(Dyn) *gnu_hash_ent = dynamic_lookup(l->l_ld, DT_GNU_HASH);
	ElfW(Sym) *found = gnu_hash_ent ? gnu_hash_lookup((uint32_t*) gnu_hash_ent->d_un.d_ptr, 
		dynsym, dynstr, name) : NULL;
	if (found && found->st_shndx != STN_UNDEF)
	{
		trap_one_instruction_range((unsigned char *)(l->l_addr + found->st_value),
			(unsigned char *)(l->l_addr + found->st_value + found->st_size),
			0, 1);
		return 1;
	} else return 0;
}

extern ElfW(Dyn) _DYNAMIC[];
_Bool __liballocs_systrap_is_initialized; /* globally visible, so that it gets overridden. */
_Bool __lookup_static_allocation_by_name(struct link_map *l, const char *name,
	void **out_addr, size_t *out_len) __attribute__((weak));

static _Bool found_a_brk_or_sbrk;

/* This is logically a constructor, since it's important that it happens before
 * much stuff has been memory-mapped. BUT we have to hand off smoothly from the
 * mmap allocator, which processes /proc. So it will call us when it's done that.
 * This also avoids the "two copies" problem we had before, because only one copy
 * of this symbol will be callable, and the library initializer doesn't call it. 
 * But it does mean that libcrunch's stubs library has to call us explicitly. */
void __liballocs_systrap_init(void)
{
	/* NOTE: in a preload libcrunch run, there are two copies of this code running!
	 * One is in the preload library, the other in the stubs library. We should only
	 * run one of them.
	 * 
	 * Also, it's important that we don't call malloc() in this function, because its
	 * self-call detection will be foiled: we'll be calling *from* the stubs library 
	 * *into* the preload library. It's okay to call malloc from (non-static) things we 
	 * call, because it'll be the preload's copy of that callee that actually gets called.
	 * ARGH, but -Bsymbolic may have screwed with this. Oh, but we don't use it for the 
	 * stubs library, I don't think. Indeed, we don't. */
	if (__liballocs_systrap_is_initialized) return;
	
	static char realpath_buf[4096]; /* bit of a HACK */
	/* Make sure we're trapping all syscalls within ld.so. */
	replaced_syscalls[SYS_mmap] = mmap_replacement;
	replaced_syscalls[SYS_munmap] = munmap_replacement;
	replaced_syscalls[SYS_mremap] = mremap_replacement;
	replaced_syscalls[SYS_brk] = brk_replacement;
	replaced_syscalls[SYS_open] = open_replacement;
	replaced_syscalls[SYS_openat] = openat_replacement;
	/* Get a hold of the ld.so's link map entry. How? We get it from the auxiliary
	 * vector. */
	const char *interpreter_fname = NULL;
	ElfW(auxv_t) *auxv = get_auxv(environ, &interpreter_fname);
	if (!auxv) abort();
	ElfW(auxv_t) *auxv_at_base = auxv_lookup(auxv, AT_BASE);
	if (!auxv_at_base) abort();
	const void *interpreter_base = (const void *) auxv_at_base->a_un.a_val;
	if (interpreter_base == 0)
	{
		/* This means the dynamic linker was run as the program. In that case
		 * AT_EXECFN has the interpreter name. */
		interpreter_fname = realpath((char*) auxv_xlookup(auxv, AT_EXECFN)->a_un.a_val,
				&realpath_buf[0]);
	}
	else
	{
		for (struct link_map *l = find_r_debug()->r_map; l; l = l->l_next)
		{
			if ((const void *) l->l_addr == interpreter_base)
			{
				interpreter_fname = realpath(l->l_name, &realpath_buf[0]);
			}
		}
	}
	if (!interpreter_fname) abort();

	// we're about to start rewriting syscall instructions, so be ready
	install_sigill_handler();
	
	/* FIXME: instead of reading the maps file, use section headers to
	 * figure out the instruction ranges. 
	 * FIXME: trap everything, and use in-fs caching to mitigate the startup
	 * overhead. Specifically, we cache a bunch of relocation records having
	 * a vendor-specific reloc kind R_{ARCH}_SYSCALL_2 for a 2-byte call, etc..*/

	struct maps_entry entry;
	char proc_buf[4096];
	int ret;
	ret = snprintf(proc_buf, sizeof proc_buf, "/proc/%d/maps", getpid());
	if (!(ret > 0)) abort();
	int fd = open(proc_buf, O_RDONLY);
	if (fd == -1) abort();
	/* Copy the whole file into a buffer. */
	const size_t filebuf_sz = 64 * 8192;
	char *filebuf = alloca(64 * 8192); // HACK: guessing maximum /proc/pid/maps file size
	char *filebuf_pos = filebuf;
	const size_t amt_to_read = 4096;
	ssize_t amt_read = 0;
	do
	{
		if (filebuf + filebuf_sz - filebuf_pos < amt_to_read) break; // shouldn't happen
		amt_read = read(fd, filebuf_pos, amt_to_read);
		if (amt_read != -1) filebuf_pos += amt_read;
	} while (amt_read > 0);
	struct maps_buf m = { filebuf, 0, filebuf_pos - filebuf };
	char linebuf[8192];
	for_each_maps_entry((intptr_t) &m, get_a_line_from_maps_buf,
		linebuf, sizeof linebuf, &entry, maybe_trap_map_cb, (void*) interpreter_fname);
	close(fd);
#ifdef GUESS_RELEVANT_SYSCALL_SITES
	/* Also trap the mmap and mmap64 calls in the libc so. Again, we use relf
	 * routines to look them up. How do we identify libc in the link map?
	 * We don't! Instead, look for anything called "mmap" in any *other* object
	 * than ourselves (... HACK/workaround: that doesn't have a weird address
	 * or absent name -- these are vdso or other abominations). */
	_Bool found_an_mmap = 0;
	unsigned char *libc_base = NULL; /* MONSTER HACK */
	for (struct link_map *l = find_r_debug()->r_map; l; l = l->l_next)
	{
		if ((const void *) l->l_ld != &_DYNAMIC && (intptr_t) l->l_addr > 0
			&& strlen(l->l_name) > 0)
		{
			ElfW(Dyn) *dynsym_ent = dynamic_lookup(l->l_ld, DT_SYMTAB);
			if (!dynsym_ent) continue;
			ElfW(Sym) *dynsym = (ElfW(Sym) *) dynsym_ent->d_un.d_ptr;
			if ((intptr_t) dynsym < 0) continue; /* HACK x86-64 vdso bug */
			if ((char*) dynsym < (char*) get_highest_loaded_object_below((void*) l->l_addr)->l_addr) continue; /* HACK x86-64 vdso bug */
			/* nasty hack for getting the end of dynsym */
			ElfW(Dyn) *dynstr_ent = dynamic_lookup(l->l_ld, DT_STRTAB);
			if (!dynstr_ent) continue;
			unsigned char *dynstr = (unsigned char *) dynstr_ent->d_un.d_ptr;
			if ((intptr_t) dynstr < 0) continue; /* HACK x86-64 vdso bug */
			if ((unsigned char*) dynstr < (unsigned char*) get_highest_loaded_object_below((void*) l->l_addr)->l_addr) continue; /* HACK x86-64 vdso bug */
			assert((unsigned char *) dynstr > (unsigned char *) dynsym);
			ElfW(Dyn) *dynstrsz_ent = dynamic_lookup(l->l_ld, DT_STRSZ);
			if (!dynstrsz_ent) continue;
			unsigned long dynstrsz = dynstrsz_ent->d_un.d_val;
			ElfW(Sym) *dynsym_end = dynsym + dynamic_symbol_count(l->l_ld, l);
			
			/* GIANT HACK for __mmap64 in ld.so (glibc ~2.27 onwards) */
			Elf64_Sym *found = symbol_lookup_in_object(l, "__tls_get_addr"); // HACK
			if (found)
			{
				/* It's too soon to use our static object metadata to
				 * figure out whether  thing is called "__mmap64".
				 * So just trap the whole range of ld.so's text segment.
				 * PROBLEM: how to find its text segment?
				 * for a reasonable approximation, go with
				 * the min and max addresses
				 * of its STT_FUNC symbols. */
				unsigned char *min = (void*) -1;
				unsigned char *max = NULL;
				for (ElfW(Sym) *d = dynsym; d != dynsym_end; ++d)
				{
					if (ELF64_ST_TYPE(d->st_info) == STT_FUNC)
					{
						unsigned char *addr = sym_to_addr(d);
						if (addr > max) max = addr;
						if (addr < min) min = addr;
					}
				}
				
				trap_one_executable_region(
					min, max, l->l_name, 0, 0);
			}
			else // not the ld.so
			{
				/* Now we can look up symbols. */
				found_an_mmap |= trap_syscalls_in_symbol_named("mmap",   l, dynsym, dynsym_end, dynstr, dynstr + dynstrsz);
				found_an_mmap |= trap_syscalls_in_symbol_named("mmap64", l, dynsym, dynsym_end, dynstr, dynstr + dynstrsz);
				found_an_mmap |= trap_syscalls_in_symbol_named("__mmap64", l, dynsym, dynsym_end, dynstr, dynstr + dynstrsz);
				trap_syscalls_in_symbol_named("munmap", l, dynsym, dynsym_end, dynstr, dynstr + dynstrsz);
				trap_syscalls_in_symbol_named("mremap", l, dynsym, dynsym_end, dynstr, dynstr + dynstrsz);
				found_a_brk_or_sbrk |= trap_syscalls_in_symbol_named("sbrk", l, dynsym, dynsym_end, dynstr, dynstr + dynstrsz);
				/* PROBLEM: trap-syscalls wants to be able to do open(). 
				 * Surely it should be doing raw_open? And not instrumenting itself? */
				//trap_syscalls_in_symbol_named("open", l, dynsym, dynsym_end, dynstr, dynstr + dynstrsz);
				//trap_syscalls_in_symbol_named("__libc_open64", l, dynsym, dynsym_end, dynstr, dynstr + dynstrsz);
			}
		}
	/* MONSTER HACK TEMPORARY FIXME */
		if (0 == strcmp(l->l_name, "/lib/x86_64-linux-gnu/libc.so.6"))
		{
			libc_base = (void *) l->l_addr;
		}
	} // end for all loaded objects
	/* MONSTER HACK TEMPORARY FIXME */
	assert(libc_base);
	const off_t OPEN64_START = 953744;
	const size_t OPEN64_LEN = 302;
	trap_one_instruction_range(
		(unsigned char *) libc_base + OPEN64_START, (unsigned char *) libc_base + OPEN64_START + OPEN64_LEN,
		0, 1);

	/* There's no hope of us working if we didn't find these. ACTUALLY don't abort
	 * though, because aborting during startup stops gdb from taking control. */
	// if (!found_an_mmap) abort();
	// if (!found_a_brk_or_sbrk) abort();
#else
	/* Just trap the whole bloody lot. */
#endif
	__liballocs_systrap_is_initialized = 1;
}

/* We do a self-call check by comparing addresses against this
 * function's address, so be defensive about overrides. */
void __liballocs_nudge_mmap(void **p_addr, size_t *p_length, int *p_prot, int *p_flags,
                  int *p_fd, off_t *p_offset, const void *caller)
__attribute__((alias("local_liballocs_nudge_mmap")));

extern struct allocator __static_file_allocator;
extern void *__private_malloc_heap_base;
__attribute__((visibility("hidden")))
void local_liballocs_nudge_mmap(void **p_addr, size_t *p_length, int *p_prot, int *p_flags,
                  int *p_fd, off_t *p_offset, const void *caller)
{
	if (&dlbind_dummy && dlbind_open_active_on)
	{
		*p_flags &= ~(0x3 /*MAP_SHARED|MAP_PRIVATE*/);
		*p_flags |= 0x1 /* MAP_SHARED */;
	}
#define IS_SELF_CALL(caller) ( \
	(__private_malloc_heap_base) && \
	__lookup_bigalloc_from_root(caller, &__static_file_allocator, NULL) == \
	__lookup_bigalloc_from_root(local_liballocs_nudge_mmap, &__static_file_allocator, NULL) \
	)
	else if (*p_addr == NULL && IS_SELF_CALL(caller)
		&& !((*p_flags & /*MAP_FIXED*/0x10) || (*p_flags & /*MAP_FIXED_NOREPLACE*/0x100000)))
	{
		/* If we're making a self-call with a NULL addr argument, it's dangerous
		 * because the kernel might plonk it inside an intra-DSO hole that we're yet to plug,
		 * breaking our invariant and causing an abort later during startup. This has been
		 * seen with librunt get_or_map_file_range calls. QUICK HACK: pick an unlikely
		 * address range and use this for internal unhinted calls. FIXME: does this
		 * work if we simply always give the same hint? We just update it assuming our
		 * mmap will succeed.
		 *
		 * Note that we use such an 'mmap' when creating the private mmap area, during
		 * init of the pageindex. That's too soon to do our test for a self call, so
		 * we let that case proceed normally. This is relying on the private malloc heap
		 * being too large an area to fit inside any hole. That is likely true but is
		 * definitely not guaranteed (FIXME). */
		static uintptr_t unhinted_self_call_mmap_area = 0x5000000000; /* FIXME: sysdep */
		*p_addr = (void*) unhinted_self_call_mmap_area;
		unhinted_self_call_mmap_area += *p_length;
	}
}

void __liballocs_nudge_open(const char **p_pathname, int *p_flags, mode_t *p_mode, const void *caller)
{
	if (&dlbind_dummy && dlbind_open_active_on)
	{
		*p_flags &= ~(O_RDWR|O_RDONLY);
		*p_flags |= O_RDWR;
	}
}

void __liballocs_nudge_openat(int *p_dirfd, const char **p_pathname, int *p_flags, mode_t *p_mode, const void *caller)
{
	if (&dlbind_dummy && dlbind_open_active_on)
	{
		*p_flags &= ~(O_RDWR|O_RDONLY);
		*p_flags |= O_RDWR;
	}
}
