#include "systrap.h"
#include "do-syscall.h"
#define RELF_DEFINE_STRUCTURES
#include "relf.h"
#include "maps.h"

/* We also get linked in from libcrunch's stubs file, which lacks most of liballocs. 
 * So only call out to the hooks if they're present. */
void __liballocs_nudge_mmap(void **p_addr, size_t *p_length, int *p_prot, int *p_flags,
                  int *p_fd, off_t *p_offset, const void *caller) __attribute__((weak));
void __mmap_allocator_notify_munmap(void *addr, size_t length) __attribute__((weak));
void __mmap_allocator_notify_mremap_before(void *old_addr, size_t old_size, size_t new_size, int flags, void *new_address)
			__attribute__((weak));
void __mmap_allocator_notify_mremap_after(void *ret, void *old_addr, size_t old_size, size_t new_size, int flags, void *new_address)
			__attribute__((weak));
void __mmap_allocator_notify_mmap(void *ret, void *requested_addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
			__attribute__((weak));

/* avoid standard headers */
char *realpath(const char *path, char *resolved_path);
int snprintf(char *str, size_t size, const char *format, ...);
int open(const char *pathname, int flags);
int close(int fd);

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
	
	/* Nudge them. */
	if (&__liballocs_nudge_mmap)
	{	
		__liballocs_nudge_mmap(&addr, &length, &prot, &flags, 
			&fd, &offset, s->saved_context->pretcode);
	}
	
	/* Re-pack them. */
	s->args[0] = (long int) addr;
	s->args[1] = length;
	s->args[2] = prot;
	s->args[3] = flags;
	s->args[4] = fd;
	s->args[5] = offset;
	
	/* Do the call. */
	long int ret = do_syscall6(s);

	/* If it did something, notify the allocator. */
	if ((void*) ret != (void*) -1 && &__mmap_allocator_notify_mmap)
	{
		__mmap_allocator_notify_mmap((void*) ret, addr, length, prot, flags, fd, offset);
	}

	/* Do the post-handling. */
	post(s, ret);
	
	/* We need to do our own resumption also. */
	resume_from_sigframe(ret, s->saved_context, /* HACK */ 2);
}

void munmap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void munmap_replacement(struct generic_syscall *s, post_handler *post)
{
	/* Unpack the mmap arguments. */
	void *addr = (void*) s->args[0];
	size_t length = s->args[1];
	
	/* Do the call. */
	long int ret = do_syscall2(s);
	
	/* If it did something, notify the allocator. */
	if (ret == 0 && &__mmap_allocator_notify_munmap) __mmap_allocator_notify_munmap(addr, length);
	
	/* Do the post-handling. */
	post(s, ret);
	
	/* We need to do our own resumption also. */
	resume_from_sigframe(ret, s->saved_context, /* HACK */ 2);
}

void mremap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void mremap_replacement(struct generic_syscall *s, post_handler *post)
{
	/* Unpack the mmap arguments. */
	/* Unpack the mmap arguments. */
	void *old_addr = (void*) s->args[0];
	size_t old_length = s->args[1];
	size_t new_length = s->args[2];
	int flags = s->args[3];
	void *maybe_new_address = (void*) s->args[4];
	
	/* Pre-notify the allocator. This is so it can grab the "prot". */
	if (&__mmap_allocator_notify_mremap_before)
	{
		__mmap_allocator_notify_mremap_before(old_addr, old_length, new_length, flags, 
			maybe_new_address);
	}	
	
	/* Do the call. */
	long int ret = do_syscall5(s);
	
	// FIXME: also nudge mremaps
	
	/* Whether or not it did something, notify the allocator. */
	if (&__mmap_allocator_notify_mremap_after)
	{
		__mmap_allocator_notify_mremap_after((void*) ret, old_addr, old_length, new_length, flags, 
			maybe_new_address);
	}
	
	/* Do the post-handling. */
	post(s, ret);
	
	/* We need to do our own resumption also. */
	resume_from_sigframe(ret, s->saved_context, /* HACK */ 2);
}

static int trap_ldso_cb(struct proc_entry *ent, char *linebuf, size_t bufsz, void *interpreter_fname_as_void)
{
	const char *interpreter_fname = (const char *) interpreter_fname_as_void;
	if (ent->x == 'x' && 0 == strcmp(interpreter_fname, ent->rest))
	{
		/* It's an executable mapping in the ld.so, so trap it. */
		trap_one_executable_region((unsigned char *) ent->first, (unsigned char *) ent->second,
			interpreter_fname, ent->w == 'w', ent->r == 'r');
	}
	
	return 0;
}

extern ElfW(Dyn) _DYNAMIC[];
_Bool __liballocs_systrap_is_initialized; /* globally visible, so that it gets overridden. */
/* This is logically a constructor, since it's important that it happens before
 * much stuff has been memory-mapped. BUT we have to hand off smoothly from the
 * mmap allocator, which processes /proc. So it will call us when it's done that.
 * Does this also avoid the "two copies" problem we had before. But it does mean
 * that libcrunch's stubs library has to call us explicitly. */
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
	/* Get a hold of the ld.so's link map entry. How? We get it from the auxiliary
	 * vector. */
	const char *interpreter_fname = NULL;
	ElfW(auxv_t) *auxv = get_auxv((const char **) environ, &interpreter_fname);
	if (!auxv) abort();
	ElfW(auxv_t) *auxv_at_base = auxv_lookup(auxv, AT_BASE);
	if (!auxv_at_base) abort();
	const void *interpreter_base = (const void *) auxv_at_base->a_un.a_val;
	for (struct link_map *l = find_r_debug()->r_map; l; l = l->l_next)
	{
		if ((const void *) l->l_addr == interpreter_base)
		{
			interpreter_fname = realpath(l->l_name, &realpath_buf[0]);
		}
	}
	if (!interpreter_fname) abort();
	struct proc_entry entry;
	char proc_buf[4096];
	int ret;
	ret = snprintf(proc_buf, sizeof proc_buf, "/proc/%d/maps", getpid());
	if (!(ret > 0)) abort();
	int fd = open(proc_buf, O_RDONLY);
	if (fd == -1) abort();
	char linebuf[8192];
	for_each_maps_entry(fd, linebuf, sizeof linebuf, &entry, trap_ldso_cb, (void*) interpreter_fname);
	close(fd);

	/* Also trap the mmap and mmap64 calls in the libc so. Again, we use relf
	 * routines to look them up. How do we identify libc in the link map?
	 * We don't! Instead, look for anything called "mmap" in any *other* object
	 * than ourselves (... HACK/workaround: that doesn't have a weird address
	 * or absent name -- these are vdso or other abominations). */
	for (struct link_map *l = find_r_debug()->r_map; l; l = l->l_next)
	{
		if ((const void *) l->l_ld != &_DYNAMIC && (intptr_t) l->l_addr > 0
			&& strlen(l->l_name) > 0)
		{
			ElfW(Dyn) *dynsym_ent = dynamic_lookup(l->l_ld, DT_SYMTAB);
			if (!dynsym_ent) continue;
			ElfW(Sym) *dynsym = (ElfW(Sym) *) dynsym_ent->d_un.d_ptr;
			/* nasty hack for getting the end of dynsym */
			ElfW(Dyn) *dynstr_ent = dynamic_lookup(l->l_ld, DT_STRTAB);
			if (!dynstr_ent) continue;
			char *dynstr = (char *) dynstr_ent->d_un.d_ptr;
			assert((char *) dynstr > (char *) dynsym);
			ElfW(Dyn) *dynstrsz_ent = dynamic_lookup(l->l_ld, DT_STRSZ);
			if (!dynstrsz_ent) continue;
			unsigned long dynstrsz = dynstrsz_ent->d_un.d_val;
			ElfW(Sym) *dynsym_end = dynsym + dynamic_symbol_count(l->l_ld);

			/* Now we can look up symbols. */
			ElfW(Sym) *found_mmap = symbol_lookup_linear(dynsym, dynsym_end, dynstr, 
				dynstr + dynstrsz, "mmap");
			if (found_mmap && found_mmap->st_shndx != STN_UNDEF)
			{
				trap_one_instruction_range((unsigned char *)(l->l_addr + found_mmap->st_value), 
					(unsigned char *)(l->l_addr + found_mmap->st_value + found_mmap->st_size),
					0, 1);
			}
			ElfW(Sym) *found_mmap64 = symbol_lookup_linear(dynsym, dynsym_end, dynstr, 
				dynstr + dynstrsz, "mmap64");
			if (found_mmap64 && found_mmap64->st_shndx != STN_UNDEF)
			{
				trap_one_instruction_range((unsigned char *)(l->l_addr + found_mmap64->st_value), 
					(unsigned char *)(l->l_addr + found_mmap64->st_value + found_mmap64->st_size),
					0, 1);
			}
		}
	}
	install_sigill_handler();
	__liballocs_systrap_is_initialized = 1;
}
