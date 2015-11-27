#ifndef RELF_H_
#define RELF_H_

#include <link.h>
#include <stddef.h> /* for offsetof */
#include <elf.h>
/* #include <link.h> -- we don't do this because it can pollute us with libc stuff
 * when clients (like trap-syscalls) want to use us in sub-libc (asm-level) code. 
 * Use RELF_DEFINE_STRUCTURES instead. */
#include <string.h>

extern void 
__assert_fail (const char *assertion, const char *file,
	unsigned int line, const char *function) __attribute__((__noreturn__));

/* 

ELF introspection routines.

Some properties:

- ElfW macro

- do not use libdl/ldso calls likely to do allocation or syscalls (dlopen, dlsym)
- hence safe to use from a no-syscalls-please context (e.g. syscall emulator, allocator instrumentation)

TODO:
- dladdr + cache
- outsource filename issues (i.e. don't read /proc/pid/maps) ? HMM. actually, implement this
- grep -rl ElfW liballocs.hg node/src libcrunch.hg/ rsem/ppcmem/system-call-plumbing/trap-syscalls/src

BARELY POSSIBLE without syscalls, libdl/allocation: or nonportable logic
- get auxv
=> get phdrs
... we use a hacky "likely to work, vaguely portable" method to get auxv

*/

#ifndef ElfW
#define ElfW(t) Elf64_ ## t
#endif

#ifndef LINK_MAP_STRUCT_TAG
#define LINK_MAP_STRUCT_TAG link_map
#endif

#ifndef R_DEBUG_STRUCT_TAG
#define R_DEBUG_STRUCT_TAG r_debug
#endif

#ifndef R_DEBUG_MAKE_ENUMERATOR
#define R_DEBUG_MAKE_ENUMERATOR(p) p
#endif

#ifdef RELF_DEFINE_STRUCTURES
struct LINK_MAP_STRUCT_TAG
{
	ElfW(Addr) l_addr;
	char *l_name;
	ElfW(Dyn) *l_ld;
	struct LINK_MAP_STRUCT_TAG *l_next;
	struct LINK_MAP_STRUCT_TAG *l_prev;
};
struct R_DEBUG_STRUCT_TAG
{
	int r_version;

	struct LINK_MAP_STRUCT_TAG *r_map;
	ElfW(Addr) r_brk;
	enum {
		R_DEBUG_MAKE_ENUMERATOR(RT_CONSISTENT),
		R_DEBUG_MAKE_ENUMERATOR(RT_ADD),
		R_DEBUG_MAKE_ENUMERATOR(RT_DELETE)
	} r_state;
	ElfW(Addr) r_ldbase;
};
#endif

extern ElfW(Dyn) _DYNAMIC[] __attribute__((weak));
extern struct R_DEBUG_STRUCT_TAG _r_debug __attribute__((weak));

static inline
struct LINK_MAP_STRUCT_TAG*
get_lowest_loaded_object_above(void *ptr);

#ifndef ALIGNOF
#define ALIGNOF(t) offsetof (struct { char c; t memb; }, memb)
#endif

static inline
ElfW(auxv_t) *get_auxv(const char **environ, void *stackptr)
{
	/* This somewhat unsound but vaguely portable mechanism for getting auxv
	 * works as follows.
	 * 
	 * - The caller supplies a pointer to an environment table. 
	 *   It is important that at least one environment variable in this
	 *   array comes from the actual auxv, rather than being modified.
	 *   So, e.g. a process which empties out its environment on startup
	 *   would not be able to find the auxv this way after doing the emptying.
	 * 
	 * - The caller also supplies a pointer to the initial stack.
	 *   any environment pointer which is *greater* than this value
	 *   will be treated as a pointer into the auxv env, and used
	 *   as a basis for search. For sanity, we check for any loaded object
	 *   at a *higher* base address (sometimes the vdso gets loaded here),
	 *   and use its load address as an upper bound
	 */
	struct LINK_MAP_STRUCT_TAG *found = get_lowest_loaded_object_above(stackptr);
	void *stack_upper_bound;
	if (found) stack_upper_bound = (void*) found->l_addr;
	else stack_upper_bound = (void*) -1;
	
	for (const char **p_str = &environ[0]; *p_str; ++p_str)
	{
		if (*p_str > (const char*) stackptr && *p_str < (const char *) stack_upper_bound)
		{
			uintptr_t search_addr = (uintptr_t) *p_str;
			/* We're pointing at chars in an asciiz blob high on the stack. 
			 * The auxv is somewhere below us. */
			 
			/* 1. Down-align our pointer to alignof auxv_t. */
			search_addr &= ~(ALIGNOF(ElfW(auxv_t)) - 1);
			
			/* 2. Search *downwards* for a full auxv_t's worth of zeroes
			 * s.t. the next-lower word is a non-zero blob of the same size. 
			 * This is the AT_NULL record; we shouldn't have such a blob
			 * of zeroes elsewhere in this region, because even if we have
			 * 16 bytes of padding between asciiz and auxv, that will only
			 * account for one auxv_t's blob. We assume that what padding
			 * there is is all zeroes, and that asciiz data does not contain 
			 * all-zero chunks.
			 * 
			 * NOTE: not portable to (hypothetical) platforms where AT_NULL 
			 * has a nonzero (but ignored) a_val.
			 */
			
#ifndef AT_MAX
#define AT_MAX 0x1000
#endif
			ElfW(auxv_t) *searchp = (ElfW(auxv_t) *) search_addr;
			#define IS_AT_NULL(p) ((p)->a_type == AT_NULL && (p)->a_un.a_val == 0)
			#define IS_PLAUSIBLE_NONNULL_AT(p) \
				((p)->a_type != AT_NULL && (p)->a_type < AT_MAX)
			/* NOTE: we decrement searchp by _Alignof (auxv_t), *not* its size. */
			#define NEXT_SEARCHP(p) ((ElfW(auxv_t) *) ((uintptr_t) (p) - ALIGNOF(ElfW(auxv_t))))
			/* PROBLEM: we might be seeing a misaligned view: the last word
			 * of AT_NULL, then some padding (zeroes); the searchp-1 will also
			 * be a misaligned view of auxv that easily passes the not-AT_NULL check.
			 * This means we've exited the loop too eagerly! We need to go as far as 
			 * we can, i.e. get the *last* plausible location (this is more robust
			 * than it sounds :-). 
			 * 
			 * OH, but we might *still* be seeing a misaligned view: if the previous
			 * auxv record has a zero a_val, then we'll go back one too far.
			 * So add in the plausibility condition: the a_type field should
			 * be nonzero and less than AT_MAX (HACK: which we make a guess at). */
			while (!(
					    (IS_AT_NULL(searchp)               && IS_PLAUSIBLE_NONNULL_AT(searchp - 1))
					&& !(IS_AT_NULL(NEXT_SEARCHP(searchp)) && IS_PLAUSIBLE_NONNULL_AT(NEXT_SEARCHP(searchp) - 1))
			))
			{
				searchp = NEXT_SEARCHP(searchp);
			}
			#undef IS_AT_NULL
			#undef NEXT_SEARCHP
			ElfW(auxv_t) *at_null = searchp;
			assert(at_null->a_type == AT_NULL && !at_null->a_un.a_val);
			
			/* Search downwards for the beginning of the auxv. How can we
			 * recognise this? It's preceded by the envp's terminating zero word. 
			 * BUT CARE: some auxv entries are zero words! 
			 * How can we distinguish this? Immediately below
			 * auxv is envp, which ends with a NULL word preceded by some 
			 * pointer. All pointer values are higher than auxv tag values! so
			 * we can use that (NASTY HACK) to identify it. 
			 * 
			 * In the very unlikely case that the envp is empty, we will see 
			 * another NULL instead of a pointer. So we can handle that too. */
			ElfW(auxv_t) *at_search = at_null;
			while (!(
					((void**) at_search)[-1] == NULL
				&&  (
						((void**) at_search)[-2] > (void*) AT_MAX
					||  ((void**) at_search)[-2] == NULL
					)
				))
			{
				--at_search;
			}
			/* Now at_search points to the first word after envp's null terminator, i.e. auxv[0]! */
			ElfW(auxv_t) *auxv = at_search;
			return auxv;
		}
	}
	
	return NULL;
}

static inline
ElfW(auxv_t) *auxv_lookup(ElfW(auxv_t) *a, ElfW(Addr) tag)
{
	for (ElfW(auxv_t) *aux = a; aux->a_type != AT_NULL; ++aux)
	{
		if (aux->a_type == tag)
		{
			return aux;
		}
	}
	return NULL;
}

static inline
ElfW(auxv_t) *auxv_xlookup(ElfW(auxv_t) *a, ElfW(Addr) tag)
{
	ElfW(auxv_t) *found = auxv_lookup(a, tag);
	if (!found) __assert_fail("found expected auxv tag", __FILE__, __LINE__, __func__);
	return found;
}

static inline
ElfW(Dyn) *find_dynamic(const char **environ, void *stackptr)
{
	if (&_DYNAMIC[0]) return &_DYNAMIC[0];
	else
	{
		ElfW(auxv_t) *auxv = get_auxv(environ, stackptr);
		if (auxv)
		{
			// ElfW(auxv_t) found_phdr = auxv
			assert(0); // FIXME: Complete
		}
	}
	return NULL; /* shuts up frontc */
}


static inline
ElfW(Dyn) *dynamic_lookup(ElfW(Dyn) *d, ElfW(Sxword) tag)
{
	for (ElfW(Dyn) *dyn = d; dyn->d_tag != DT_NULL; ++dyn)
	{
		if (dyn->d_tag == tag)
		{
			return dyn;
		}
	}
	return NULL;
}

static inline
ElfW(Dyn) *local_dynamic_xlookup(ElfW(Sword) tag)
{
	ElfW(Dyn) *found = dynamic_lookup(_DYNAMIC, tag);
	if (!found) __assert_fail("found expected dynamic tag", __FILE__, __LINE__, __func__);
	return found;
}

static inline 
unsigned long
elf64_hash(const unsigned char *name)
{
	unsigned long h = 0, g;
	while (*name)
	{
		h = (h << 4) + *name++;
		if (0 != (g = (h & 0xf0000000))) h ^= g >> 24;
		h &= 0x0fffffff;
	}
	return h;
}

static inline 
struct R_DEBUG_STRUCT_TAG *find_r_debug(void)
{
	/* If we have DT_DEBUG in our _DYNAMIC, try that. */
	ElfW(Dyn) *found = &_DYNAMIC ? dynamic_lookup(_DYNAMIC, DT_DEBUG) : NULL;
	if (found) return (struct R_DEBUG_STRUCT_TAG *) found->d_un.d_ptr;
	else
	{
		/* HMM. We need to get the _DYNAMIC section from another object, 
		 * like ld.so or the executable. Can we do this portably? I don't think so. */
		
		/* Fall back to the _r_debug "convention" */
		if (NULL != &_r_debug)
		{
			return &_r_debug;
		}
		__assert_fail("found r_debug", __FILE__, __LINE__, __func__);
	}
}
static inline
struct LINK_MAP_STRUCT_TAG*
get_highest_loaded_object_below(void *ptr)
{
	/* Walk all the loaded objects' load addresses. 
	 * The load address we want is the next-lower one. */
	struct LINK_MAP_STRUCT_TAG *highest_seen = NULL;
	for (struct LINK_MAP_STRUCT_TAG *l = find_r_debug()->r_map; l; l = l->l_next)
	{
		if (!highest_seen || 
				((char*) l->l_addr > (char*) highest_seen->l_addr
					&& (char*) l->l_addr <= (char*) ptr))
		{
			highest_seen = l;
		}
	}
	return highest_seen;
}
static inline
struct LINK_MAP_STRUCT_TAG *
get_lowest_loaded_object_above(void *ptr)
{
	/* Walk all the loaded objects' load addresses. 
	 * The load address we want is the next-higher one. */
	struct LINK_MAP_STRUCT_TAG *lowest_higher_seen = NULL;
	for (struct LINK_MAP_STRUCT_TAG *l = find_r_debug()->r_map; l; l = l->l_next)
	{
		if ((char*) l->l_addr > (char*) ptr
				&& (!lowest_higher_seen || 
					(char*) l->l_addr < (char*) lowest_higher_seen->l_addr))
		{
			lowest_higher_seen = l;
		}
	}
	return lowest_higher_seen;
}
static inline
struct LINK_MAP_STRUCT_TAG*
get_link_map(void *ptr)
{
	return get_highest_loaded_object_below(ptr);
}

static inline
ElfW(Sym) *hash_lookup(ElfW(Word) *hash, ElfW(Sym) *symtab, const char *strtab, const char *sym)
{
	ElfW(Sym) *found_sym = NULL;
	ElfW(Word) nbucket = hash[0];
	ElfW(Word) nchain = hash[1];
	/* gcc accepts these funky "dependent types", but frontc doesn't */
	ElfW(Word) (*buckets)[/*nbucket*/] = (void*) &hash[2];
	ElfW(Word) (*chains)[/*nchain*/] = (void*) &hash[2 + nbucket];

	unsigned long h = elf64_hash((const unsigned char *) sym);
	ElfW(Word) first_symind = (*buckets)[h % nbucket];
	ElfW(Word) symind = first_symind;
	for (; symind != STN_UNDEF; symind = (*chains)[symind])
	{
		ElfW(Sym) *p_sym = &symtab[symind];
		if (0 == strcmp(&strtab[p_sym->st_name], sym))
		{
			/* match */
			found_sym = p_sym;
			break;
		}
	}
	
	return found_sym;
}

static inline
ElfW(Sym) *hash_lookup_local(const char *sym)
{
	ElfW(Word) *hash = (ElfW(Word) *) local_dynamic_xlookup(DT_HASH)->d_un.d_ptr;
	ElfW(Sym) *symtab = (ElfW(Sym) *) local_dynamic_xlookup(DT_SYMTAB)->d_un.d_ptr;
	const char *strtab = (const char *) local_dynamic_xlookup(DT_STRTAB)->d_un.d_ptr;
	return hash_lookup(hash, symtab, strtab, sym);
}

static inline 
ElfW(Sym) *symbol_lookup_linear(ElfW(Sym) *symtab, ElfW(Sym) *symtab_end, const char *strtab, const char *strtab_end, const char *sym)
{
	ElfW(Sym) *found_sym = NULL;
	for (ElfW(Sym) *p_sym = &symtab[0]; p_sym <= symtab_end; ++p_sym)
	{
		ssize_t distance_to_strtab_end = strtab_end - &strtab[p_sym->st_name];
		if (distance_to_strtab_end > 0 && 
			0 == strncmp(&strtab[p_sym->st_name], sym, distance_to_strtab_end))
		{
			/* match */
			found_sym = p_sym;
			break;
		}
	}
	
	return found_sym;
}

#define ROUND_DOWN_PTR(p, align) \
	(((uintptr_t) (p)) % (align) == 0 ? ((void*) (p)) \
	: (void*) ((align) * ((uintptr_t) (p) / (align))))

static inline 
ElfW(Sym) *symbol_lookup_linear_local(const char *sym)
{
	ElfW(Sym) *symtab = (ElfW(Sym) *) local_dynamic_xlookup(DT_SYMTAB)->d_un.d_ptr;
	const char *strtab = (const char *) local_dynamic_xlookup(DT_STRTAB)->d_un.d_ptr;
	const char *strtab_end = strtab + local_dynamic_xlookup(DT_STRSZ)->d_un.d_val;
	/* Round down to the alignment of ElfW(Sym). */
	ElfW(Sym) *symtab_end = ROUND_DOWN_PTR(strtab, sizeof (ElfW(Sym)));
	return symbol_lookup_linear(symtab, symtab_end, strtab, strtab_end, sym);
}

static inline
unsigned long dynamic_symbol_count(ElfW(Dyn) *dyn)
{
	unsigned long nsyms = 0;
	ElfW(Dyn) *dynstr_ent = NULL;
	unsigned char *dynstr = NULL;
	ElfW(Dyn) *dynsym_ent = dynamic_lookup(dyn, DT_SYMTAB);
	if (!dynsym_ent) return 0;
	ElfW(Sym) *dynsym = (ElfW(Sym) *) dynsym_ent->d_un.d_ptr;
	
	ElfW(Dyn) *hash_ent = (ElfW(Dyn) *) dynamic_lookup(dyn, DT_HASH);
	ElfW(Word) *hash = NULL;
	if (hash_ent)
	{
		/* Got the SysV-style hash table. */
		hash = (ElfW(Word) *) hash_ent->d_un.d_ptr;
		nsyms = hash[1]; /* nchain, which equals the number of symbols */
	}
	else if (NULL != (hash_ent = (ElfW(Dyn) *) dynamic_lookup(dyn, DT_GNU_HASH)))
	{
		/* Got the GNU-style hash table. 
		 * GAH. Unlike the SysV one, this doesn't tell us the size of the symtab. */
		goto dynsym_nasty_hack;
	}
	else
	{
dynsym_nasty_hack:
		/* Take a wild guess, by assuming dynstr directly follows dynsym. */
		dynstr_ent = dynamic_lookup(dyn, DT_STRTAB);
		assert(dynstr_ent);
		dynstr = (unsigned char *) dynstr_ent->d_un.d_ptr;
		assert((unsigned char *) dynstr > (unsigned char *) dynsym);
		// round down, because dynsym might be padded
		nsyms = (dynstr - (unsigned char *) dynsym) / sizeof (ElfW(Sym));
	}
	return nsyms;
}

/* preserve NULLs */
#define LOAD_ADDR_FIXUP(p, p_into_obj) \
	((!(p)) ? NULL : ((void*) ((char*) (p)) + (uintptr_t) (get_link_map( (p_into_obj) )->l_addr)))

static inline
void *sym_to_addr(ElfW(Sym) *sym)
{
	if (!sym) return NULL;
	return LOAD_ADDR_FIXUP(sym->st_value, sym);
}

#endif
