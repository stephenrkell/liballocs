#ifndef RELF_H_
#define RELF_H_

#include <elf.h>
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

NOT POSSIBLE without syscalls, libdl/allocation or nonportable logic
- get auxv
- get phdrs

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
		RT_CONSISTENT,
		RT_ADD,
		RT_DELETE
	} r_state;
	ElfW(Addr) r_ldbase;
};

extern ElfW(Dyn) _DYNAMIC[];
extern struct R_DEBUG_STRUCT_TAG _r_debug __attribute__((weak));

static inline
struct LINK_MAP_STRUCT_TAG*
get_lowest_loaded_object_above(void *ptr);

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
	 * - The caller also supplies a pointer to the initial stack.
	 *   any environment pointer which is *greater* than this value
	 *   will be treated as a pointer into the auxv env, and used
	 *   as a basis for search. For sanity, we check that no loaded object
	 *   has a *higher* base address. */
	struct link_map *found = get_lowest_loaded_object_above(stackptr);
	if (found)
	{
		__assert_fail("no object loaded above stack", __FILE__, __LINE__, __func__);
	}
	
	for (const char **p_str = &environ[0]; *p_str; ++p_str)
	{
		if (*p_str > (const char*) stackptr)
		{
			/* We're pointing at chars high on the stack. 
			 * Search *downwards* for a zero word followed by a nonzero word. 
			 * This is the boundary between the AT_NULL record and the last
			 * non-terminator record in the auxv.
			 *  
			 * We assume that if there is padding between the auxv and asciiz, it is all zeroes,
			 * and that the asciiz data does not contain all-zero words. */
			uintptr_t *searchp = (uintptr_t*) ((uintptr_t) stackptr & ~(sizeof (uintptr_t) - 1));
			while (!(!*searchp && *(searchp-1))) --searchp;
			
			/* Now searchp points to the last word of the entry preceding the AT_NULL. So... */
			ElfW(auxv_t) *at_null = (ElfW(auxv_t) *) (searchp + 1);
			ElfW(auxv_t) *at_search = at_null;
			while (*(((uintptr_t *) at_search - 1))) --at_search;
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
ElfW(Dyn) *dynamic_lookup(ElfW(Dyn) *d, ElfW(Addr) tag)
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
	ElfW(Dyn) *found = dynamic_lookup(_DYNAMIC, DT_DEBUG);
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
struct LINK_MAP_STRUCT_TAG*
get_lowest_loaded_object_above(void *ptr)
{
	/* Walk all the loaded objects' load addresses. 
	 * The load address we want is the next-higher one. */
	struct LINK_MAP_STRUCT_TAG *lowest_higher_seen = NULL;
	for (struct LINK_MAP_STRUCT_TAG *l = find_r_debug()->r_map; l; l = l->l_next)
	{
		if (!lowest_higher_seen || 
				((char*) l->l_addr < (char*) lowest_higher_seen->l_addr
					&& (char*) l->l_addr > (char*) ptr))
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
	ElfW(Word) (*buckets)[nbucket] = (void*) &hash[2];
	ElfW(Word) (*chains)[nchain] = (void*) &hash[2 + nbucket];

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
