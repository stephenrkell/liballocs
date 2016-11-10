#ifndef RELF_H_
#define RELF_H_

#include <stddef.h> /* for offsetof */
#include <elf.h>
/* #include <link.h> -- we don't do this because it can pollute us with libc stuff
 * when clients (like trap-syscalls) want to use us in sub-libc (asm-level) code. 
 * Use RELF_DEFINE_STRUCTURES instead. */
#include <string.h>

extern void 
__assert_fail (const char *assertion, const char *file,
	unsigned int line, const char *function) __attribute__((__noreturn__));
extern char **environ;
extern void abort(void) __attribute__((noreturn));

/* 

ELF introspection routines.

Some properties:

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
#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT ((void*)0) /* HACK: GNU-specific? */
#endif
#ifndef RTLD_NEXT
#define RTLD_NEXT ((void*)-1) /* HACK: GNU-specific? */
#endif

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
ElfW(Dyn) *dynamic_lookup(ElfW(Dyn) *d, ElfW(Sword) tag)
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
ElfW(Dyn) *dynamic_xlookup(ElfW(Dyn) *dyn, ElfW(Sword) tag)
{
	ElfW(Dyn) *found = dynamic_lookup(dyn, tag);
	if (!found) __assert_fail("expected dynamic tag", __FILE__, __LINE__, __func__);
	return found;
}

static inline
ElfW(Dyn) *local_dynamic_xlookup(ElfW(Sword) tag)
{
	return dynamic_xlookup(_DYNAMIC, tag);
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
// 	/* If we have DT_DEBUG in our _DYNAMIC, try that. */
// 	ElfW(Dyn) *found = &_DYNAMIC ? dynamic_lookup(_DYNAMIC, DT_DEBUG) : NULL;
// 	if (found) return (struct R_DEBUG_STRUCT_TAG *) found->d_un.d_ptr;
// 	else
// 	{
// 		/* HMM. We need to get the _DYNAMIC section from another object, 
// 		 * like ld.so or the executable. Can we do this portably? I don't think so. */
// 		
// 		/* Fall back to the _r_debug "convention" */
// 		if (NULL != &_r_debug)
// 		{
// 			return &_r_debug;
// 		}
// 		__assert_fail("found r_debug", __FILE__, __LINE__, __func__);
// 	}
	return &_r_debug;
}
static inline
struct LINK_MAP_STRUCT_TAG*
get_highest_loaded_object_below(void *ptr)
{
	/* Walk all the loaded objects' load addresses. 
	 * The load address we want is the next-lower one. */
	struct LINK_MAP_STRUCT_TAG *highest_lower_seen = NULL;
	for (struct LINK_MAP_STRUCT_TAG *l = find_r_debug()->r_map; l; l = l->l_next)
	{
		if ((char*) l->l_addr <= (char*) ptr
			&& (!highest_lower_seen || 
				(char*) l->l_addr > (char*) highest_lower_seen->l_addr))
		{
			highest_lower_seen = l;
		}
	}
	return highest_lower_seen;
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

static inline void *get_local_load_addr(void)
{
	return (void*) get_highest_loaded_object_below(&get_local_load_addr)->l_addr;
}

extern int _etext;
static inline void *get_local_text_segment_end(void)
{
	char *our_load_addr = get_local_load_addr();
	uintptr_t etext_value = (uintptr_t) &_etext;
	// MONSTER HACK: sometimes _etext references are relocated, others not.
	// FIXME: understand this.
	if (etext_value > (uintptr_t) our_load_addr) return (char*) etext_value;
	else return our_load_addr + etext_value;
}

// HACK: not actually possible in general, because we use phdrs
static inline void *get_text_segment_end_from_load_addr(void *load_addr)
{
	/* monster HACK; consider searching for an _etext or etext symbol first */
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) load_addr;
	ElfW(Phdr) *phdrs = (ElfW(Phdr) *)((char*) ehdr + ehdr->e_phoff);
	return load_addr + phdrs[0].p_memsz; // another monster HACK
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
	ElfW(Word) nchain __attribute__((unused)) = hash[1];
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
			/* match! FIXME: symbol type filter, FIXME: versioning */
			found_sym = p_sym;
			break;
		}
	}
	
	return found_sym;
}

static inline uint_fast32_t
dl_new_hash(const char *s)
{
	uint_fast32_t h = 5381;
	for (unsigned char c = *s; c != '\0'; c = *++s)
	{
		h = h * 33 + c;
	}
	return h & 0xffffffff;
}

static inline
ElfW(Sym) *gnu_hash_lookup(ElfW(Word) *gnu_hash, ElfW(Sym) *symtab, const char *strtab, const char *sym)
{
	ElfW(Sym) *found_sym = NULL;
	uint32_t hashval = dl_new_hash(sym);
	/* see: https://sourceware.org/ml/binutils/2006-10/msg00377.html */
	uint32_t *gnu_hash_words = (uint32_t *) gnu_hash;
	uint32_t nbuckets = gnu_hash_words[0];
	uint32_t symbias = gnu_hash_words[1]; // only symbols at symbias up are gnu_hash'd
	uint32_t maskwords = gnu_hash_words[2]; // number of ELFCLASS-sized words in pt2 of table
	uint32_t shift2 = gnu_hash_words[3];

	ElfW(Off) *bloom = (ElfW(Off) *) &gnu_hash_words[4];
	uint32_t *buckets = (uint32_t*) (bloom + maskwords);
	uint32_t *hasharr = buckets + nbuckets;
	
	
	/* Symbols in dynsyn (from symbias up) are sorted by ascending hash % nbuckets.
	 * The Bloom filter has k == 2, where the two different hash functions are
	 *   (1) the low-order 5 or 6 bits of dl_new_hash  (resp. on 32- and 64-bit ELF)
	 *   (2) the 5 or 6 bits starting from bit index `shift2' of the same. 
	 * 
	 * EXCEPT wait. both of these hash values are used to index the *same* word
	 * of the Bloom filter. So it's not one Bloom filter; it's a vector of one-word
	 * Bloom filters, of length `maskwords'. The particular word is extracted via

	  ElfW(Addr) bitmask_word
	    = bitmask[(new_hash / __ELF_NATIVE_CLASS)
		      & map->l_gnu_bitmask_idxbits]; // means maskwords - 1
	
	  meaning we wrap around: each word-sized Bloom filter covers a family of
	  hash values, each with varying low-order bits (we divide away the 5 or 6 lower bits)
	  but the same middle-order bits (the number depends on the choice of maskwords,
	  being some power of two; e.g. if we have 32 words, hashes with the same middle 
	  5 bits will be directed into the same word-sized Bloom filter).
	
	  Or I suppose you can think of this as one big Bloom filter where the two hash 
	  functions say:
	  
	  "take the high-and-middle-order bits of dl_new_hash,
	        append the low- (k==1) or somewhere-in-middle- (k==2) order 5 or 6 bits,
	        then look at the bottom ~14 bits of that" (for maskwords == 256 a.k.a. 2^8)
	
	  i.e. we've chosen shift2 and maskwords so that the middle-order bits we append
	  for the second hash function DON'T overlap with the high-and-middle-order
	  bits that we actually look at (bits 6..13 in the example above,
	  cf. shift2 which is 14, so positions 0..5 contain bits 14..19 of the dl_new_hash).
	  This does mean that the two hash values share their high-order bits (both are
	  bits 6..13 of the dl_new_hash value). I'm sure this increases the false-positive
	  rate of the Bloom filter, since for any given hashval, we hash it to the same
	  word of the filter. Oh well... we still have 32--64 bits to play with.
	
	  The Bloom filter has no correspondence with the bucket structure -- it just records
	  whether a given hash is in the table or not.
	 */

	ElfW(Off) bloom_word
		= bloom[(hashval / (8*sizeof(ElfW(Off))))
				& (maskwords - 1)];

	unsigned int hash1_bitoff = hashval & (8*sizeof(ElfW(Off)) - 1);
	unsigned int hash2_bitoff = ((hashval >> shift2) & (8*sizeof(ElfW(Off)) - 1));

	if ((bloom_word >> hash1_bitoff) & 0x1 
			&& (bloom_word >> hash2_bitoff) & 0x1)
	{
		/* buckets are in the range 0..nbuckets.
		 * and bucket N contain the lowest M
		 * for which the hash % nbuckets of dynsym entry M's name
		 * equals N, or 0 for no such M.
		 * 
		 * The hash array (part four of the table) contains words such that word M
		 * is the hash of dynsyn N, with the low bit cleared,
		 * ORed with a new value for the low bit: 
		 * 1 if N is the maximum value (dynsymcount - 1)
		 *   or if symbol N was hashed into a different bucket than symbol N+1,
		 * 0 otherwise.
		 * 
		 * How do we use this array to walk a particular bucket?
		 * Recall that symbols in dynsym are sorted by ascending hash % nbuckets.
		 * In other words, they are grouped into ranges of equal hash % nbuckets already.
		 * The order in part four mirrors this ordering, but stores hashes (and one bit).
		 * So we basically want to walk this range of the array, from first to last.
		 * The low bit tells us when we've hit the end of the range.
		 * The bucket array tells us the starting index.
		 * Simples!
		 */
		
		uint32_t lowest_symidx = buckets[hashval % nbuckets]; // might be 0
		for (uint32_t symidx = lowest_symidx; 
				symidx; 
				symidx = (!(hasharr[symidx - symbias] & 1)) ? symidx + 1 : 0)
		{
			/* We know that hash-mod-nbuckets equals the right value,
			 * but what about the hash itself? Test this before we bother
			 * doing the full comparison. We have to live with not being
			 * able to test the lowest bit. */
			if (((hasharr[symidx - symbias] ^ hashval) >> 1) == 0)
			{
				if (0 == strcmp(&strtab[symtab[symidx].st_name], sym))
				{
					found_sym = &symtab[symidx];
					break;
				}
			}
		}
	}
	
	return found_sym;
}

static inline
ElfW(Sym) *hash_lookup_local(const char *sym)
{
	ElfW(Word) *hash = (ElfW(Word) *) local_dynamic_xlookup(DT_HASH)->d_un.d_ptr;
	if ((intptr_t) hash < 0) return NULL; // HACK: x86-64 vdso workaround
	unsigned long local_base = (unsigned long) get_local_load_addr();
	if ((unsigned long) hash < local_base) return NULL; // HACK: x86-64 vdso workaround
	ElfW(Sym) *symtab = (ElfW(Sym) *) local_dynamic_xlookup(DT_SYMTAB)->d_un.d_ptr;
	const char *strtab = (const char *) local_dynamic_xlookup(DT_STRTAB)->d_un.d_ptr;
	return hash_lookup(hash, symtab, strtab, sym);
}

static inline
ElfW(Sym) *gnu_hash_lookup_local(const char *sym)
{
	ElfW(Word) *hash = (ElfW(Word) *) local_dynamic_xlookup(DT_GNU_HASH)->d_un.d_ptr;
	if ((intptr_t) hash < 0) return NULL; // HACK: x86-64 vdso workaround
	unsigned long local_base = (unsigned long) get_local_load_addr();
	if ((unsigned long) hash < local_base) return NULL; // HACK: x86-64 vdso workaround
	ElfW(Sym) *symtab = (ElfW(Sym) *) local_dynamic_xlookup(DT_SYMTAB)->d_un.d_ptr;
	const char *strtab = (const char *) local_dynamic_xlookup(DT_STRTAB)->d_un.d_ptr;
	return gnu_hash_lookup(hash, symtab, strtab, sym);
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

static inline 
uintptr_t guess_page_size_unsafe(void)
{
	int x;
	ElfW(auxv_t) *p_auxv = get_auxv((const char **) environ, &x);
	if (!p_auxv) abort();
	return auxv_xlookup(p_auxv, AT_PAGESZ)->a_un.a_val;
}

static inline 
void *get_exe_handle(void)
{
	int x;
	ElfW(auxv_t) *p_auxv = get_auxv((const char **) environ, &x);
	if (!p_auxv) abort();
	void *entry = (void*) auxv_xlookup(p_auxv, AT_ENTRY)->a_un.a_val;
	return get_highest_loaded_object_below(entry);
}
#define ROUND_DOWN(p, align) \
	(((uintptr_t) (p)) % (align) == 0 ? ((uintptr_t) (p)) \
	: (uintptr_t) ((align) * ((uintptr_t) (p) / (align))))
#define ROUND_UP(p, align) \
	(((uintptr_t) (p)) % (align) == 0 ? ((uintptr_t) (p)) \
	: (uintptr_t) ((align) * (1 + ((uintptr_t) (p) / (align)))))
#define ROUND_DOWN_PTR(p, align) \
	((void*) (ROUND_DOWN((p), (align))))
#define ROUND_UP_PTR(p, align) \
	((void*) (ROUND_UP((p), (align))))

static inline 
ElfW(Sym) *symbol_lookup_linear_local(const char *sym)
{
	ElfW(Sym) *symtab = (ElfW(Sym) *) local_dynamic_xlookup(DT_SYMTAB)->d_un.d_ptr;
	if ((intptr_t) symtab < 0) return NULL; // HACK: x86-64 vdso workaround
	const char *strtab = (const char *) local_dynamic_xlookup(DT_STRTAB)->d_un.d_ptr;
	if ((intptr_t) strtab < 0) return NULL; // HACK: x86-64 vdso workaround
	const char *strtab_end = strtab + local_dynamic_xlookup(DT_STRSZ)->d_un.d_val;
	/* Round down to the alignment of ElfW(Sym). */
	ElfW(Sym) *symtab_end = ROUND_DOWN_PTR(strtab, sizeof (ElfW(Sym)));
	return symbol_lookup_linear(symtab, symtab_end, strtab, strtab_end, sym);
}

static inline
unsigned long dynamic_symbol_count(ElfW(Dyn) *dyn, struct LINK_MAP_STRUCT_TAG *l)
{
	unsigned long nsyms = 0;
	ElfW(Dyn) *dynstr_ent = NULL;
	unsigned char *dynstr = NULL;
	ElfW(Dyn) *dynsym_ent = dynamic_lookup(dyn, DT_SYMTAB);
	if (!dynsym_ent) return 0;
	ElfW(Sym) *dynsym = (ElfW(Sym) *) dynsym_ent->d_un.d_ptr;
	if ((intptr_t) dynsym < 0) return 0; // HACK: x86-64 vdso workaround
	
	ElfW(Dyn) *hash_ent = (ElfW(Dyn) *) dynamic_lookup(dyn, DT_HASH);
	ElfW(Word) *hash = NULL;
	if (hash_ent)
	{
		/* Got the SysV-style hash table. */
		hash = (ElfW(Word) *) hash_ent->d_un.d_ptr;
		if ((intptr_t) hash < 0) return 0; // HACK: x86-64 vdso workaround
		if ((char*) hash < (char*) l->l_addr) return 0; // HACK: x86-64 vdso workaround
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
		if ((intptr_t) dynstr < 0) return 0; // HACK: x86-64 vdso workaround
		assert((unsigned char *) dynstr > (unsigned char *) dynsym);
		// round down, because dynsym might be padded
		nsyms = (dynstr - (unsigned char *) dynsym) / sizeof (ElfW(Sym));
	}
	return nsyms;
}

static inline 
ElfW(Sym) *symbol_lookup_in_object(struct LINK_MAP_STRUCT_TAG *l, const char *sym)
{
	ElfW(Dyn) *hash_ent = dynamic_lookup(l->l_ld, DT_HASH);
	ElfW(Word) *hash = hash_ent ? (ElfW(Word) *) hash_ent->d_un.d_ptr : NULL;
	if ((intptr_t) hash < 0) return 0; // HACK: x86-64 vdso workaround
	if ((uintptr_t) hash < l->l_addr) return 0; // HACK: x86-64 vdso workaround
	ElfW(Dyn) *gnu_hash_ent = dynamic_lookup(l->l_ld, DT_GNU_HASH);
	ElfW(Word) *gnu_hash = gnu_hash_ent ? (ElfW(Word) *) gnu_hash_ent->d_un.d_ptr : NULL;
	if ((intptr_t) gnu_hash < 0) return 0; // HACK: x86-64 vdso workaround
	if ((uintptr_t) gnu_hash < l->l_addr) return 0; // HACK: x86-64 vdso workaround
	ElfW(Sym) *symtab = (ElfW(Sym) *) dynamic_xlookup(l->l_ld, DT_SYMTAB)->d_un.d_ptr;
	if ((intptr_t) symtab < 0) return 0; // HACK: x86-64 vdso workaround
	ElfW(Sym) *symtab_end = symtab + dynamic_symbol_count(l->l_ld, l);
	const char *strtab = (const char *) dynamic_xlookup(l->l_ld, DT_STRTAB)->d_un.d_ptr;
	if ((intptr_t) strtab < 0) return 0; // HACK: x86-64 vdso workaround
	const char *strtab_end = strtab + dynamic_xlookup(l->l_ld, DT_STRSZ)->d_un.d_val;
	
	/* Try the GNU hash lookup, if we can. Or else try SvsV hash. 
	 * If we found no hash table of either kind, try linear. */
	ElfW(Sym) *found_sym = NULL;
	ElfW(Sym) *found = NULL;
	if (gnu_hash) found = gnu_hash_lookup(gnu_hash, symtab, strtab, sym);
	else if (hash) found = hash_lookup(hash, symtab, strtab, sym);
	else found = symbol_lookup_linear(symtab, symtab_end, strtab, strtab_end, sym);
	return found;
}

/* preserve NULLs */
#define LOAD_ADDR_FIXUP_IN_OBJ(l, p) \
	((!(p)) ? NULL : ((void*) ((char*) (p)) + (l->l_addr)))
#define LOAD_ADDR_FIXUP(p, p_into_obj) \
	LOAD_ADDR_FIXUP_IN_OBJ( (uintptr_t) (get_link_map( (p_into_obj) )), (p) )

static inline
void *sym_to_addr(ElfW(Sym) *sym)
{
	if (!sym) return NULL;
	return LOAD_ADDR_FIXUP(sym->st_value, sym);
}

static inline
void *sym_to_addr_in_object(struct LINK_MAP_STRUCT_TAG *l, ElfW(Sym) *sym)
{
	if (!sym) return NULL;
	return LOAD_ADDR_FIXUP_IN_OBJ(l, sym->st_value);
}

static inline
void *fake_dlsym(void *handle, const char *symname)
{
	/* Which object do we want? It's either
	 * "the first" (RTLD_DEFAULT);
	 * "the one after us (RTLD_NEXT);
	 * "this one". */

	struct LINK_MAP_STRUCT_TAG *default_match = NULL;
	struct LINK_MAP_STRUCT_TAG *ourselves = NULL;
	struct LINK_MAP_STRUCT_TAG *handle_match = NULL;
	
	for (struct LINK_MAP_STRUCT_TAG *l = _r_debug.r_map;
			l;
			l = l->l_next)
	{
		_Bool had_seen_ourselves = (ourselves != NULL);

		if (l->l_ld == _DYNAMIC)
		{
			ourselves = l;
		}
		
		/* Is this object eligible? */
		if (handle == l
				|| handle == RTLD_DEFAULT
				|| (handle == RTLD_NEXT && had_seen_ourselves))
		{
			/* Does this object have the symbol? */
			ElfW(Sym) *found = symbol_lookup_in_object(l, symname);
			if (found && found->st_shndx != SHN_UNDEF)
			{
				/* HACK for ifunc */
				if (ELF64_ST_TYPE(found->st_info) == STT_GNU_IFUNC)
				{
					void *(*ifunc)(void) = sym_to_addr(found);
					return ifunc();
				}
				else return sym_to_addr(found);
			}
			
			if (handle == l)
			{
				/* Symbol not found. We can stop now. */
				goto not_found;
			}
			// else continue around the loop
		}
	}
	
not_found:
	/* Symbol not found. FIXME: we really want to set dlerror, but we can't. 
	 * Ideally we'd make a libdl call that sets it to something. But we can't
	 * reliably do that from here. Instead, we use MAP_FAILED to signal error. */
	return (void*) -1;
	
}

#endif
