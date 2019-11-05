#ifndef ALLOCMETA_H_
#define ALLOCMETA_H_

#include <sys/resource.h> /* for rlim_t */
#include <sys/time.h>
#include <elf.h>
#include <dlfcn.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <link.h> /* for ElfW() */
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
#include <cstdbool>
#endif

#include "allocmeta-defs.h"
#include "bitmap.h"

struct liballocs_err;
typedef struct liballocs_err *liballocs_err_t;

struct big_allocation;
#if !defined(_GNU_SOURCE) && !defined(HAVE_DLADDR) /* FIXME: proper autoconf'able test */
typedef struct {
	const char *dli_fname;
	void       *dli_fbase;
	const char *dli_sname;
	void       *dli_saddr;
} Dl_info;
#endif

/* A tentative meta-protocol for allocators. 
 * 
 * Assume:
 * 
 * - liballocs can tell us which allocator a given allocation came from
 *       (at leaf; also a chain of allocators)
 * - stacks are allocation pools too
 * 
 * Question:
 * 
 * - what can we then ask the allocator to do for us?
 *
 * Examples:
 * 
 * - move the object internally (give it a fresh address & update pointers)
 * - resize the allocation, preserving its contents if possible
 * - change type of the allocation (erasing contents?)
 * - migrate (hand-off) the allocation to another allocator
 * - enumerate all local objects
 * - enumerate *globally* all references to a local object?
 * - or enumerate locally all references to a possibly-remote object?
 * - ... the latter, I think
 * 
 * Notes:
 * 
 * - some objects are not resizable 
 * - references can cross allocators
 * - ... but we might want to preserve some invariants about that
 */

typedef enum { DISCIPL_ANY, DISCIPL_BASE_ONLY, DISCIPL_ASK_FIRST } addr_discipl_t;
/* Two concerns: 
 * - what event signifies the end of the lifetime? Ideally in a form that can be observed. 
 *      -- the goal here is to enable observation of end-of-life.
 * - what is a necessary and sufficient condition for that event *not* to occur?
 *      -- the goal here is to enable *extending* the allocation's life
 */
typedef enum { LT_EVENT_PROC_CALL, LT_EVENT_FRAME_EXEC_PT } lifetime_end_event_t; // these are all patterns over ucontexts
typedef enum { LT_COND_UNKNOWN, LT_COND_REACHABLE_IN } lifetime_cond_t;         // stack and manual are "unknown"
typedef struct lifetime_policy_s
{
	lifetime_end_event_t end_event;
	union
	{
		struct
		{
			void *fun_entry;
			unsigned nargs;
			intptr_t *argbuf;
		} call_event;
		struct
		{
			void *thread;
			void *sp;
			void *ip;
		} frame_event;
	} u_end;
	
	lifetime_cond_t cond;
	union
	{
		struct
		{
			
		} unknown;
		struct 
		{
			struct allocator *allocator;
		} reachable;
	} u_cond;
} lifetime_policy_t;

struct allocated_chunk;              /* the start of an allocation, opaquely */
struct alloc_metadata;               /* metadata associated with a chunk */

/* The idealised base-level allocator protocol. These operations are mostly
   to be considered logically; some allocators (e.g. stack, GC) "inline" them
   rather than defining them as entry points. However, some allocators do define
   corresponding entry points, like malloc; here it would make sense to implement 
   these operations as an abstraction layer. I'm not yet sure how useful this is. */
#define ALLOC_BASE_API(fun, arg) \
fun(struct allocated_chunk *,alloc_uninit   ,arg(size_t, sz),arg(size_t,align),arg(struct uniqtype *,t)) \
fun(struct allocated_chunk *,alloc_zero     ,arg(size_t, sz),arg(size_t,align),arg(struct uniqtype *,t)) \
fun(void,                    free           ,arg(struct allocated_chunk *,start)) \
fun(_Bool,                   resize_in_place,arg(struct allocated_chunk *,start),arg(size_t,new_sz)) \
fun(struct allocated_chunk *,safe_migrate,   arg(struct allocated_chunk *,start),arg(struct allocator *,recipient)) /* may fail */\
fun(struct allocated_chunk *,unsafe_migrate, arg(struct allocated_chunk *,start),arg(struct allocator *,recipient)) /* needn't free existing (stack) */\
fun(void,                    register_suballoc,arg(struct allocated_chunk *,start),arg(struct allocator *,suballoc))

/* The *process-wide* reflective interface of liballocs.
 * FIXME: maybe this should always take
 *     a struct allocator
 * and a struct big_allocation *maybe_the_allocation
 * and a struct containing_bigalloc?
 * Can we compress these into only one or two arguments?
 * If we pass the "relevant bigalloc", then either
 * the allocator itself is the suballocator, or
 * the allocator itself allocated the suballoc. Either way
 * that's all the information we need. So the FIXME is: do
 * the refactoring, starting with set_type and set_size. */
#define ALLOC_REFLECTIVE_API(fun, arg) \
fun(struct uniqtype *  ,get_type,      arg(void *, obj)) /* what type? */ \
fun(void *             ,get_base,      arg(void *, obj))  /* base address? */ \
fun(unsigned long      ,get_size,      arg(void *, obj))  /* size? */ \
fun(const char *       ,get_name,      arg(void *, obj))  /* name? */ \
fun(const void *       ,get_site,      arg(void *, obj))  /* where allocated?   optional   */ \
fun(liballocs_err_t    ,get_info,      arg(void *, obj), arg(struct big_allocation *, maybe_alloc), arg(struct uniqtype **,out_type), arg(void **,out_base), arg(unsigned long*,out_size), arg(const void**, out_site)) \
fun(struct big_allocation *,ensure_big,arg(void *, obj)) \
fun(Dl_info            ,dladdr,        arg(void *, obj))  /* dladdr-like -- only for static*/ \
fun(lifetime_policy_t *,get_lifetime,  arg(void *, obj)) \
fun(addr_discipl_t     ,get_discipl,   arg(void *, site)) /* what will the code (if any) assume it can do with the ptr? */ \
fun(_Bool              ,can_issue,     arg(void *, obj), arg(off_t, off)) \
fun(size_t             ,raw_metadata,  arg(struct allocated_chunk *,start),arg(struct alloc_metadata **, buf)) \
fun(liballocs_err_t    ,set_type,      arg(struct big_allocation *, maybe_the_allocation), arg(void *, obj), arg(struct uniqtype *,new_t)) /* optional (stack) */\
fun(liballocs_err_t    ,set_site,      arg(struct big_allocation *, maybe_the_allocation), arg(void *, obj), arg(struct uniqtype *,new_t)) /* optional (stack) */

#define __allocmeta_fun_arg(argt, name) argt
#define __allocmeta_fun_ptr(rett, name, ...) \
	rett (*name)( __VA_ARGS__ );

struct allocator
{
	const char *name;
	unsigned min_alignment;
	_Bool is_cacheable; /* HACK. FIXME: check libcrunch / is_a_cache really gets invalidated by all allocators. */
	ALLOC_REFLECTIVE_API(__allocmeta_fun_ptr, __allocmeta_fun_arg)
	/* Put the base API last, because it's least likely to take non-NULL values. */
	ALLOC_BASE_API(__allocmeta_fun_ptr, __allocmeta_fun_arg)
};

/* Declare the top-level functions. FIXME: many of these are not defined
 * anywhere. FIXME: do we want to use 'protected' to make the __liballocs_-
 * prefixed ones non-overridable for internal calls? */
#define __liballocs_toplevel_fun_decl(rett, name, ...) \
	rett __liballocs_ ## name( __VA_ARGS__ ); \
	rett alloc_ ## name( __VA_ARGS__ );
ALLOC_REFLECTIVE_API(__liballocs_toplevel_fun_decl, __allocmeta_fun_arg)
// we can also ask for the allocator
struct allocator *alloc_get_allocator(void *obj);
void *__liballocs_get_alloc_base(void *); /* alias of __liballocs_get_base */

/* Which allocators do we have? */
extern struct allocator __stack_allocator;
extern struct allocator __stackframe_allocator;
extern struct allocator __mmap_allocator; /* mmaps */
extern struct allocator __sbrk_allocator; /* sbrk() */
extern struct allocator __static_file_allocator;
extern struct allocator __static_segment_allocator;
extern struct allocator __static_section_allocator;
extern struct allocator __static_symbol_allocator;
extern struct allocator __auxv_allocator; /* nests under stack? */
extern struct allocator __alloca_allocator; /* nests under stack? */
// FIXME: These are indexes, not allocators
extern struct allocator __generic_malloc_allocator; /* covers all chunks */
extern struct allocator __generic_small_allocator; /* usual suballoc impl */
extern struct allocator __generic_uniform_allocator; /* usual suballoc impl */
// extern struct allocator __global_malloc_allocator;
// extern struct allocator __libc_malloc_allocator; // good idea? probably not
// extern struct allocator __global_obstack_allocator;

// FIXME: we should probably have per-allocator headers for the stuff below

#define ALLOCATOR_HANDLE_LIFETIME_INSERT(a) ((a) == &__generic_malloc_allocator)

void __mmap_allocator_init(void);
void __mmap_allocator_notify_mmap(void *ret, void *requested_addr, size_t length, 
	int prot, int flags, int fd, off_t offset, void *caller);
void __mmap_allocator_notify_mremap_before(void *old_addr, size_t old_size, 
	size_t new_size, int flags, void *new_address, void *caller);
void __mmap_allocator_notify_mremap_after(void *ret_addr, void *old_addr, size_t old_size, 
	size_t new_size, int flags, void *new_address, void *caller);
void __mmap_allocator_notify_munmap(void *addr, size_t length, void *caller);
_Bool __mmap_allocator_is_initialized(void) __attribute__((visibility("hidden")));
_Bool __mmap_allocator_notify_unindexed_address(const void *ptr);
struct mapping_entry;
struct mapping_sequence;
struct mapping_entry *__mmap_allocator_find_entry(const void *addr, struct mapping_sequence *seq)
	__attribute__((visibility("protected")));

void __auxv_allocator_notify_init_stack_mapping_sequence(struct big_allocation *b);

void __static_file_allocator_init(void);
void __static_file_allocator_notify_load(void *handle, const void *load_site);
void __static_file_allocator_notify_unload(const char *copied_filename);

struct segment_metadata
{
	unsigned phdr_idx;
	struct sym_or_reloc_rec *metavector; /* addr-sorted list of relevant dynsym/symtab/extrasym/reloc entries */
	size_t metavector_size;
	bitmap_word_t *starts_bitmap; // maybe!
};
typedef unsigned short allocsite_id_t;
struct allocsites_vectors_by_base_id_entry; // opaque here

/* Hmm -- with -Wl,-q we might get lots of reloc section mappings. Is this enough? */
#define MAPPING_MAX 16

struct file_metadata
{
	const char *filename;
	const void *load_site;
	struct link_map *l;

	void *meta_obj_handle; /* loaded by us */
	ElfW(Sym) *extrasym;

	ElfW(Phdr) *phdrs; /* always mapped or copied by ld.so */
	ElfW(Half) phnum;
	unsigned nload; /* number of segments that are LOADs */

	ElfW(Sym) *dynsym; /* always mapped by ld.so */
	unsigned char *dynstr; /* always mapped by ld.so */
	unsigned char *dynstr_end;

	ElfW(Half) dynsymndx; // section header idx of dynsym, or 0 if none such
	ElfW(Half) dynstrndx;

	struct extra_mapping
	{
		void *mapping_pagealigned;
		off_t fileoff_pagealigned;
		size_t size;
	} extra_mappings[MAPPING_MAX];

	ElfW(Ehdr) *ehdr;
	ElfW(Shdr) *shdrs;
	unsigned char *shstrtab;
	ElfW(Sym) *symtab; // NOTE this really is symtab, not dynsym
	ElfW(Half) symtabndx;
	unsigned char *strtab; // NOTE this is strtab, not dynstr
	ElfW(Half) strtabndx;

	// FIXME: mapping the rel sections should go away.
	/* We want to be able to identify any relocation record in the binary
	 * using a single "index space", even though there may be many reloc
	 * sections (e.g. if linking -q). So we maintain a "spine" with one
	 * unsigned per (non-empty) reloc section, holding the index in the
	 * "global" numbering of the first reloc in that section. We also
	 * keep pointers to those sections here, which we map as needed. */
	unsigned *rel_spine_idxs;    // the indices
	ElfW(Rela) **rel_spine_scns; // pointers to the mapped sections
	unsigned rel_spine_len;      // how many elements

	struct allocsites_vectors_by_base_id_entry *allocsites_info;

	/* "Starts" are symbols with length (spans).
	   We don't index symbols that are not spans.
	   If we see multiple spans covering the same address, we discard one
	   of them heuristically.
	   The end result is a list of spans, in address order, with distinct starts.
	   Our sorted metavector has one record per indexed span.
	   Logically the content is a pointer to its ELF metadata *and* its type.
	   For spans that are in dynsym, it points to their dynsym entry.
	*/
	struct segment_metadata segments[];
};
#define FILE_META_DESCRIBES_EXECUTABLE(meta) \
	((meta)->l->l_name && (meta)->l->l_name[0] == '\0') /* FIXME: better test? */
#define STARTS_BITMAP_NWORDS_FOR_PHDR(ph) \
    (ROUND_UP((ph)->p_vaddr + (ph)->p_memsz, sizeof (void*)) - ROUND_DOWN((ph)->p_vaddr, sizeof (void*)) \
    / (sizeof (void*)))

inline 
ElfW(Sym) *__static_file_allocator_get_symtab_by_idx(struct file_metadata *meta, ElfW(Half) i)
{
	if (meta->symtab && meta->symtabndx == i) return meta->symtab;
	else if (meta->dynsym && meta->dynsymndx == i) return meta->dynsym;
	return NULL;
}
void __static_segment_allocator_init(void);
void __static_segment_allocator_notify_define_segment(
	struct file_metadata *meta,
	unsigned phndx,
	unsigned loadndx
);
void __static_section_allocator_init(void);
void __static_section_allocator_notify_define_section(
	struct file_metadata *meta,
	const ElfW(Shdr) *shdr
);
void __static_symbol_allocator_init(void);
liballocs_err_t __static_symbol_allocator_get_info(void * obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site) __attribute__((visibility("protected")));

void __stack_allocator_init(void);
_Bool __stack_allocator_notify_unindexed_address(const void *ptr);
extern void *__top_of_initial_stack __attribute__((visibility("protected")));
extern rlim_t __stack_lim_cur __attribute__((visibility("protected")));

void __auxv_allocator_init(void);
void __alloca_allocator_init(void);
void __generic_malloc_allocator_init(void);
void __generic_small_allocator_init(void);
void __generic_uniform_allocator_init(void);

liballocs_err_t __generic_heap_get_info(void * obj, struct big_allocation *maybe_bigalloc, 
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void **out_site);

_Bool __auxv_get_asciiz(const char **out_start, const char **out_end, struct uniqtype **out_uniqtype);
_Bool __auxv_get_argv(const char ***out_start, const char ***out_terminator, struct uniqtype **out_uniqtype);
_Bool __auxv_get_env(const char ***out_start, const char ***out_terminator, struct uniqtype **out_uniqtype);
_Bool __auxv_get_auxv(const Elf64_auxv_t **out_start, Elf64_auxv_t **out_terminator, struct uniqtype **out_uniqtype);
void *__auxv_get_program_entry_point(void);

#ifdef _GNU_SOURCE
/* Macro which open-codes a binary search over a sorted array
 * of T, returning a pointer to the highest element that
 * is greater than or equal to the target. To get an integer
 * value out of a T t, we use proj(t). */
#define /* T* */  bsearch_leq_generic(T, target_proj_val, /*  T*  */ base, /* unsigned */ n, proj) \
	({ \
		T *upper = base + n; \
		T *lower = base; \
		if (upper - lower == 0) abort(); \
		assert(proj(lower) <= target_proj_val); \
		while (upper - lower != 1) \
		{ \
			T *mid = lower + ((upper - lower) / 2); \
			if (proj(mid) > target_proj_val) \
			{ \
				/* we should look in the lower half */ \
				upper = mid; \
			} \
			else lower = mid; \
		} \
		assert(proj(lower) <= target_proj_val); \
		/* if we didn't hit the max item, assert the next one is greater */ \
		assert(lower == base + n - 1 \
			 || proj(lower+1) > target_proj_val); \
		/* If all elements are > the target, return NULL */ \
		proj(lower) <= target_proj_val ? lower : NULL; \
	})
#endif

static inline uintptr_t vaddr_from_rec(struct sym_or_reloc_rec *p,
	struct file_metadata *file)
{
	ElfW(Sym) *symtab;
	switch (p->kind)
	{
		case REC_DYNSYM:   symtab = file->dynsym; goto sym;
		case REC_SYMTAB:   symtab = file->symtab; goto sym;
		case REC_EXTRASYM: symtab = file->extrasym; goto sym;
		sym:
			return symtab[p->idx].st_value;
		case REC_RELOC_DYN: symtab = file->dynsym; goto rel;
		case REC_RELOC:     symtab = file->symtab; goto rel;
		rel:
			// the awkward case
			/* (1) use precomputed spine to get the reloc section+idx,
			   (2) decode the r_info to get the target section/symbol + addend,
			   (3) get the symbol/section's address and do the add.
			 */
			{
#if 1
				// find the greatest spine element le this value
				// the spine should have no repeated elements!
				// FIXME: lift this out into a bsearch_le function.
				unsigned target = p->idx;
				unsigned *upper = file->rel_spine_idxs + file->rel_spine_len;
				unsigned *lower = file->rel_spine_idxs;
				if (upper - lower == 0) abort();
				assert(lower[0] <= target);
				while (upper - lower != 1)
				{
					unsigned *mid = lower + ((upper - lower) / 2);
					if (*mid > target)
					{
						// we should look in the lower half
						upper = mid;
					}
					else lower = mid;
				}
				assert(lower[0] <= target);
				// if we didn't find the max item, assert the next one is greater
				assert(lower == file->rel_spine_idxs + file->rel_spine_len - 1
					 || lower[1] > target);
				// the reloc is in the given section, at the residual index
				unsigned *found = lower;
#else /* FIXME: introduce this code and test against the vanilla non-generic version! */
#define proj(tptr) *(tptr)
				unsigned *found = bsearch_leq_generic(unsigned, p->idx,
					/*  T*  */ file->rel_spine_idxs, /* unsigned */ file->rel_spine_len, proj);
#undef proj
#endif
				unsigned residual_idx = p->idx - *found;
				unsigned scn_idx = lower - file->rel_spine_idxs;
				assert(scn_idx < file->rel_spine_len);
				ElfW(Rela) *the_reloc = file->rel_spine_scns[scn_idx] + residual_idx;
				unsigned symind = ELF64_R_SYM(the_reloc->r_info);
				ElfW(Sword) addend = the_reloc->r_addend;
				return symtab[symind].st_value + addend;
			}
		default: abort();
	}
}

/* liballocs assumes some fixed structure in the first couple of levels of the hierarchy.
 * 
 *                           ______ (imaginary root) ______
 *                          /               |              \
 *                      sbrk               mmap             stack
 *                                          |              /    \
 *                                        static         auxv   alloca
 * 
 * (... or, more precisely, every chunk allocated by one of these allocators has
 * a parent chunk allocated by the parent allocator shown.)
 * 
 * Memory kinds: HEAP, STATIC, STACK and MAPPED_FILE attach to these as you'd expect.
 */

/* liballocs default: fixed population of allocators with their own fixed metadata
 * implementations. All suballocated chunks are considered to be managed by the small
 * allocator, say, whichever SUBALLOC function created them.
 * 
 * Alternative: one allocator identity per suballoc function. But then multiple
 * "allocators" [functions] might beallocating out of the same chunk, which would
 * violate our model.
 * 
 * Obviously this doesn't match with reality. It's really an indexing scheme that
 * we're designating, not an allocator per se. But elaborating this structure faithfully
 * would require more info from the user than what LIBALLOCS_* env vars currently get. */

/* Key point:
 * - core liballocs implements the reflective protocol 
     for OS (incl stack) and libc (malloc) allocators
 * - "deep" indexing routines also detect and register suballoc, 
     and provide *generic* implementation of the reflective interface
 * - an allocator is free to register itself explicitly with
     a (more efficient) implementation of the reflective interface
 * - allocators are only obliged to handle issued addresses
     (liballocs never issues addresses for them)
 * - allocators *are* obliged to check addressing discipline of 
 *   the returned-to code
 */

/* The allocator's contract with liballocs:
 * 
 * Consider TLAB / GC-nursery allocation metadata.
 * One way is to define a protocol between liballocs and the allocator 
 * on thread-local metadata buffers.
 * We could write an inline function in C which
 * records an allocation in the buffer,
 * as a ready-made helper function that most VMs could plumb in, 
 * even though the "official" protocol is defined in shared memory.
 *
 * In fact this generalises. 
 * All our link-time allocator wrappers are just an opportunity
 * to make outcalls publishing the existence of a fresh allocation.
 * We could abstract that into a metaprotocol, by which allocators must call liballocs.
 * The point about the inline function is that
 * we don't want to force them to pay the cost of a function call; 
 * we want something more local that just compiles into
 * a few instructions' work on hot/local memory.
 */

#endif
