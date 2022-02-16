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

#include "dso-meta.h"
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


/* liballocs assumes some fixed structure in the first few levels of the hierarchy.
 * Roughly it is as follows.
 *                                   (imaginary root)
 *                                          |
 *                                         mmap
 *                           _______________|______________
 *                          /      /        |          .   \
 *                        brk     /     static-file     .  auxv    (only present for initial stack)
 *                        /      /          |            .   |
 *                      mallocs...     static-segment      stack
 *                                          |                |
 *                                     static-symbol     stackframe
 *                                                           |
 *                                                         alloca
 *
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

/* FIXME: we want to capture the commonality with uniqtype_rel_info's
 * 'memb' anonymous struct case. Currently it looks like this:
 *
 *     struct {
           struct uniqtype *ptr;
           unsigned long off:56;
           unsigned long is_absolute_address:1;
           unsigned long may_be_invalid:1;
       } memb;

 * ... where the absolute-address case is intended for stackframe types
 * where the field actually lives in some saved context outside the frame,
 * i.e. the 'struct' is conceptual only. That is problematic w.r.t. our
 * notion of containment, which really is about physical containment. But
 * if we have a flag for fields-only-conceptually we should be OK.
 * Also remember we need to modify this struct so that it encodes a
 * [begin,end) range rather than just a begin offset.
 */
// FIXME: this is a more general structure than we thought.
// Perhaps rename it 'alloc_coord'? Not so much a coord as a 'tree pos'
// It should be possible to reconstruct the exact object
// address from one of these structs, now that we have the
// maybe_containee_coord.
// FIXME: maybe distinguish "tree pos" from "tree path"
// where only tree path has the encl_* stuff.
// Also remember that a path need not be a path all the way
// back to the root.
// FIXME: container_base isn't needed when we have a bigalloc, because
// the bigalloc records it.
// There's really a few concepts here:
// a "span", a "pos" and a "path"
/*
// HMM. is this really a branch? It can represent leaves too.
// Instead of 'branch' and 'pos', maybe 'pos' and 'link'?
struct alloc_tree_branch
{
	void *base;           // base addr of the containing alloc
	uintptr_t bigalloc_or_uniqtype; // container might be a bigalloc or a uniqtype-described alloc
	// FIXME: this is redundant for bigallocs
	// FIXME: for uniqtypes we need an 'end' address too,
	// especially once we make the arrays change.
	// We can just about fit all three in 128 bits, but not clear this is necessary.
	// could do the short-alloc union trick, although not clear it would help
	// since we rarely heap-allocate these things
	// We could also use the bigalloc *index*, a small integer,
	// rather than the bigalloc pointer. This is probably worth doing.
	union { struct {
		unsigned long  base:48;
		unsigned short bigalloc_idx:16; // MSB is always 0
	 };     struct {
		unsigned long base:48;
		unsigned      always_1:1;  // to discriminate w.r.t. the above -- CHECK bit order
		unsigned long uniqtype:47; // could be reduced to 44
		unsigned      len:32;
	 } // HMM: how does this compare to our 128-bit pointer-with-bounds type?
	   // That has a base but no type.
	   // Its first 64 bits are a raw pointer.
	   // And it only uses 32 bits for the base, relying on a no-cross-4GB-boundary property (or denorm cases)
	};
};
struct alloc_tree_pos
{
	struct alloc_tree_branch container;
	unsigned containee_coord; // where within the container?
};
struct alloc_tree_path
{
	struct alloc_tree_pos cur;
	unsigned encl_depth;
	struct alloc_tree_path *encl;
};

 */
struct alloc_containment_ctxt
{
	void *container_base;           // base addr of the containing alloc
	uintptr_t bigalloc_or_uniqtype; // container might be a bigalloc or a uniqtype-described alloc
	unsigned maybe_containee_coord; // where within the container?
	struct alloc_containment_ctxt *encl; // chain of enclosing contexts...
	unsigned encl_depth;                 // ... 0 if chain is empty
};
#define BOU_BIGALLOC_NOCHECK_(b_o_u) ((struct big_allocation *) ((b_o_u) & UNIQTYPE_PTR_MASK_NOTFLAGS))
#define BOU_UNIQTYPE_NOCHECK_(b_o_u) ((struct uniqtype *) ((b_o_u) & UNIQTYPE_PTR_MASK_NOTFLAGS))

#define BOU_BIGALLOC(b_o_u) (assert(BOU_IS_BIGALLOC(b_o_u)), BOU_BIGALLOC_NOCHECK_(b_o_u))
#define BOU_UNIQTYPE(b_o_u) (assert(BOU_IS_UNIQTYPE(b_o_u)), BOU_UNIQTYPE_NOCHECK_(b_o_u))

#define BOU_IS_BIGALLOC(b_o_u) (((uintptr_t)BOU_BIGALLOC_NOCHECK_(b_o_u) >= (uintptr_t) &big_allocations[1]) \
	&& ((uintptr_t)BOU_BIGALLOC_NOCHECK_(b_o_u) < (uintptr_t) &big_allocations[NBIGALLOCS]))
#define BOU_IS_UNIQTYPE(b_o_u) (!BOU_IS_BIGALLOC(b_o_u))

/* Given a containment context, we should be able
 * to get back various things:
 * the object pointer,
 * its type,
 * and the meaning of its coordinate, e.g. its field name */
#define CONT_UNIQTYPE_FIELD_NAME(c) ( \
   ( (BOU_IS_UNIQTYPE((c)->bigalloc_or_uniqtype)) && \
      UNIQTYPE_IS_COMPOSITE_TYPE(BOU_UNIQTYPE((c)->bigalloc_or_uniqtype))) ? \
      (UNIQTYPE_COMPOSITE_SUBOBJ_NAMES( \
         BOU_UNIQTYPE((c)->bigalloc_or_uniqtype) \
      )[(c)->maybe_containee_coord - 1]) : NULL \
)
#define CONT_UNIQTYPE_FIELD(c) ( \
 ( (BOU_IS_UNIQTYPE((c)->bigalloc_or_uniqtype)) && \
	UNIQTYPE_IS_COMPOSITE_TYPE(BOU_UNIQTYPE((c)->bigalloc_or_uniqtype))) ? \
	(struct uniqtype *)(BOU_UNIQTYPE((c)->bigalloc_or_uniqtype)->related[(c)->maybe_containee_coord - 1].un.memb.ptr) \
	: NULL \
)
#define CONT_UNIQTYPE_ARRAY_ELEMENT(c) ( \
  ((BOU_IS_UNIQTYPE((c)->bigalloc_or_uniqtype)) && \
    UNIQTYPE_IS_ARRAY_TYPE(BOU_UNIQTYPE((c)->bigalloc_or_uniqtype))) \
  ? \
  (BOU_UNIQTYPE((c)->bigalloc_or_uniqtype)->related[0].un.memb.ptr) \
  : NULL \
)
#define CONT_UNIQTYPE(c) ( \
  ((BOU_IS_UNIQTYPE((c)->bigalloc_or_uniqtype)) ? \
	(UNIQTYPE_IS_ARRAY_TYPE(BOU_UNIQTYPE((c)->bigalloc_or_uniqtype))) ? \
	CONT_UNIQTYPE_ARRAY_ELEMENT(c) : \
	(UNIQTYPE_IS_COMPOSITE_TYPE(BOU_UNIQTYPE((c)->bigalloc_or_uniqtype))) ? \
	 CONT_UNIQTYPE_FIELD(c) \
	: NULL \
	: /* FIXME: see below */ NULL) \
)

/* PROBLEM: What about if our obj is a top-level allocation, so lies within a bigalloc
 * but has no *enclosing* uniqtype? I guess we can call the allocator's get_type, since
 * we have the bigalloc and can use its suballocator (which we know exists).
 * We can possibly use the 'coord' field as short-cut to the type, but unclear. */

struct interpreter
{
	const char *name;
	_Bool (*can_interp)(void *, struct uniqtype *, struct alloc_containment_ctxt *);
	void *(*do_interp) (void *, struct uniqtype *, struct alloc_containment_ctxt *);
	_Bool (*may_contain)(void *, struct uniqtype *, struct alloc_containment_ctxt *);
	uintptr_t (*is_environ)(void *, struct uniqtype *, struct alloc_containment_ctxt *);
};
/* Recall: a name resolver is an interpreter of naming languages, which are
 * distinguished from computational languages only by the computational
 * complexity ("linear in the length of the name"). A resolver is also an
 * idempotent allocator, i.e. it creates the name's denotation in memory,
 * only if it is not already available in memory (fsvo 'available'). FIXME:
 * how do such allocations get freed? One possible answer is that they don't;
 * another is that they are either GC'd or are reclaimed only when their
 * wole container is reclaimed, i.e. region-style.
 */

struct allocated_chunk;   /* the start of an allocation, opaquely (gen this per-allocator?) */
struct alloc_metadata;    /* metadata associated with a chunk (ditto?) */
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
 * FIXME: morally this should always take
 *     a struct allocator
 * and a struct big_allocation *maybe_the_allocation
 * and a struct containing_bigalloc?
 * Can we compress these into only one or two arguments?
 * If we pass the "relevant bigalloc", then either
 * the allocator itself is the suballocator, or
 * the allocator itself allocated the suballoc. Either way
 * that's all the information we need. So the FIXME is: do
 * the refactoring to take these arguments consistently.
 * NOTE that maybe_the_allocation args might not be going far
 * enough... do we want maybe_the_allocation_or_arena? */
typedef int walk_alloc_cb_t(struct big_allocation *maybe_the_allocation, void *obj, struct uniqtype *t, const void *allocsite, struct alloc_containment_ctxt *cont, void *arg);
/* An 'imposed child bigalloc' is a child c of bigalloc b
 * where c is not allocated_by the suballocator of b.
 * In other words, te allocator that is nominally managing
 * the space knows nothing about this particular occupant.
 * One example is how the initial stack is imposed on the auxv,
 * which knows nothing about it. There are few or no other
 * examples as yet, but it seems worth retaining this case.
 * (We needed this wacky stack/auxv case because the two can
 * share the same page of memory, and we have an invariant that
 * memory-mapping-sequence bigallocs are page-aligned.) */
enum
{
	ALLOC_WALK_BIGALLOC_IMPOSED_CHILDREN = 0x1
};
#define ALLOC_REFLECTIVE_API(fun, arg) \
fun(struct uniqtype *  ,get_type,      arg(void *, obj)) /* what type? */ \
fun(void *             ,get_base,      arg(void *, obj))  /* base address? */ \
fun(unsigned long      ,get_size,      arg(void *, obj))  /* size? */ \
fun(const char *       ,get_name,      arg(void *, obj), arg(char *, namebuf), arg(size_t, buflen))  /* name? */ \
fun(const void *       ,get_site,      arg(void *, obj))  /* where allocated?   optional   */ \
fun(liballocs_err_t    ,get_info,      arg(void *, obj), arg(struct big_allocation *, maybe_alloc), arg(struct uniqtype **,out_type), arg(void **,out_base), arg(unsigned long*,out_size), arg(const void**, out_site)) \
fun(struct big_allocation *,ensure_big,arg(void *, obj)) \
fun(Dl_info            ,dladdr,        arg(void *, obj))  /* dladdr-like -- only for static*/ \
fun(lifetime_policy_t *,get_lifetime,  arg(void *, obj)) \
fun(addr_discipl_t     ,get_discipl,   arg(void *, site)) /* what will the code (if any) assume it can do with the ptr? */ \
fun(_Bool              ,can_issue,     arg(void *, obj), arg(off_t, off)) \
fun(size_t             ,raw_metadata,  arg(struct allocated_chunk *,start),arg(struct alloc_metadata **, buf)) \
fun(liballocs_err_t    ,set_type,      arg(struct big_allocation *, maybe_the_allocation), arg(void *, obj), arg(struct uniqtype *,new_t)) /* optional (stack) */\
fun(liballocs_err_t    ,set_site,      arg(struct big_allocation *, maybe_the_allocation), arg(void *, obj), arg(struct uniqtype *,new_t)) /* optional (stack) */\
fun(int                ,walk_allocations, arg(struct alloc_containment_ctxt *,cont), arg(walk_alloc_cb_t *, cb), arg(void *, arg), arg(void *, begin), arg(void *, end))

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
 * prefixed ones non-overridable for internal calls? Beware protected undefs,
 * which will prevent binding from outside-of-DSO clients... use IN_LIBALLOCS_DSO. */
#define __liballocs_toplevel_fun_decl(rett, name, ...) \
	rett __liballocs_ ## name( __VA_ARGS__ ); \
	rett alloc_ ## name( __VA_ARGS__ );
ALLOC_REFLECTIVE_API(__liballocs_toplevel_fun_decl, __allocmeta_fun_arg)

// we use walk_allocations to write a general cross-allocator depth-first traversal
/* Depth-first walking necessarily crosses allocators, so it
 * doesn't need to go on the allocator. */
int __liballocs_walk_allocations_df(
	struct alloc_containment_ctxt *cont,
	walk_alloc_cb_t *cb,
	void *arg
);
/* We use our general cross-allocator depth-first traversal to write a reference walker,
 * parameterised by an interpreter (i.e. many notions of 'reference'). */
struct walk_refs_state
{
	struct interpreter *interp;
	walk_alloc_cb_t *ref_cb;
	//void *ref_cb_arg;
};
int
__liballocs_walk_refs_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_containment_ctxt *cont, void *walk_refs_state_as_void);

/* We use our general cross-allocator depth-first traversal to write an environment walker,
 * parameterised by an interpreter (i.e. many notions of 'environment', to serve the
 * notion of 'reference').
 */
struct environ_elt;
struct walk_environ_state
{
	struct interpreter *interp;
	walk_alloc_cb_t *environ_cb; // this gets a environ_elt_cb_arg as its arg
	struct environ_elt *buf; // don't copy this; we need to realloc it
	unsigned buf_capacity;
	unsigned buf_used;
};
struct environ_elt
{
	void *base;
	struct uniqtype *t;
	unsigned long sz;
	uintptr_t key;
};
struct walk_environ_state;
struct environ_elt_cb_arg
{
	struct walk_environ_state *state;
	uintptr_t key;
};

int
__liballocs_walk_environ_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_containment_ctxt *cont, void * /* YES */ walk_environ_state_as_void);

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
extern struct allocator __packed_seq_allocator;
// FIXME: These are indexes, not allocators
extern struct allocator __generic_malloc_allocator; /* covers all chunks */
extern struct allocator __generic_small_allocator; /* usual suballoc impl */
extern struct allocator __generic_uniform_allocator; /* usual suballoc impl */
// extern struct allocator __global_malloc_allocator;
// extern struct allocator __libc_malloc_allocator; // good idea? probably not
// extern struct allocator __global_obstack_allocator;

// FIXME: we should probably have per-allocator headers for the stuff below

#define ALLOCATOR_HANDLE_LIFETIME_INSERT(a) ((a) == &__generic_malloc_allocator)

void __mmap_allocator_init(void) __attribute__((constructor(101)));
void __mmap_allocator_notify_brk(void *new_curbrk);
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

void __static_file_allocator_init(void) __attribute__((constructor(102)));
struct file_metadata *__static_file_allocator_notify_load(void *handle, const void *load_site);
void __static_file_allocator_notify_unload(const char *copied_filename);

void __brk_allocator_notify_brk(void *new_curbrk, const void *caller) __attribute__((visibility("hidden")));
void __brk_allocator_init(void) __attribute__((visibility("hidden"),constructor(101)));
extern struct big_allocation *__brk_bigalloc __attribute__((visibility("hidden")));
_Bool __brk_allocator_notify_unindexed_address(const void *mem);

typedef unsigned short allocsite_id_t;
struct allocsites_vectors_by_base_id_entry; // opaque here

const char *__liballocs_meta_libfile_name(const char *objname);

struct allocs_file_metadata
{
	void *meta_obj_handle; /* loaded by us */
	ElfW(Sym) *extrasym;
	struct allocsites_vectors_by_base_id_entry *allocsites_info;
	struct frame_allocsite_entry *frames_info;
	unsigned nframes;
	/* We extend the librunt structure. Since it is variable-size
	 * at the end, we must put it at the end.
	 * GAH. Actually this doesn't work! Not permitted in C. Need to
	 * refactor somehow. Could just make this a char[] and rely on
	 * effective type stuff and a nasty macro to view it with the
	 * right type. Or could take the array out of the file_metadata
	 * struct and macro-up only that. */
	struct file_metadata m;
};

static inline uintptr_t vaddr_from_rec(union sym_or_reloc_rec *p,
	struct allocs_file_metadata *file)
{
	ElfW(Sym) *symtab;
	if (p->is_reloc) return p->reloc.base_vaddr;
	else switch (p->sym.kind)
	{
		case REC_DYNSYM:   symtab = file->m.dynsym; goto sym;
		case REC_SYMTAB:   symtab = file->m.symtab; goto sym;
		case REC_EXTRASYM: symtab = file->extrasym; goto sym;
		sym:
			return symtab[p->sym.idx].st_value;
		default: abort();
	}
}

void __static_segment_allocator_init(void) __attribute__((constructor(102)));
void __static_segment_allocator_notify_define_segment(
	struct file_metadata *meta,
	unsigned phndx,
	unsigned loadndx
);
void __static_section_allocator_init(void) __attribute__((constructor(102)));
void __static_section_allocator_notify_define_section(
	struct file_metadata *meta,
	const ElfW(Shdr) *shdr
);
void __static_segment_setup_metavector(struct allocs_file_metadata *afile, unsigned phndx, unsigned loadndx);

void __static_symbol_allocator_init(void) __attribute__((constructor(102)));
liballocs_err_t __static_symbol_allocator_get_info(void * obj, struct big_allocation *maybe_bigalloc,
	struct uniqtype **out_type, void **out_base,
	unsigned long *out_size, const void **out_site) __attribute__((visibility("protected")));

void __stack_allocator_init(void) __attribute__((constructor(101)));
_Bool __stack_allocator_notify_unindexed_address(const void *ptr);

void init_frames_info(struct allocs_file_metadata *file) __attribute__((visibility("hidden")));

void __auxv_allocator_init(void) __attribute__((constructor(101)));
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

struct packed_sequence_family;
struct packed_sequence
{
	struct packed_sequence_family *fam;
	void *fn_arg;
	/* We cache, lazily, up to a given offset. The metavector
	 * and starts bitmap are good up to exactly that offset.
	 * We can realloc them if we need to enlarge the range. */
	union {
		void *metavector_any; /* for generic access */
		struct packed_sequence_metavector_rec16 *metavector_16;
		struct packed_sequence_metavector_rec32 *metavector_32;
	} un;
	unsigned metavector_nused;
	unsigned metavector_size;
	bitmap_word_t *starts_bitmap;
	unsigned starts_bitmap_nwords;
	// unsigned length_in_bytes; // do we need this? implied by container?
	unsigned offset_cached_up_to; // always the *end* offset of the last one we have cached
};
extern struct packed_sequence_family __string8_nulterm_packed_sequence;
void __packed_seq_free(void *arg);

/* Assorted notes:
 * - core liballocs implements the reflective protocol 
     for OS (incl stack) and libc (malloc) allocators
 * - "deep" indexing routines also detect and register suballoc,
     and provide *generic* implementation of indexing
 * - an allocator is free to register itself explicitly with
     a (more efficient) implementation of the reflective interface
 * - allocators are only obliged to handle issued addresses
     (liballocs never issues addresses for them)
 * - allocators *are* obliged to check addressing discipline of 
 *   the returned-to code ("any", base-only, "ask"),
 *   should we ever do anything with addressing disciplines.
 * - high-rate allocators usually want to do their own indexing,
 *   not use the generic implementations.
 *   E.g. the stack currently does so (even though the impl is inside
 *   liballocs, by walking the stack and looking up frame info etc).
 *   We don't want to force allocators to pay the cost of a function call; 
 *   they might do something more local that just compiles into
 *   a few instructions' work on hot/local memory.
 */

#endif
