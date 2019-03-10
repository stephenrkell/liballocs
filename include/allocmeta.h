#ifndef ALLOCMETA_H_
#define ALLOCMETA_H_

#include <sys/resource.h> /* for rlim_t */
#include <sys/time.h>
#include <elf.h>
#include <dlfcn.h>

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

/* Declare the top-level functions. */
#define __liballocs_toplevel_fun_decl(rett, name, ...) \
	rett __liballocs_ ## name( __VA_ARGS__ );
ALLOC_REFLECTIVE_API(__liballocs_toplevel_fun_decl, __allocmeta_fun_arg)
void *__liballocs_get_alloc_base(void *); /* alias of __liballocs_get_base */

/* Which allocators do we have? */
extern struct allocator __stack_allocator;
extern struct allocator __stackframe_allocator;
extern struct allocator __mmap_allocator; /* mmaps */
extern struct allocator __sbrk_allocator; /* sbrk() */
extern struct allocator __static_allocator; /* ldso; nests under file? */
// extern struct allocator __static_file_allocator;
// extern struct allocator __static_segment_allocator;
// extern struct allocator __static_section_allocator;
// extern struct allocator __static_symbol_allocator;
extern struct allocator __auxv_allocator; /* nests under stack? */
extern struct allocator __alloca_allocator; /* nests under stack? */
// FIXME: These are indexes, not allocators
extern struct allocator __generic_malloc_allocator; /* covers all chunks */
extern struct allocator __generic_small_allocator; /* usual suballoc impl */
extern struct allocator __generic_uniform_allocator; /* usual suballoc impl */
// extern struct allocator __global_malloc_allocator;
// extern struct allocator __libc_malloc_allocator; // good idea? probably not
// extern struct allocator __global_obstack_allocator;

void __mmap_allocator_init(void);
void __mmap_allocator_notify_mmap(void *ret, void *requested_addr, size_t length, 
	int prot, int flags, int fd, off_t offset, void *caller);
void __mmap_allocator_notify_mremap_before(void *old_addr, size_t old_size, 
	size_t new_size, int flags, void *new_address, void *caller);
void __mmap_allocator_notify_mremap_after(void *ret_addr, void *old_addr, size_t old_size, 
	size_t new_size, int flags, void *new_address, void *caller);
void __mmap_allocator_notify_munmap(void *addr, size_t length, void *caller);
void __mmap_allocator_notify_brk(void *addr);
_Bool __mmap_allocator_is_initialized(void) __attribute__((visibility("hidden")));
_Bool __mmap_allocator_notify_unindexed_address(const void *ptr);
struct mapping_entry;
struct mapping_sequence;
struct mapping_entry *__mmap_allocator_find_entry(const void *addr, struct mapping_sequence *seq)
	__attribute__((visibility("protected")));
extern struct big_allocation *executable_mapping_sequence_bigalloc __attribute__((visibility("hidden")));
extern struct big_allocation *__brk_bigalloc __attribute__((visibility("hidden")));
void __brk_allocator_notify_brk(void *, const void *) __attribute__((visibility("hidden")));
void __brk_allocator_init(void) __attribute__((visibility("hidden")));

void __auxv_allocator_notify_init_stack_mapping_sequence(struct big_allocation *b);

void __static_allocator_init(void);
void __static_allocator_notify_load(void *handle);
void __static_allocator_notify_unload(const char *copied_filename);

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
