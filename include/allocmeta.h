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

enum addr_disc_t { ANY, BASE_ONLY, ASK_FIRST };
/* Two concerns: 
 * - what event signifies the end of the lifetime? Ideally in a form that can be observed. 
 *      -- the goal here is to enable observation of end-of-life.
 * - what is a necessary and sufficient condition for that event *not* to occur?
 *      -- the goal here is to enable *extending* the allocation's life
 */
enum lifetime_end_event_t { PROC_CALL, FRAME_EXEC_PT }; // these are all patterns over ucontexts
enum lifetime_cond_t { UNKNOWN, REACHABLE_IN };         // stack and manual are "unknown"
typedef struct lifetime_policy_s
{
	enum lifetime_end_event_t end_event;
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
	
	enum lifetime_cond_t cond;
	union
	{
		struct
		{
			
		} unknown;
		struct 
		{
			struct allocator *allocator;
		} reachable
	} u_cond;
} lifetime_policy_t;

#define ALLOC_REFLECTIVE_API(fun, arg) \
/* The *process-wide* reflective interface of liballocs */ \
fun(uniqtype * , alloc_get_type, arg(void *, obj)) /* what type? */ \
fun(void *     , alloc_get_base, arg(void *, obj))  /* base address? */ \
fun(void *     , alloc_get_limit,arg(void *,obj))  /* end address? */ \
fun(void *     , alloc_get_site, arg(void *,obj))  /* where allocated?   optional   */ \
fun(Dl_info    , alloc_dladdr,   arg(void *, obj))  /* dladdr-like -- only for static*/ \
fun(allocator *, alloc_get_allocator, arg((void *, obj))  /* heap/stack? etc */ \
fun(discipl_t  , alloc_get_discipl, arg(void *,site)) /* what will the code (if any) assume it can do with the ptr? */ \
fun(lifetime_policy_t *,alloc_get_lifetime, arg(void *,obj))

#define __allocmeta_fun_arg(argt, name) argt
#define __allocmeta_fun_ptr(rett, name, args...) \
	rett (*name)( ## args );

struct allocator
{
	ALLOC_REFLECTIVE_API(__allocmeta_fun_arg, __allocmeta_fun_ptr)
};


/* The idealised base-level allocator protocol. These operations are 
   defined only logically; any allocators (e.g. stack, GC) "inline" them. */
void *alloc_new_uninit(size_t size, size_t align, struct uniqtype *t);
void *alloc_new_zero(size_t size, size_t align, struct uniqtype *t);
void  alloc_delete(void *start);
void *alloc_resize_in_place(void *start, size_t new_size, size_t new_align); /* may fail */
void *alloc_change_type(void *start, struct uniqtype *u);                    /* optional (stack) */
void *alloc_safe_migrate(void *start, allocator *recipient);                 /* may fail */
void  alloc_unsafe_migrate(void *start, allocator *recipient);               /* needn't free existing (stack) */
void *alloc_nest(void *obj, struct allocator *impl); /* register an allocated region (implied by suballocator handling) */

/* The *per-allocator* meta-level interface of liballocs */
uniqtype * (*get_type)   (void *obj);  /* what type?        \  call            */
void *     (*get_site)   (void *obj);  /* where allocated?   > these on        */
void *     (*get_base)   (void *obj);  /* base address?     /  issued addrs!   */
void *     (*get_limit)  (void *obj);  /* end address?     /                   */
discipl_t  (*get_discipl)(void *site); /* what will code assume it can do with the ptr? */
int        (*can_issue)  (void *obj, off_t off); /* ok to issue this address? only for ASK_FIRST */

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
 * want to implement TLAB / GC-nursery allocation metadata.
 * One way is to define a protocol between liballocs and the allocator 
 * on thread-local metadata buffers.
 * We could write an inline function in C which
 * records an allocation in the buffer,
 * as a ready-made helper function that most VMs could plumb in, 
 * even though the "official" protocol is defined in shared memory
 *
 * In fact this generalises. 
 * All our link-time allocator wrappers are just an opportunity
 * to make outcalls publishing the existence of a fresh allocation.
 * We could abstract that into a metaprotocol, by which allocators must call liballocs.
 * The point about the inline function is that
 * we don't want to force them to pay the cost of a function call; 
 * we want something more local that just compiles into
 * a few instructions' work on hot/local memory.
 * 
 * It might be worth tweaking the layering of 
 * the l0 index, l1 index, malloc wrappers, preload.o and link-time stubs
 * to more cleanly exhibit this protocol.
 */

/* What allocators do we have? 
 * 
 * - level 0: mmap, munmap, mremap, 
 * - level 1: global malloc/free 
 * - level 2: e.g. gslice
 */
