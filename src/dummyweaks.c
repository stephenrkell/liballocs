#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "allocmeta.h"
#include "fake-libunwind.h"
#include "uniqtype.h"
#include "uniqtype-bfs.h"
#include "liballocs_cil_inlines.h"
#include "pageindex.h"

/* NOTE: is linking -R, i.e. "symbols only", the right solution for 
 * getting the weak references to pop out the way we want them?
 * It seems what we want is a weak_symbols.so that we link -R.
 *
 * HMM. It doesn't quite work: with the weak defs in a .so, we get
 
        /usr/bin/ld.bfd.real: --just-symbols may not be used on DSO: weakdefs.so
        Failing over to ld.gold
        /usr/bin/ld.gold.real: error: --just-symbols does not make sense with a shared object
 *
 * ... and using the .o (with --export-dynamic) also doesn't help.
 * We get the symbol, as an ABS defined to 0, but relocation records are 
 * not generated, i.e. the -R is considered non-interposable/overridable.
 *
 * The effect of -R is to 
 * - copy any ABS symbols
 * - also copy any UND symbols?
 * - for any defined symbols, create an ABS of the same name, value 0?
 *      NO. It blindly copies the "value", but ignores "section". So
 *      if your section is at offset 0xbeef, you'll get an ABS symbol
 *      of value 0xbeef.
 * 
 * So what we want is not analogous. It's really more like saying "link
 * weakly to this object", or --dt-useful. Failing an actual DT_USEFUL,
 * we make a NEEDED to a fake object; then delete the NEEDED after the 
 * fact. Weak references will yield to a relocatable 0 if the symbol is in
 * the useful object and a non-relocatable 0 otherwise. Non-weak references 
 * will link okay only if the supplied object defines the symbol. The
 * output binary will fail to load unless these symbols are somehow provided
 * (e.g. by LD_PRELOAD; or by a bolstered NEEDED library).
 *
 * Can we use -R with a linker script?
 */

struct __liballocs_memrange_cache __liballocs_ool_cache; // all zeroes
_Bool __liballocs_is_initialized;

struct big_allocation;

uint16_t *pageindex __attribute__((visibility("protected")));

__attribute__((visibility("protected")))
struct big_allocation big_allocations[/*NBIGALLOCS*/1];

__thread void *__current_allocfn;
__thread _Bool __currently_allocating;
__thread void *__current_allocsite;
__thread size_t __current_allocsz;
__thread int __currently_freeing;
int (__attribute__((constructor(103))) __liballocs_global_init)(void) { return 0; }

void __liballocs_unindex_stack_objects_counted_by(unsigned long *bytes_counter, void *frame_addr)
{
}
void __alloca_allocator_notify(void *new_userchunkaddr,
		unsigned long requested_size, unsigned long *frame_counter,
		const void *caller, const void *caller_sp, const void *caller_bp) {}

int __index_small_alloc(void *ptr, int level, unsigned size_bytes) { return 2; }
void __unindex_small_alloc(void *ptr, int level) {}

void 
__liballocs_index_delete(void *userptr)
{
	
}

void __liballocs_index_insert(void *new_userchunkaddr, size_t modified_size, const void *caller)
{
	
}

void *__liballocs_my_metaobj(void)
{
	return NULL;
}

unsigned long __liballocs_get_alloc_size(void *obj)
{
	return 0;
}
unsigned long alloc_get_size(void *obj) __attribute__((alias("__liballocs_get_alloc_size")));
const void *__liballocs_get_alloc_site(void *obj)
{
	return 0;
}
const void *allocs_get_site(void *obj) __attribute__((alias("__liballocs_get_alloc_site")));
void *__liballocs_get_base(void *obj)
{
	return NULL;
}
void *alloc_get_base(void *obj) __attribute__((alias("__liballocs_get_base")));
void *__liballocs_get_alloc_base(void *obj)
{
	return NULL;
}
void *
__liballocs_get_alloc_base_with_fill(void *obj, struct allocator **out_a, /*bigalloc_num_t*/ unsigned short *out_num)
{
	return NULL;
}
struct uniqtype * __liballocs_get_alloc_type(const void *obj)
{
	return NULL;
}
struct uniqtype *
__liballocs_get_alloc_type_with_fill(void *obj, struct allocator **out_a, /*bigalloc_num_t*/ unsigned short *out_num)
{
	return NULL;
}
struct allocator * __liballocs_get_leaf_allocator(void *obj)
{
	return NULL;
}
struct allocator *alloc_get_allocator(void *obj) __attribute__((alias("__liballocs_get_leaf_allocator")));
//struct allocator * __liballocs_leaf_allocator_for(const void *obj,
//	struct big_allocation **out_bigalloc)
//{
//	return NULL;
///}
// instantiate the inline here
extern inline struct allocator * __liballocs_leaf_allocator_for(const void *obj,
	struct big_allocation **out_bigalloc);

struct uniqtype * 
__liballocs_get_inner_type(void *obj, unsigned skip_at_bottom)
{
	return NULL;
}

struct uniqtype * 
__liballocs_get_outermost_type(void *obj)
{
	return NULL;
}
struct uniqtype *
alloc_get_type(void *obj) __attribute__((alias("__liballocs_get_outermost_type")));

struct uniqtype;
const char *(__attribute__((pure)) __liballocs_uniqtype_name)(const struct uniqtype *u)
{
	return NULL;
}

struct mcontext;
struct uniqtype *
__liballocs_make_array_precise_with_memory_bounds(struct uniqtype *in,
   struct uniqtype *out, unsigned long out_len,
   void *obj, void *memrange_base, unsigned long memrange_sz, void *ip, struct mcontext *ctxt)
{
	return NULL;
}
struct uniqtype *
__liballocs_make_precise_identity(struct uniqtype *in,
   struct uniqtype *out, unsigned long out_len,
   void *obj, void *memrange_base, unsigned long memrange_sz, void *ip, struct mcontext *ctxt)
{
	return in;
}

void __liballocs_report_wild_address(const void *ptr)
{
}

struct allocator __stack_allocator;
struct allocator __stackframe_allocator;
struct allocator __mmap_allocator; /* mmaps */
struct allocator __sbrk_allocator; /* sbrk() */
struct allocator __static_file_allocator; /* ldso; nests under file? */
struct allocator __static_symbol_allocator; /* ldso; nests under file? */
struct allocator __static_section_allocator; /* ldso; nests under file? */
struct allocator __static_segment_allocator; /* ldso; nests under file? */
struct allocator __auxv_allocator; /* nests under stack? */
struct allocator __alloca_allocator; /* nests under stack? */
struct allocator __default_lib_malloc_allocator = (struct allocator) {}; /* covers all chunks */
struct allocator __generic_small_allocator; /* usual suballoc impl */
struct allocator __generic_uniform_allocator; /* usual suballoc impl */
struct allocator __packed_seq_allocator;
struct packed_sequence_family { long pad[10]; } __string8_nulterm_packed_sequence; // HACK

extern struct allocator __global_malloc_allocator __attribute__((weak,alias("__default_lib_malloc_allocator"))); /* covers all chunks */

struct liballocs_err *__liballocs_get_alloc_info(const void *obj, 
	struct allocator **out_allocator, const void **out_alloc_start,
	unsigned long *out_alloc_size_bytes,
	struct uniqtype **out_alloc_uniqtype, const void **out_alloc_site)
{
	return (void *)-1; // We need to return an error here so do not return NULL
}


void __liballocs_malloc_post_init(void) {}
void __liballocs_malloc_pre_alloc(size_t *p_size, size_t *p_alignment, const void *caller)
{}
void 
__liballocs_malloc_post_successful_alloc(void *allocptr, size_t modified_size, size_t modified_alignment, 
                size_t requested_size, size_t requested_alignment, const void *caller)
{}
void __liballocs_malloc_pre_nonnull_free(void *userptr, size_t freed_usable_size) {}
void __liballocs_malloc_post_nonnull_free(void *userptr) {}

void __liballocs_malloc_pre_nonnull_nonzero_realloc(void *userptr, size_t size, const void *caller) 
{}

void __liballocs_malloc_post_nonnull_nonzero_realloc(void *userptr, 
	size_t old_usable_size,
	const void *caller, void *__new_allocptr)
{}

unw_addr_space_t unw_local_addr_space __asm__("__liballocs_unw_local_addr_space") __attribute__((visibility("protected")));
int unw_get_reg(unw_cursor_t *cursor, int reg, unw_word_t *dest) { return 0; }
int unw_init_local(unw_cursor_t *cursor, unw_context_t *context) { return 0; }
int unw_getcontext(unw_context_t *ucp) { return 0; }
int unw_step(unw_cursor_t *cp) { return 0; }

void __uniqtype_default_follow_ptr(void **p_obj, struct uniqtype **p_t, void *arg)
{ /* no-op */ }

void __uniqtype_walk_bfs_from_object(
	void *object, struct uniqtype *t,
	follow_ptr_fn *follow_ptr, void *fp_arg,
	on_blacken_fn *on_blacken, void *ob_arg) {}

struct uniqtype *
__liballocs_get_or_create_union_type(unsigned n, /* struct uniqtype *first_memb_t, */...)
{
	return NULL;
}
struct uniqtype *__liballocs_get_or_create_unbounded_array_type(struct uniqtype *element_t)
{
	return NULL;
}
int __liballocs_add_type_to_block(void *block, struct uniqtype *t)
{
	return 0;
}
struct big_allocation *__liballocs_new_bigalloc(const void *ptr, size_t size,
		void *suballocator_private, void (*suballocator_private_free)(void*),
		struct big_allocation *maybe_parent, struct allocator *a)
{
	return NULL;
}
struct mapping_entry *__liballocs_get_memory_mapping(const void *obj,
		struct big_allocation **maybe_out_bigalloc)
{
	return NULL;
}
struct big_allocation *__lookup_bigalloc_from_root(const void *mem, struct allocator *a, void **out_object_start)
{
	return NULL;
}
__attribute__((visibility("protected")))
struct big_allocation *__lookup_deepest_bigalloc(const void *mem)
{ return NULL; }

__attribute__((visibility("protected")))
struct big_allocation *__lookup_bigalloc_under_by_suballocator(const void *mem, struct allocator *sub_a,
    struct big_allocation *start, void **out_object_start)
{
	return NULL;
}
__attribute__((visibility("protected")))
struct big_allocation *__lookup_bigalloc_from_root_by_suballocator(const void *mem, struct allocator *sub_a, void **out_object_start)
{ return NULL; }

__attribute__((visibility("protected")))
struct big_allocation *__lookup_bigalloc_under(const void *mem, struct allocator *a, struct big_allocation *start, void **out_object_start)
{ return NULL; }

_Bool __liballocs_truncate_bigalloc_at_end(struct big_allocation *b, const void *new_end)
{ return 1; }

__attribute__((visibility("protected")))
_Bool __liballocs_delete_bigalloc_at(const void *begin, struct allocator *a)
{ return 1; }

struct alloc_tree_pos;
struct alloc_tree_link;
typedef int walk_alloc_cb_t(struct big_allocation *maybe_the_allocation, void *obj, struct uniqtype *t, const void *allocsite, struct alloc_tree_link *cont, void *arg);
int
__liballocs_walk_allocations(struct alloc_tree_pos *cont,
	walk_alloc_cb_t *cb,
	void *arg,
	void *maybe_range_begin,
	void *maybe_range_end) { return 0; }
int
alloc_walk_allocations(struct alloc_tree_pos *cont,
	walk_alloc_cb_t *cb,
	void *arg,
	void *maybe_range_begin,
	void *maybe_range_end) __attribute__((alias("__liballocs_walk_allocations")));

int __liballocs_walk_allocations_df(
	struct alloc_tree_pos *pos,
	walk_alloc_cb_t *cb,
	void *arg
)
{
	return 0;
}
struct walk_refs_state;
int
__liballocs_walk_refs_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_tree_link *cont, void *walk_refs_state_as_void)
{
	return 0;
}
struct walk_environ_state;
int
__liballocs_walk_environ_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_tree_link *cont, void * /* YES */ walk_environ_state_as_void)
{
	return 0;
}
// instantiate this one
extern struct big_allocation *__liballocs_get_bigalloc_containing(const void *obj);

struct allocsite_entry;
struct allocsite_entry *__liballocs_find_allocsite_entry_at(
	const void *allocsite)
{
	return NULL;
}

unsigned short __liballocs_allocsite_id(const void *allocsite)
{ return 0; }

struct allocsite_entry *__liballocs_allocsite_entry_by_id(unsigned short id,
	unsigned long *out_file_base_addr)
{
	return NULL;
}
const void *__liballocs_allocsite_by_id(unsigned short id)
{
	return NULL;
}

void __notify_ptr_write(const void **dest, const void *val)
{
	/* Called for *dest = val; on code instrumented with trapptrwrites
	 * Only provide this weak symbol unless lifetime policies are enabled */
}

void __notify_copy(void *dest, const void *src, unsigned long n)
{
	/* We provide a weak definition here that is overriden if lifetime policies
	 * are enabled.
	 * Also note that in any case, libcrunch will wrap us. */
}

const char *__liballocs_meta_libfile_name(const char *objname) { return NULL; }

/* GIANT HACK:
 * This *non*-dummy code is in this file because:
 * - librunt/liballocs_systrap clients end up needing it, including
 *      libcrunch_stubs.so
 * - --defsym __private_strdup=strdup doesn't work with ld.gold (internal error),
 *      so we need to provide an implementation locally
 */
/* __private_malloc is defined by our Makefile as __wrap_dlmalloc.
 * Since dlmalloc does not include a strdup, we need to define
 * that explicitly.
 *
 * Why is an outgoing reference to __private_malloc all right?
 * In *both* liballocs_dummyweaks.so and liballocs_preload.so,
 * we link in a full dlmalloc, so this will be a defined reference.
 * In liballocs_dummyweaks.o, we have no __private_malloc and so
 * the resulting DSO will have an outgoing weak reference to this
 * private malloc, but that won't prevent us from running.
 * (FIXME: ... but libcrunch stubs probably only if we link with -z dynamic-undefined-weak?)
 */
void *__private_malloc(size_t len) __attribute__((weak)); /* weak ref */
char *__liballocs_private_strdup(const char *s) __attribute__((weak));
char *__liballocs_private_strdup(const char *s)
{
	size_t len = strlen(s) + 1;
	char *mem = __private_malloc(len);
	if (!mem) return NULL;
	return memcpy(mem, s, len);
}
char *__private_strdup(const char *s) __attribute__((weak,alias("__liballocs_private_strdup")));
char *__liballocs_private_strndup(const char *s, size_t n) __attribute__((weak));
char *__liballocs_private_strndup(const char *s, size_t n)
{
	size_t maxlen = strlen(s);
	size_t len = (n > maxlen ? maxlen : n) + 1;
	char *mem = __private_malloc(len);
	if (!mem) return NULL;
	return memcpy(mem, s, len);
}
char *__private_strndup(const char *s, size_t n) __attribute__((weak,alias("__liballocs_private_strndup")));

void __packed_seq_free(void *arg) {}

// FIXME: these are just pasted, and that is just wrong.
// See GitHub issue #56 for possible ways to get rid of all this.
struct liballocs_err
{
	const char *message;
};
struct liballocs_err __liballocs_err_stack_walk_step_failure 
 = { "stack walk reached higher frame" };
struct liballocs_err __liballocs_err_stack_walk_reached_higher_frame 
 = { "stack walk reached higher frame" };
struct liballocs_err __liballocs_err_stack_walk_reached_top_of_stack 
 = { "stack walk reached top-of-stack" };
struct liballocs_err __liballocs_err_unknown_stack_walk_problem 
 = { "unknown stack walk problem" };
struct liballocs_err __liballocs_err_unindexed_heap_object
 = { "unindexed heap object" };
struct liballocs_err __liballocs_err_unindexed_alloca_object
 = { "unindexed alloca object" };
struct liballocs_err __liballocs_err_unrecognised_alloc_site
 = { "unrecognised alloc site" };
struct liballocs_err __liballocs_err_unrecognised_static_object
 = { "unrecognised static object" };
struct liballocs_err __liballocs_err_object_of_unknown_storage
 = { "object of unknown storage" };

void *emulated_sbrk(long int n) { return (void*)-1; }

void *__liballocs_private_realloc(void*, size_t);
void __liballocs_private_free(void *);

void __liballocs_free_arena_bitmap_and_info(void *info  /* really struct arena_bitmap_info * */);

unsigned long __liballocs_aborted_stack __attribute__((visibility("hidden")));;
unsigned long __liballocs_aborted_static __attribute__((visibility("hidden")));;
unsigned long __liballocs_aborted_unknown_storage __attribute__((visibility("protected")));;
unsigned long __liballocs_hit_heap_case __attribute__((visibility("protected")));
unsigned long __liballocs_hit_alloca_case __attribute__((visibility("hidden")));;
unsigned long __liballocs_hit_stack_case __attribute__((visibility("hidden")));;
unsigned long __liballocs_hit_static_case __attribute__((visibility("hidden")));;
unsigned long __liballocs_aborted_unindexed_heap __attribute__((visibility("protected")));;
unsigned long __liballocs_aborted_unindexed_alloca __attribute__((visibility("hidden")));;
unsigned long __liballocs_aborted_unrecognised_allocsite __attribute__((visibility("protected")));;

__attribute__((visibility("protected")))
liballocs_err_t __liballocs_extract_and_output_alloc_site_and_type(
    struct insert *p_ins,
    struct uniqtype **out_type,
    void **out_site
) { return NULL; }

void *__liballocs_private_malloc(size_t sz)
{ return NULL; }
void *__liballocs_private_realloc(void *ptr, size_t sz)
{ return NULL; }
void __liballocs_free_arena_bitmap_and_info(void *info)
{}
void __liballocs_uncache_all(const void *allocptr, unsigned long size)
{}

_Bool __liballocs_notify_unindexed_address(const void *obj) { return 1; }
