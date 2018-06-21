#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "allocmeta.h"
#include "fake-libunwind.h"
#include "uniqtype.h"
#include "uniqtype-bfs.h"

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

_Bool __liballocs_is_initialized;

uint16_t *pageindex __attribute__((visibility("protected")));

__thread void *__current_allocfn;
__thread _Bool __currently_allocating;
__thread void *__current_allocsite;
__thread size_t __current_allocsz;
__thread int __currently_freeing;
int __liballocs_global_init(void) { return 0; }

void __liballocs_unindex_stack_objects_counted_by(unsigned long *bytes_counter, void *frame_addr)
{
}
void __alloca_allocator_notify(void *new_userchunkaddr, unsigned long modified_size, 
		unsigned long *frame_counter, const void *caller, 
		const void *caller_sp, const void *caller_bp) {}

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

void *__liballocs_allocsmt;

unsigned long __liballocs_get_alloc_size(const void *obj)
{
	return 0;
}
void *__liballocs_get_alloc_site(const void *obj)
{
	return 0;
}
void *__liballocs_get_alloc_base(const void *obj)
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
struct allocator * __liballocs_get_leaf_allocator(const void *obj)
{
	return NULL;
}
struct allocator * __liballocs_leaf_allocator_for(const void *obj,
	struct big_allocation **out_containing_bigalloc,
	struct big_allocation **out_maybe_the_allocation)
{
	return NULL;
}

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
struct allocator __static_allocator; /* ldso; nests under file? */
struct allocator __auxv_allocator; /* nests under stack? */
struct allocator __alloca_allocator; /* nests under stack? */
struct allocator __generic_malloc_allocator; /* covers all chunks */
struct allocator __generic_small_allocator; /* usual suballoc impl */
struct allocator __generic_uniform_allocator; /* usual suballoc impl */
struct allocator __generic_malloc_allocator;

struct liballocs_err *__liballocs_get_alloc_info(const void *obj, 
	struct allocator **out_allocator, const void **out_alloc_start,
	unsigned long *out_alloc_size_bytes,
	struct uniqtype **out_alloc_uniqtype, const void **out_alloc_site)
{
	return NULL;
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
int __liballocs_add_type_to_block(void *block, struct uniqtype *t)
{
	return 0;
}

struct mapping_entry *__liballocs_get_memory_mapping(const void *obj,
		struct big_allocation **maybe_out_bigalloc)
{
	return NULL;
}

Dl_info dladdr_with_cache(const void *addr)
{
	Dl_info dummy;
	memset(&dummy, 0, sizeof dummy);
	return dummy;
}

