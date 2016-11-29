#include <stdlib.h>
#include <stdint.h>

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

unsigned long __liballocs_get_alloc_size(const void *obj)
{
	return 0;
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

void __liballocs_report_wild_address(const void *ptr)
{
}
