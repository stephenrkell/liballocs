#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <err.h>
#include <assert.h>
#include <link.h>
#include "relf.h"
#include "donald.h"

typedef _Bool (*ld_so_sym_cb_t)(ElfW(Sym) *sym, unsigned char *dynstr,
	uintptr_t load_addr, void *arg);

_Bool instr_cb(ElfW(Sym) *sym, unsigned char *dynstr,
	uintptr_t load_addr, void *arg)
{
	const char *name = dynstr + sym->st_name;
	// FIXME: get these names from elsewhere
	// (where? simply a constant string in the meta-DSO perhaps?...)
	if (0 == strcmp(name, "__minimal_malloc")
	||  0 == strcmp(name, "__minimal_calloc")
	||  0 == strcmp(name, "__minimal_realloc")
	||  0 == strcmp(name, "__minimal_free")
	)
	{
		debug_printf(0, "caught a malloc-family! %s\n", name);
		// FIXME: header file for this please
		void instrument_malloc_entry(const void *func, const void *func_limit,
			void *trampoline_buf, void *trampoline_buf_limit);
		if (0 == strcmp(name, "__minimal_malloc"))
		{
			// where is our trampoline buf?
			void *function_entry = sym_to_addr_given_base(load_addr, sym);
			size_t function_size = sym->st_size; // FIXME: wrong for IFUNCs?
			//instrument_malloc_entry(function_entry, (char*) function_entry + function_size,
			//	trampoline_buf, trampoline_buf_limit);
		}

	}
	return 1; // keep going
}

__attribute__((visibility("hidden")))
_Bool walk_all_ld_so_symbols(struct link_map *ld_so_link_map)
{
	unsigned char *dynstr = get_dynstr(ld_so_link_map);
	ElfW(Sym) *dynsym = get_dynsym(ld_so_link_map);
	unsigned long ndynsyms = dynamic_symbol_count(
		/* ignored */ ld_so_link_map->l_ld, ld_so_link_map);
	// now iterate over those symbols
#define ITERATE_SYMTAB(dynsym, dynstr, ndynsyms) \
    for (unsigned i = 0; i < (ndynsyms); ++i) { \
        _Bool keep_going = instr_cb(&(dynsym)[i], (dynstr), ld_so_link_map->l_addr, /*cb_arg*/ NULL); \
        if (!keep_going) break; \
    }
	ITERATE_SYMTAB(dynsym, dynstr, ndynsyms);

	/* Now see if we can get the extrasyms. PROBLEM: we want to
	 * call dlopen, but we don't yet have a functioning dlopen.
	 * Instead we map the meta.so ourselves, using routines from
	 * donald. */
	const char *meta_base = getenv("META_BASE") ?: "/usr/lib/meta";
	char meta_buf[PATH_MAX];
	char real_buf[PATH_MAX];
	char *real_ret = realpath(SYSTEM_LDSO_PATH, real_buf);
	real_buf[sizeof real_buf - 1] = '\0';
	if (!real_ret) abort();
	int ret = snprintf(meta_buf, sizeof meta_buf, "%s/%s-meta.so", meta_base, real_buf);
	if (ret <= 0) abort();
	meta_buf[sizeof meta_buf - 1] = '\0';
	struct loadee_info ld_so_meta = load_file(meta_buf,
		/* loadee_base_addr_hint */ NULL, NULL, NULL);
	if (!ld_so_meta.dynamic_vaddr) abort(); // harsh but go with it for now
	ElfW(Dyn) *meta_dyn = (ElfW(Dyn) *) (ld_so_meta.dynamic_vaddr + ld_so_meta.base_addr);
	// also look for  'extrasyms' and walk those
	ElfW(Sym) *extrasyms_sym = symbol_lookup_in_dyn(meta_dyn,
		ld_so_meta.base_addr, "extrasyms");
	if (!extrasyms_sym) abort();
	ElfW(Sym) *extrasyms = sym_to_addr_given_base(ld_so_meta.base_addr, extrasyms_sym);
	// we need extrastr too
	ElfW(Sym) *extrastr_sym = symbol_lookup_in_dyn(meta_dyn,
		ld_so_meta.base_addr, "extrastr");
	if (!extrastr_sym) abort();
	unsigned char *extrastr = sym_to_addr_given_base(ld_so_meta.base_addr, extrastr_sym);
	if (!extrasyms) abort();
	ITERATE_SYMTAB(extrasyms, extrastr, extrasyms_sym->st_size / sizeof (ElfW(Sym)));

	return 1;
}

__attribute__((visibility("hidden")))
void instrument_ld_so_allocators(void)
{
	/* We fix up all ld.so allocation functions so that they
	 * - increment the size
	 * - stash the call site address in the insert.
	 * Is this enough? Ideally we want also to set a bit in the
	 * bitmap, meaning we need to set the bits in the bitmap or whatever.
	 * Can we just make the instrumentation call the vanilla pre_alloc
	 * and post_successful_alloc functions?
	 *
	 * Also, where do I allocate the trampolines?
	 * Ideally I would use libdlbind but that's definitely circular --
	 * only works after we have dlopen'd.
	 * 
	 */

}

__attribute__((visibility("hidden")))
void make_ld_so_introspectable(void)
{
	/* Here we are doing some liballocs-like things before liballocs
	 * has started.
	 *
	 * Our premise is that from the constructor in liballocs, we can
	 * fix up the ld.so data structures if they're about to cause a crash,
	 * because the crash happens *after* the constructor has run. But
	 * we need to make the ld.so malloc chunks introspectable.
	 *
	 * How can we do this "the right way"? Do we want to
	 * hand off some proto-liballocs state to the "real" liballocs?
	 * We have no mechanism for this currently. But ultimately it
	 * could simplify our initialization considerably. E.g. we can
	 * use our bootstrapping syscall-trapping to ensure we see mmap()
	 * and friends from instruction 0, not just when we get around to
	 * enabling trapping. Maybe we want to hand off the bigallocs array,
	 * pageindex and an initial heap (containing stuff __private_malloc'd
	 * and linked from bigallocs)? That seems hard to achieve.
	 *
	 * Right now, we just want to introspect enough to read the symbol
	 * information. Hmm. We can load the -meta.so. Then what?
	 * We want a walk_all_ld_so_symbols() call that gets extrasyms as well
	 * as dynsyms. We can then match symbol names (and ideally versions, but
	 * just names for now) against our known malloc functions.
	 *
	 * We are still going to need a malloc bitmap. We can set the bit in
	 * a post_successful_alloc function, I guess. If all the logic we need
	 * is in inlines, it's possibly doable.
	 *
	 * Should we perhaps use the auxiliary vector to pass information
	 * to the 
	 */
	
}
