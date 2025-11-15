#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <err.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <link.h>
#include "relf.h"
#define CURRENT_ALLOC_VARS_QUALIFIERS static /* we run before TLS is working! see comment below*/
#define CURRENT_ALLOC_VARS_QUALIFIERS_POST
#include "donald.h"
#include "asmutil.h"
// #define __liballocs_extract_and_output_alloc_site_and_type extract_and_output_alloc_site_and_type
#include "allocmeta.h"
#include "malloc-meta.h"
#include "linear_malloc_index.h"
#include "cover-tracks.h"

typedef _Bool (*ld_so_sym_cb_t)(ElfW(Sym) *sym, unsigned char *dynstr,
	uintptr_t load_addr, void *arg);

/* These will be assigned when we install the trampolines. */
static void *(*orig_malloc)(size_t);
static void *(*orig_calloc)(size_t, size_t);
static void *(*orig_realloc)(void*, size_t);
static void (*orig_free)(void*);

/* Simple binary patcher for allocation function prologues.
 * We do roughly the following:
 *
 * 1. Decode the first N bytes of the function, where
 * N is the number of bytes in a jump instruction [sequence] that can get us
 * into a per-function trampoline. On x86 and x86-64, N is 5. Any instruction
 * that covers any of these bytes is a "displaced instruction".
 *
 * 2. Check that the displaced instructions are all position-independent, i.e.
 * they run correctly even if sited at a different address. If they are not,
 * we fail because such cases are currently too hard for us.
 *
 * 3. Set up a trampoline and clobber the entry point to jump to it. The approach
 * is rather like 'Detours' by Hunt & Brubacher (Proc. 3rd USENIX Windows NT
 * Symposium, 1999).
 */
#include <instr.h> /* from libsystrap */
/* We write into a buffer the information about relocatable fields in the
 * instructions we skip over. PROBLEM: we need to record also for each
 * instruction its byte offset, because the relocatable_field_info is always
 * relative to the start of the instruction. */
static void *prologue_get_first_non_displaced(const void *func, const void *func_limit,
	struct relocatable_field_info *out_relocs, unsigned *out_byte_offsets, unsigned *inout_nrelocs)
{
#define NBYTES_TO_CLOBBER  5 /* FIXME: sysdep */
#define CHECK_DISPLACEABLE(ptr) 1 /* FIXME: actually do this */
#define MAYBE_APPEND_ONE_FIELD(f) do { if (inout_nrelocs && nrelocs_used < *inout_nrelocs) { \
      out_byte_offsets[nrelocs_used] = nbytes_decoded; \
      out_relocs[nrelocs_used] = f; \
      ++nrelocs_used; \
} } while (0)
	/* + REMEMBER: displaceable instructions must not only be position-independent
	 * but also have no incoming branches! */
	unsigned nbytes_decoded = 0;
	unsigned char *insbyte = (unsigned char *) func;
	unsigned nrelocs_used = 0;
	while (nbytes_decoded < NBYTES_TO_CLOBBER)
	{
		// decode one, check we can 
		struct decoded_insn_info info = instr_len_extended(insbyte, func_limit);
		if (info.len == 0) /* error */ return NULL;
		if (info.relocatable_fields[0].reloc_type != 0) MAYBE_APPEND_ONE_FIELD(info.relocatable_fields[0]);
		if (info.relocatable_fields[1].reloc_type != 0) MAYBE_APPEND_ONE_FIELD(info.relocatable_fields[1]);

		nbytes_decoded += info.len;
		insbyte += info.len;
	}
	if (inout_nrelocs) *inout_nrelocs = nrelocs_used;
	return insbyte; // first non-displaced
}

/* Next for the Detours-style stuff. The trampoline is a "monopoline" because
 * it's specialised to a single detoured entry point. We therefore don't need to
 * save the entry point address anywhere in code... our generated trampoline code
 * embodies it in the displaced-instructinos-then-jump sequence.
 *
 * It's impossible to generate the monopoline as a compiled chunk of code, because
 * we only know where it needs to jump back to when we are doing the patching,
 * i.e. at run time. Likewise it needs to know the displaced instructions and
 * those are also only known at run time.
 *
 * Still, this ends suspiciously similar to a link-time-interposed function.
 * Our orig_post_displaced is similar to the dlsym() result.
 * But we are regrettably more malware-like... we are defeating the normal
 * dynamic-linking-induced points-to and called-from relation.
 */
__attribute__((visibility("hidden")))
void *write_monopoline_and_detour(void *func, void *func_limit,
	void *detour_func,
	void *detour_func_orig_callee_slot,
	void *trampoline_buf,
	void *trampoline_buf_limit)
{
	/* We jump straight from the target function entry instruction
	 * to the detour function, not via the trampoline.
	 * The trampoline is used only for return: it is specialised to
	 * a particular callee, and its entry point is what we set the
	 * orig callee slot to point to -- it performs the displaced
	 * instructions and then jumps back. It could be used either
	 * for a call or a jump, but a call is easier when coming from
	 * compiler-generated code. */
	struct relocatable_field_info reloc_fields[4];
	unsigned byte_offsets[4];
	unsigned n_reloc_fields = 4;
	void *first_non_displaced = prologue_get_first_non_displaced(func, func_limit,
		reloc_fields, byte_offsets, &n_reloc_fields);
	unsigned ndisplaced_bytes = (unsigned char *) first_non_displaced - (unsigned char*) func;

	// create the trampoline, beginning with the displaced instructions
	memcpy((char*) trampoline_buf, func, ndisplaced_bytes);
	fprintf(stderr, "Displaced instruction bytes are:");
	for (unsigned i = 0; i < ndisplaced_bytes; ++i) fprintf(stderr,
		" %02x", ((unsigned char*) trampoline_buf)[i]);
	fprintf(stderr, "\n");

	// apply any relocations
	for (unsigned i = 0; i < n_reloc_fields; ++i)
	{
		// the unique 'symaddr' is the old referent of the field
		uintptr_t symaddr = read_one_relocated_field(func, (ElfW(Rela)) {
			.r_offset = byte_offsets[i] + reloc_fields[i].fieldoff_nbits / 8,
			.r_info = ELFW_R_INFO(0, reloc_fields[i].reloc_type)
		});
		apply_one_reloc(trampoline_buf, (ElfW(Rela)) {
			.r_offset = byte_offsets[i] + reloc_fields[i].fieldoff_nbits / 8,
			.r_info = ELFW_R_INFO(0, reloc_fields[i].reloc_type)
			}, &symaddr);
	}
	INSTRS_FROM_ASM(trampoline_exit,
"1:jmp 0 \n\
        RELOC 1b + 1, "R_(X86_64_PC32)", "/* symidx 0: original entry point */" 0, -0x4\n"
	);
	memcpy_and_relocate((char*) trampoline_buf + ndisplaced_bytes,
		trampoline_exit,
		(uintptr_t) func + ndisplaced_bytes);
	*(void**) detour_func_orig_callee_slot = trampoline_buf;

	uint32_t buf;
	/* Finally, plumb in the detour function. PROBLEM: the detour function
	 * is in *our* code, allocsld. That is NOT necessarily within +/i 2GB (PC32 range)
	 * from the stuff we've mapped, which is at the inferior ld.so location and
	 * environs.
	 *
	 * We could use a longer instruction sequence to do the jump.
	 * We could jump initially to our trampoline and then to the detour, again
	 *     using a longer instruction sequence (but in the trampoline where
	 *     we are not in danger of breaking existing code).
	 * We could simply ensure that we always map the real ld.so very near to
	 * allocsld, e.g. right before it.
	 *
	 * Which is best?
	 */
	INSTRS_FROM_ASM(jump_to_detour,
"1:jmp 0 \n\
        RELOC 1b + 1, "R_(X86_64_PC32)", "/* symidx 0: detour func addr */" 0, -0x4\n"
	);
	memcpy_and_relocate((void*) func,
		jump_to_detour,
		(uintptr_t) detour_func);
	memcpy(&buf, (char*) func + 1, 4); /* the 32-bit displacement is at an offset of 1 byte */
	fprintf(stderr, "After relocation, 4-byte PC32 offset from %p is 0x%x "
		"(signed displacement: %d; should point to %p)\n",
		(char*) func + 1,
		buf,
		(int)((intptr_t) detour_func - (intptr_t) (func + 1)),
		detour_func);
	extern size_t trampoline_exit_size;
	return (char*) trampoline_buf + ndisplaced_bytes + trampoline_exit_size;
}

/* Now we want to use mallochooks to generate our detour functions.
 * From libmallochooks we can get user2hook (narrowing to a minimal
 * malloc API) and hook2event (turning malloc/realloc/free into events).
 * The implementation of event hooks comes from stubgen.h. And
 * in turn those call indexing functions in generic_malloc.h. */

static
_Bool instr_cb(ElfW(Sym) *sym, unsigned char *dynstr,
	uintptr_t load_addr, void *arg);

__attribute__((visibility("hidden")))
_Bool walk_all_ld_so_symbols(struct link_map *ld_so_link_map, void *arg)
{
	unsigned char *dynstr = get_dynstr(ld_so_link_map);
	ElfW(Sym) *dynsym = get_dynsym(ld_so_link_map);
	unsigned long ndynsyms = dynamic_symbol_count(
		/* ignored */ ld_so_link_map->l_ld, ld_so_link_map);
	// now iterate over those symbols
#define ITERATE_SYMTAB(dynsym, dynstr, ndynsyms) \
    for (unsigned i = 0; i < (ndynsyms); ++i) { \
        _Bool keep_going = instr_cb(&(dynsym)[i], (dynstr), ld_so_link_map->l_addr, /*cb_arg*/ arg); \
        if (!keep_going) break; \
    }
	ITERATE_SYMTAB(dynsym, dynstr, ndynsyms);

	/* Now see if we can get the extrasyms. PROBLEM: we want to
	 * call dlopen, but we don't yet have a functioning dlopen.
	 * Instead we map the meta.so ourselves, using routines from
	 * donald. We also use one liballocs routine, which we rename
	 * to avoid conflicting with the "main" copy once allocsld and
	 * liballocs_preload are unified into the same library. We have to
	 * fake up the allocs_file_metadata structure. */
	struct allocs_file_metadata fake_meta;
	bzero(&fake_meta, sizeof fake_meta);
	//int allocsld_find_and_open_meta_libfile(struct allocs_file_metadata *meta);
	fake_meta.m.l = ld_so_link_map;
	fake_meta.m.filename = fake_meta.m.l->l_name;
	int fd_meta = /*allocsld_*/find_and_open_meta_libfile(&fake_meta);
	if (fd_meta == -1) goto out_notloaded;
	struct loadee_info ld_so_meta = load_from_fd(fd_meta, "metadata object for " SYSTEM_LDSO_PATH,
		/* loadee_base_addr_hint */ (uintptr_t) 0, NULL, NULL);
	if (!ld_so_meta.dynamic_vaddr) goto out; // harsh but go with it for now
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

	// FIXME: we should really close/unload the meta file we just loaded
	// munmap(ld_so_meta.
out:
	close(fd_meta);
out_notloaded:
	return 1;
}

struct linear_malloc_index_instance *linear_malloc;
struct trampoline_buf_info {
	void *nextfree;
	void *limit;
};

__attribute__((visibility("hidden")))
void instrument_ld_so_allocators(uintptr_t ld_so_load_addr)
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
	 * Should we perhaps use the auxiliary vector to pass information
	 * to liballocs proper? Maybe. For now we just put it in a well-known
	 * location.
	 *
	 * Also, where do I allocate the trampolines?
	 * Ideally I would use libdlbind but that's definitely circular --
	 * only works after we have dlopen'd.
	 */

	/* We fix up all ld.so allocation functions so that they
	 * - increment the size
	 * - stash the call site address in the insert.
	 * 
	 * 
	 */

#define hard_assert(cond) do { assert(cond); if (!(cond)) abort(); } while(0)

/* If we don't have MAP_FIXED_NOREPLACE, and have to use MAP_FIXED,
 * what's the damage? In theory there's a chance that we will
 * clobber something important like the stack or vdso... or perhaps
 * something we don't know about, if the execution environment is
 * especially wacky. It's vanishingly in practice. We could possibly
 * use the auxv to check for some of these, or /proc/self/maps to
 * check definitively. FIXME: do something about this. Or fail to
 * run on kernels < 4.14 where we don't have MAP_FIXED_NOREPLACE?
 * There's also the host glibc version... we could supply the flag
 * numerically ourselves.... Is it sane to probe the kernel version? */
#ifdef MAP_FIXED_NOREPLACE
#define FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE)
#else
#define FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED)
#endif
	/* We have to place our linear malloc info precisely on the page
	 * preceding the ld.so, so that liballocs can find it. This is
	 * a total HACK and we should instead pass something in the auxv. */
	linear_malloc = mmap((void*) (ld_so_load_addr - 4096), 4096,
		PROT_READ|PROT_WRITE, FLAGS, -1, 0);
	hard_assert((uintptr_t) linear_malloc < (uintptr_t) -4095);
	*linear_malloc = (struct linear_malloc_index_instance) {
		.recs = RELF_ROUND_UP_PTR_((char*) linear_malloc + sizeof (*linear_malloc),
			_Alignof(struct linear_malloc_rec))  /* we map this */,
		.nrecs = MAX_LINEAR_MALLOCS,
		/* We take the address of these guys so that we can swap them out once
		 * liballocs starts up, for ones that ensure the bigalloc is created.
		 * Our versions are just the "early versions" for when that is not yet
		 * possible. */
		.p_orig_malloc = &orig_malloc,
		.p_orig_calloc = &orig_calloc,
		.p_orig_realloc = &orig_realloc,
		.p_orig_free = &orig_free
	};

	/* We need a writable, executable buffer for trampolines. AND
	 * it needs to be within a 32-bit PC-relative branch range of
	 * the original ld.so. So ask for the next earlier frame */
	void *rwx_buf = mmap((void*) (ld_so_load_addr - 8192), 4096,
		PROT_READ|PROT_WRITE|PROT_EXEC, FLAGS, -1, 0);
	hard_assert((uintptr_t) rwx_buf < (uintptr_t) -4095);
	struct trampoline_buf_info trampoline_info = {
		.nextfree = rwx_buf,
		.limit = (char*) rwx_buf + 4096
	};

	walk_all_ld_so_symbols(&fake_ld_so_link_map, &trampoline_info);
	// now we don't need the trampolines to be writable
	mprotect(rwx_buf, 4096, PROT_READ|PROT_EXEC);
}

/* We generate a bespoke set of malloc hooks here. */
#define MALLOC_PREFIX(s) allocsld_detour_##s
#define HOOK_PREFIX(s) hook_##s
// declare hook_malloc etc. -- defaults to hidden visibility on the prototypes
#include "mallochooks/hookapi.h"
#include "../src/user2hook.c"
/* Now we have generated "allocsld_detour_*" calling "hook_"*. */

#undef HOOK_PREFIX
#define HOOK_PREFIX(s) __terminal_hook_##s
#define ALLOC_EVENT(s) __ld_so_malloc_##s
#include "../src/hook2event.c"
/* Now we have generated hook_malloc etc.,
 * calling __ld_so_malloc_post_successful_alloc and so on,
 * (but those are not yet generated -- instead by ALLOC_EVENT_INDEXING_DEFS4 below)
 * intermingled with
 * calling __terminal_hook_*.
 * To terminate things we also need...
 */
#undef MALLOC_PREFIX
#define MALLOC_PREFIX(s) (*orig_##s)
#undef HOOK_PREFIX /* terminal-direct will define this itself */
#undef MALLOC_LINKAGE
#define MALLOC_LINKAGE static
#include "../src/terminal-direct.c"

/* So we just need to:
 * - generate the trampoline and entry-clobber and orig*-initializing code;
 * - implement __ld_so_malloc_post_successful_alloc and friends, which
 *    generic_malloc_index.h can do for us....
 *
 * ... if could, if it weren't for one problem. At least as of 2.36,
 * glibc's __minimal_malloc does not store a chunk's size! It can only free
 * the most recently issued chunk. So, our indexing scheme, using trailers,
 * does not work!
 *
 * Another problem: it uses mmap to extend its arena, so the arena can
 * easily be spread out all over the place. This might necessitate many bitmaps.
 *
 * We could perhaps use our bitmap to figure out, for any chunk, where its
 * trailer is. Problem: the frontier chunk, which has no successive bit,
 * has an end point that is only revealed by alloc_end. We could slurp that
 * using debug info. We could remember it specially from the malloc we're doing.
 *
 * Or we could skip the generic_malloc_index.h above and just
 * implement our own indexing.
 * E.g. instead of a bitmap, maybe we should simply push <addr, length> pairs into a
 * bump vector. If we detect an address that is not greater than the last allocated
 * address, we need to sort the vector. Otherwise it's still sorted.
 *
 * Or perhaps we should use the generic-small index?
 *
 * Let's try a custom indexing implementation for now.
 */

// struct liballocs_err; // HACK: shouldn't be necessary
#define indexer_namefrag linear_malloc

extern struct allocator __ld_so_malloc_allocator; // dummy
 // HACK: copied from generic_malloc.h so that
/* Now we just define the calls above... */

static struct linear_malloc_index_instance *arena_info_for_userptr(struct allocator *a, void *userptr)
{
	return linear_malloc;
}
static struct linear_malloc_index_instance *ensure_arena_info_for_userptr(
	struct allocator *a,
	void *userptr)
{
	return arena_info_for_userptr(a, userptr);
}
static void linear_malloc_index_insert(
	struct allocator *a,
	struct linear_malloc_index_instance *ignored,
	void *allocptr, size_t caller_requested_size, const void *caller,
	sizefn_t *sizefn)
{
	size_t real_requested_size = CHUNK_SIZE_WITH_TRAILER(caller_requested_size,
		struct insert, void*);
	/* We know this because we wrote the pre_alloc function which incremented
	   the size... this is in stubgen.h. The size requested is...
	   CHUNK_SIZE_WITH_TRAILER(orig_size, INSERT_TYPE, void*)
	   (defined in malloc-meta.h).
	 */
	size_t real_caller_usable_size = real_requested_size - sizeof (INSERT_TYPE);
	struct insert *insert = insert_for_chunk_and_caller_usable_size(allocptr,
		real_caller_usable_size);
	insert->alloc_site = (uintptr_t) caller;
	linear_malloc->recs[linear_malloc->nrecs_used++] = (struct linear_malloc_rec) {
		.addr = allocptr,
		.caller_requested_size = caller_requested_size,
		.padding_to_caller_usable_size = real_caller_usable_size - caller_requested_size
	};
	
	if (linear_malloc->nrecs_used > 1 &&
			(uintptr_t) linear_malloc->recs[linear_malloc->nrecs_used - 1].addr <
			(uintptr_t) linear_malloc->recs[linear_malloc->nrecs_used - 2].addr)
	{
		qsort(linear_malloc->recs,
			linear_malloc->nrecs_used, sizeof (struct linear_malloc_rec),
			compare_linear_mallocs);
	}
}
static void linear_malloc_index_delete(struct allocator *a,
	struct linear_malloc_index_instance *ignored,
	void *userptr,
	sizefn_t *sizefn)
{
	struct linear_malloc_rec *found = find_linear_malloc_rec(userptr,
		linear_malloc->recs,
		MAX_LINEAR_MALLOCS, linear_malloc->nrecs_used);
	found->addr = 0;
	qsort(linear_malloc->recs,
			linear_malloc->nrecs_used, sizeof (struct linear_malloc_rec),
			compare_linear_mallocs);
	assert(!linear_malloc->recs[linear_malloc->nrecs_used - 1].addr);
	--linear_malloc->nrecs_used;
#if 0 /* version that assumes only the greatest addr can be freed... this is not quite
         the restriction */ 
	if (found && found - linear_malloc->recs == linear_malloc->nrecs_used - 1)
	{ --linear_malloc->nrecs_used; return; }
	// error!
	debug_printf(0, "asked to delete non-terminating allocation record\n");
#endif
}
static void linear_malloc_index_reinsert_after_resize(
	struct allocator *a,
	struct linear_malloc_index_instance *oldinfo, /* new and old need not share a bitmap! */
	void *userptr,
	size_t modified_size,
	size_t old_usable_size,
	size_t requested_size,
	const void *caller, void *new_allocptr, sizefn_t *sizefn)
{
	linear_malloc_index_insert(a, oldinfo, new_allocptr, requested_size, caller, sizefn);
}
static inline
size_t ld_so_malloc_usable_size(void *arg)
{
	return linear_malloc_usable_size(arg, linear_malloc->recs,
		MAX_LINEAR_MALLOCS, linear_malloc->nrecs_used);
}
void __notify_free(void *arg) __attribute__((visibility("hidden")));
void __notify_free(void *arg) {}
/* FIXME: we should parameterise the generation on the arena info structure.
 * For now we just monkey-patch what gets generated, to swap in our struct name. */
#define arena_bitmap_info linear_malloc_rec
/* Our generated instrumentation requires __current_allocsite and friends...
 * these are normally defined in liballocs and dummyweaks.
 *
 * REMEMBER: our code here is generated as part of allocsld, but it *runs*
 * called from the real ld.so. In *that* context there is a separate TLS
 * implementation running. And there is a liballocs (either dummyweak or
 * real/both), so there is a definition of these TLS vars. BUT when the
 * early malloc calls happen, these DSOs haven't been loaded, and more generally
 * TLS isn't working yet. So we need to hack in a special static version
 * of them. */

#include "stubgen.h"
ALLOC_EVENT_INDEXING_DEFS4(__ld_so_malloc, linear_malloc, ld_so_malloc_usable_size, __default_initial_lifetime_policies)


static
_Bool instr_cb(ElfW(Sym) *sym, unsigned char *dynstr,
	uintptr_t load_addr, void *arg)
{
	struct trampoline_buf_info *trampoline_buf_info = (struct trampoline_buf_info *) arg;

	const char *name = dynstr + sym->st_name;
	// FIXME: get these names from elsewhere
	// (where? simply a constant string in the meta-DSO perhaps?...)
	if (0 == strcmp(name, "__minimal_malloc")
	||  0 == strcmp(name, "__minimal_calloc")
	||  0 == strcmp(name, "__minimal_realloc")
	||  0 == strcmp(name, "__minimal_free")
	)
	{
		void *function_entry = sym_to_addr_given_base(load_addr, sym);
		debug_printf(0, "ld.so defines a malloc-family function: %s at %p (%p+0x%lx)\n", name,
			function_entry, (void*) load_addr, (unsigned long) sym->st_value);
		size_t function_size = sym->st_size; // FIXME: wrong for IFUNCs?
		void *protect_begin = RELF_ROUND_DOWN_PTR_(function_entry, page_size);
		void *protect_end = RELF_ROUND_UP_PTR_(function_entry + NBYTES_TO_CLOBBER, page_size);
		int ret = mprotect(protect_begin,
			(uintptr_t) protect_end - (uintptr_t) protect_begin,
			PROT_READ|PROT_WRITE);
#define case_(stem) (0 == strcmp(name, "__minimal_" #stem )) { \
 void *ret = write_monopoline_and_detour( \
				/* void *func */ function_entry, \
				/* void *func_limit */(char*) function_entry + function_size, \
				allocsld_detour_ ## stem, \
				&orig_ ## stem, \
				trampoline_buf_info->nextfree, \
				trampoline_buf_info->limit \
				); \
 debug_printf(0, "redirected __minimal_ " #stem " to a trampoline of length %d at %p\n", (int)((uintptr_t) ret - (uintptr_t) trampoline_buf_info->nextfree), trampoline_buf_info->nextfree); \
 trampoline_buf_info->nextfree = ret; \
}
		if case_(malloc)
		else if case_(calloc)
		else if case_(realloc)
		else if case_(free)

		ret = mprotect(protect_begin,
			(uintptr_t) protect_end - (uintptr_t) protect_begin,
			PROT_READ|PROT_EXEC);
	}
	return 1; // keep going
}
