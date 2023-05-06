#define _GNU_SOURCE
#include <elf.h>
#include <string.h>
size_t strlcat(char *dst, const char *src, size_t size);
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <ctype.h>
#include <unistd.h>
#include "liballocs.h"
#include "allocmeta.h"
#include "relf.h"
#include "librunt.h"
#include "pageindex.h"

#include "elf-allocators.h"
#include "elf-refs.h"
#include "emit-asm.h"

int main(void)
{
	// assert our meta-object has been loaded, since we can't work without it?
	// FIXME: we now link in our usedtypes, but that doesn't help because
	// we didn't finish the macro magic that would make them actually used;
	// instead we still do need the meta-DSO
	//debug = getenv("DEBUG");
	assert(NULL != dlopen(__liballocs_meta_libfile_name(__runt_get_exe_realpath()), RTLD_NOW|RTLD_NOLOAD));
	char *path = getenv("ELF_FILE_TEST_DSO");
	if (!path) path = getenv("LIBALLOCS_BUILD");
	assert(path && "test lib should be loaded with ELF_FILE_TEST_DSO or LIBALLOCS_BUILD set");
	int fd = open(path, O_RDONLY);
	assert(fd != -1);
	struct stat s;
	int ret = fstat(fd, &s);
	assert(ret == 0);
	size_t len = ROUND_UP(s.st_size, COMMON_PAGE_SIZE);
	void *mapping = mmap(NULL, len, MAP_SHARED,
		PROT_READ, fd, 0);
	assert((intptr_t) mapping > 0);
	struct big_allocation *b = elf_adopt_mapping_sequence(mapping, len, 0);
	assert(b);
	struct uniqtype *u = elf_get_type(mapping);
	assert(u == elf_file_type_table[ELF_DATA_EHDR]);
	printf("ELF file at %p (%s) has %d allocations\n",
		mapping, path,
		((struct elf_elements_metadata *) b->suballocator_private)->metavector_size
	);
	/* Let's dump the ELF header fieldwise as assembly, just for fun.
	 * How should this work?
	 * In general we want to recursively walk the allocation tree
	 * until we get down to primitives, i.e. we want to walk even
	 * under the uniqtype level. For each primitive, we use an assembly
	 * directive to output its data. */
	uintptr_t asm_cursor_addr = (uintptr_t) mapping;
	/* How can we ensure that __uniqtype__Elf64_Ehdr will be generated and
	 * loaded? For now we have put a hack into lib-test, but we need to
	 * ensure meta-objects have been loaded. */
	struct alloc_tree_pos scope = {
		.base = b->begin,
		.bigalloc_or_uniqtype = (uintptr_t) b
	};
	/* Walk references, to get the pointer targets. We do this using the stock
	 * __liballocs_walk_refs_cb.
	 * For each reference we find, we append a record to our buffer,
	 * recording various things about its source and target. 
	 * Once we have all the targets, we do *another* DF walk, but *not*
	 * walking references, but rather, walking targets. For anything that is a
	 * target, we snarf its name. (Problem: where in the tree counts? Well, we
	 * recorded the type, so that'll do.) */
	struct interpreter elf_offset_or_pointer_resolver = {
		.name = "ELF-offset-or-pointer interpreter",
		.can_interp = can_interp_elf_offset_or_pointer,
		.do_interp = do_interp_elf_offset_or_pointer,
		.may_contain = may_contain_elf_offset_or_pointer,
		.is_environ = is_environ_elf_offset_or_pointer
	};
	struct elf_walk_refs_state reference_state = {
		.ref = (struct walk_refs_state) {
			.interp = &elf_offset_or_pointer_resolver,
			.ref_cb = seen_elf_reference_or_pointer_cb
			/* cb arg is always just the reference state */
		},
		.buf = NULL,
		.buf_capacity = 0,
		.buf_used = 0,
		.file_bigalloc = b
	};
	struct walk_environ_state environ_state = {
		.interp = &elf_offset_or_pointer_resolver,
		.environ_cb = seen_elf_environ_cb,
		.buf = NULL,
		.buf_capacity = 0,
		.buf_used = 0
	};
	// also __liballocs_walk_down_at( ... ) which privately uses an offset-based helper
	/* Gather 'environment' info, i.e. stuff that we need in order to decode
	 * references a.k.a. offsets-or-pointers. Am not entirely sure that this step is sane.
	 * The issue is possibly that we need to emit references *symbolically*,
	 * so we need to gather knowledge that will let us *generate* those symbols (labels *references*). */
	__liballocs_walk_allocations_df(
		&scope,
		__liballocs_walk_environ_cb,
		&environ_state
	);
	printf("Saw %u environment elements on our walk\n", (unsigned) environ_state.buf_used);
	/* Now gather references themselves. The idea is that we need incoming
	 * references so that we can emit label *definitions* as we go along. */
	__liballocs_walk_allocations_df(
		&scope,
		__liballocs_walk_refs_cb, // generic cb takes a struct walk_environ_state * arg, as void
		&reference_state          // ... which our seen_... cb it will get by casting this guy
	);
	printf("Saw %u references on our walk\n", (unsigned) reference_state.buf_used);
	// now sort the refs buffer by its target offset
	qsort(reference_state.buf, reference_state.buf_used, sizeof *reference_state.buf,
		compare_reference_target_address);
	// now look for ref targets
	__liballocs_walk_allocations_df(
		&scope,
		__liballocs_name_ref_targets_cb,
		&reference_state
	);
	/* Now sort the refs buffer by its source offset, so we can find
	 * ourselves as we do another DF walk. */
	qsort(reference_state.buf, reference_state.buf_used, sizeof *reference_state.buf,
		compare_reference_source_address);
	sleep(3);
	/* Walk allocations. */
	struct emit_asm_ctxt ctxt = {
		.start_address = mapping,
		.emitted_up_to_offset = 0,
		//.overall_comment = "ELF element",
		.depth = 0,
		.references = &reference_state, // HMM, we chain ctxts to...
		.file_bigalloc = b
	};
	__liballocs_walk_allocations_df(
		&scope,
		emit_memory_asm_cb,
		&ctxt
	);
	drain_queued_output(&ctxt, 0);
	if (ctxt.queued_end_output) free(ctxt.queued_end_output);
	if (reference_state.buf)
	{
		// FIXME: free anything allocated per-record as well
		for (unsigned i = 0; i < reference_state.buf_used; ++i)
		{
			void *nameptr = reference_state.buf[i].target_alloc_name;
			if (nameptr) free(nameptr);
		}
		free(reference_state.buf);
	}
}
