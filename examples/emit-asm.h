#ifndef EMIT_ASM_H_
#define EMIT_ASM_H_

struct elf_walk_refs_state;
struct big_allocation;

struct emit_asm_ctxt
{
	void *start_address;
	unsigned long emitted_up_to_offset;
	unsigned depth;
	// need to thread through a summary of incoming references,
	// so that we can emit labels as we go along
	struct elf_walk_refs_state *references;
	// to simulate a post-order traversal given only in-order traversal,
	// we queue up post-order output, which gets flushed
	// (1) on output at or below its depth, and
	// (2) at the end of the traversal.
	struct {
		unsigned depth;
		char *output;
	} *queued_end_output;
	unsigned queue_size;
	unsigned queue_nused;
	struct big_allocation *file_bigalloc;
};

int compare_reference_source_address(const void *refent1_as_void, const void *refent2_as_void);
int compare_reference_target_address(const void *refent1_as_void, const void *refent2_as_void);

int __liballocs_name_ref_targets_cb(struct big_allocation *maybe_the_allocation,
	void *obj, struct uniqtype *t, const void *allocsite,
	struct alloc_tree_link *link_to_here,
	void *elf_walk_refs_state_as_void);

int emit_memory_asm_cb(struct big_allocation *maybe_the_allocation,
		void *obj, struct uniqtype *t, const void *allocsite,
		struct alloc_tree_link *link_to_here, void *emit_asm_ctxt_as_void);

void drain_queued_output(struct emit_asm_ctxt *ctxt, unsigned depth);

#endif
