#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include "librunt.h"
#include "relf.h"
#include "maps.h"
#include "liballocs_private.h"
#include "raw-syscalls-defs.h"
#include "dlbind.h"

uintptr_t executable_data_segment_start_addr __attribute__((visibility("hidden")));

/* We talk about "allocators" but in the case of retrofitted 
 * allocators, they actually come in up to three parts:
 * 
 * - the actual implementation;
 * - the index (separate);
 * - the instrumentation that keeps the index in sync.
 * 
 * By convention, each of our allocators also exposes "notify_*"
 * operations that the instrumentation uses to talk to the index. */

/* The mmap allocator's notion of allocation is roughly a 
 * *sequence* of memory mappings. This is so that a single segment
 * can have a single parent allocation, even though it
 * might have been created from several contiguous memory mappings
 * with different flags and permissions (PT_GNU_RELRO is one case
 * that requires this; bss areas, where memsz > filesz, are another).
 */

static const char *filename_for_fd(int fd)
{
	if (fd == -1) return NULL;
	
	/* We read from /proc into a thread-local buffer. */
	static char __thread out_buf[8192];
	
	static char __thread proc_path[4096];
	/* FIXME: snprintf is not async-signal-safe, but we might be called 
	 * from the mmap syscall signal handler. */
	int ret = snprintf(proc_path, sizeof proc_path, "/proc/%d/fd/%d", getpid(), fd);
	assert(ret > 0);
	ret = readlink(proc_path, out_buf, sizeof out_buf);
	assert(ret != -1);
	out_buf[ret] = '\0';
	
	return out_buf;
}

static void check_mapping_sequence_sanity(struct mapping_sequence *cur);

/* How are we supposed to allocate the mapping sequence metadata? */

static struct big_allocation *add_bigalloc(void *begin, size_t size)
{
	struct big_allocation *b = __liballocs_new_bigalloc(
		begin,
		size,
		NULL /* allocator_private */,
		NULL /* allocator_private_free */,
		NULL,
		&__mmap_allocator
	);
	if (!b) abort();
	return b;
}

/* This looks like Guillaume code. Why does it exist?
 *
 * 74a9081c
 * This prevents infinite recursion after an mmap call caused by a malloc
 * heap extension.
 *
 * So the problem is that malloc may do an mmap which may
 * require allocating a new mapping sequence (new heap arena), which
 * may do a malloc
 * ... and so on ...
 * without forward progress.
 *
 * What's the right way to do this? We want to always be able to create a
 * mapping sequence without doing a malloc. Suppose we can arrange that. So then
 * what if a user malloc triggers an mmap? Then that should be OK because it
 * won't trigger another malloc.
 *
 * So in short I think Guillaume's solution is good enough for now.
 */
static struct big_allocation *add_mapping_sequence_bigalloc(struct mapping_sequence *seq)
{
	struct big_allocation *b = add_bigalloc(seq->begin, (char*) seq->end - (char*) seq->begin);
	if (!b) abort();
	struct mapping_sequence *copy = __private_malloc(sizeof (struct mapping_sequence));
	if (!copy) abort();
	memcpy(copy, seq, sizeof (struct mapping_sequence));
	b->allocator_private = copy;
	b->allocator_private_free = __private_free;
	return b;
}

static struct big_allocation *add_mapping_sequence_bigalloc_nomalloc(struct mapping_sequence *seq) {
	struct big_allocation *b = add_bigalloc(seq->begin, (char*) seq->end - (char*) seq->begin);
	if (!b) abort();

	static struct mapping_sequence mapping_sequence_pool[64];
	static struct mapping_sequence *next_free_mapping_seq = mapping_sequence_pool;

	assert(next_free_mapping_seq < mapping_sequence_pool + 64);

	struct mapping_sequence *copy = next_free_mapping_seq++;
	if (!copy) abort();
	memcpy(copy, seq, sizeof (struct mapping_sequence));

	b->allocator_private = copy;
	b->allocator_private_free = __private_free;

	return b;
}

__attribute__((visibility("hidden")))
struct big_allocation *__add_mapping_sequence_bigalloc_nomalloc(struct mapping_sequence *seq)
{
	return add_mapping_sequence_bigalloc_nomalloc(seq);
}

static _Bool mapping_entry_equal(struct mapping_entry *e1,
		struct mapping_entry *e2)
{
	return e1->begin == e2->begin &&
		e1->end == e2->end &&
		e1->prot == e2->prot &&
		e1->flags == e2->flags &&
		e1->offset == e2->offset &&
		e1->is_anon == e2->is_anon &&
		e1->caller == e2->caller;
}
static _Bool mapping_entries_equal(struct mapping_entry *e1,
		struct mapping_entry *e2,
		size_t n)
{
	for (unsigned i = 0; i < n; ++i)
	{
		if (!mapping_entry_equal(e1 + i, e2 + i))
		{
			write_string("Mapping entries differ: ");
			write_ulong((unsigned long) e1 + i);
			write_string(" ");
			write_ulong((unsigned long) e2 + i);
			write_string("\n");
			
			return 0;
		}
	}
	return 1;
}

static _Bool mapping_sequence_prefix(struct mapping_sequence *s1,
	struct mapping_sequence *s2)
{
	return s1->nused <= s2->nused && mapping_entries_equal(&s1->mappings[0],
		&s2->mappings[0],
		s1->nused);
}
static _Bool mem_range_prefix(struct mapping_sequence *s1,
	struct mapping_sequence *s2)
{
	return s1->begin == s2->begin && s1->end < s2->end;
}
static _Bool mapping_sequence_suffix(struct mapping_sequence *s1,
	struct mapping_sequence *s2)
{
	return s1->nused <= s2->nused &&
		mapping_entries_equal(
			&s2->mappings[s2->nused - s1->nused],
			&s1->mappings[0],
			s1->nused);
}
static _Bool mem_range_suffix(struct mapping_sequence *s1,
	struct mapping_sequence *s2)
{
	return s1->end == s2->end && s1->begin > s2->begin;
}
// FIXME: temporarily hidden to prevent annoying abort() collapsing after inlining
void add_mapping_sequence_bigalloc_if_absent(struct mapping_sequence *seq) __attribute__((visibility("hidden")));
void add_mapping_sequence_bigalloc_if_absent(struct mapping_sequence *seq)
{
	/* Test 1. Find the top-level parent of both the beginning
	 * and end addresses. It should be the same, perhaps zero.
	 */
	struct big_allocation *parent_begin = &big_allocations[pageindex[PAGENUM(seq->begin)]];
	while (parent_begin->parent) parent_begin = parent_begin->parent;
	if (parent_begin == &big_allocations[0]) parent_begin = NULL;
	struct big_allocation *parent_end = &big_allocations[pageindex[PAGENUM(((char*)seq->end)-1)]];
	while (parent_end->parent) parent_end = parent_end->parent;
	if (parent_end == &big_allocations[0]) parent_end = NULL;
	
	/* Special case: if we've strayed into the auxv, our work is done. */
	if (parent_end && parent_begin
		&& parent_begin == parent_end
		 && parent_begin->allocated_by == &__auxv_allocator)
	{
		return;
	}
	
	struct mapping_sequence *existing_seq = NULL;

	if (!parent_begin && !parent_end) goto go_ahead;
	
	if (!parent_begin && parent_end)
	{
		/* This might be a case of a "false sequence": a suffix in the
		 * sequence is not actually related to the prefix, and already
		 * existed before the prefix was created. If we identify that
		 * this is occurring, we simply delete the overlap from the new
		 * sequence and then continue. */
		existing_seq = (struct mapping_sequence *) parent_end->allocator_private;
		if (!existing_seq)
		{
			/* The parent end has a bigalloc but no mapping sequence. HMM. */
		}
		if (mem_range_suffix(existing_seq, seq))
		{
			if (!mapping_sequence_suffix(existing_seq, seq))
			{
				write_string("Registered mapping sequence that is memory suffix of existing, but not splittable\n");
				goto report_problem;
			}
			write_string("Registered seq begin address: ");
			write_ulong((unsigned long) seq->begin);
			write_string("\nRegistered seq end address: ");
			write_ulong((unsigned long) seq->end);
			write_string("\nExisting bigalloc begin address: ");
			write_ulong((unsigned long) parent_end->begin);
			write_string("\nExisting bigalloc end address: ");
			write_ulong((unsigned long) parent_end->end);
			write_string("\n");
			/* Delete the last existing_seq->nused elements from seq */
			bzero(&seq->mappings[seq->nused - existing_seq->nused],
					existing_seq->nused * sizeof (struct mapping_entry));
			seq->nused -= existing_seq->nused;
			seq->end = existing_seq->begin;
			check_mapping_sequence_sanity(seq);
			check_mapping_sequence_sanity(existing_seq);
			/* Don't touch the parent end bigalloc. We're leaving it as-is. */
			write_string("\nRegistered seq begin address after split: ");
			write_ulong((unsigned long) seq->begin);
			write_string("\nRegistered seq end address after split: ");
			write_ulong((unsigned long) seq->end);
			write_string("\n");
			goto go_ahead;
		}
		/* We can handle this if we just have a single mapping.
		 * The new mapping is bigger, so extend the existing. */
		else if (seq->nused == 1 && existing_seq->nused == 1)
		{
			write_string("Warning: single-element mapping sequence was silently extended\n");
			__liballocs_pre_extend_bigalloc(parent_end, seq->begin);
			existing_seq->begin = seq->begin;
			existing_seq->mappings[0] = seq->mappings[0];
			check_mapping_sequence_sanity(existing_seq);
			return;
		}
		else
		{
			write_string("Hit mapping sequence pre-extend case we can't handle\n");
			goto report_problem;
		}
	}
	else if (parent_begin && !parent_end)
	{
		/* If we've been given a mapping sequence of which parent_begin's
		 * is a suffix, then extend parent_begin to cover the new end
		 * and copy the new mapping sequence in. */
		if (mapping_sequence_prefix((struct mapping_sequence *) parent_begin->allocator_private,
			seq))
		{
			__liballocs_extend_bigalloc(parent_begin, seq->end);
			memcpy(parent_begin->allocator_private,
				seq, sizeof *seq);
			return;
		}
		else
		{
			write_string("Hit mapping sequence post-extend case we can't handle\n");
			goto report_problem;
		}
	}
	else if (parent_end && parent_begin && parent_begin == parent_end)
	{
		/* FIXME: remember that augment_sequence can handle sloppy mappings,
		 * so delegate to it if possible. */
		/* A mapping exists and overlaps a unique existing one. If it's an
		 * exact match, we can simply return. */
		existing_seq = (struct mapping_sequence *) parent_begin->allocator_private;
		if (mapping_sequence_suffix(existing_seq, seq) && mapping_sequence_suffix(seq, existing_seq))
		{
			return;
		}
		else if (mapping_sequence_prefix(seq, existing_seq))
		{
			/* The sequences are not equal. But maybe only metadata changed... */
			if (seq->end == existing_seq->end)
			{
				write_string("Warning: mapping metadata changed. This probably shouldn't happen.");
				for (struct mapping_sequence *i_seq = existing_seq; i_seq; 
						i_seq = (i_seq == existing_seq) ? seq : NULL)
				{
					write_string("\nSequence begin: ");
					write_ulong((unsigned long) i_seq->begin);
					write_string("; end: ");
					write_ulong((unsigned long) i_seq->end);
					write_string("\nUsed count: ");
					write_ulong((unsigned long) i_seq->nused);
					for (unsigned i = 0; i < i_seq->nused; ++i)
					{
						write_string("\nMapping ");
						write_ulong((unsigned long) i);
						write_string(": begin ");
						write_ulong((unsigned long) i_seq->mappings[i].begin);
						write_string(" end ");
						write_ulong((unsigned long) i_seq->mappings[i].end);
						write_string(" prot ");
						write_ulong((unsigned long) i_seq->mappings[i].prot);
						write_string(" flags ");
						write_ulong((unsigned long) i_seq->mappings[i].flags);
						write_string(" caller ");
						write_ulong((unsigned long) i_seq->mappings[i].caller);
						write_string(" offset ");
						write_ulong((unsigned long) i_seq->mappings[i].offset);
						write_string(" is_anon ");
						write_ulong((unsigned long) i_seq->mappings[i].is_anon);
					}
				}
				write_string("\n");
				memcpy(existing_seq, seq, sizeof *seq);
				return;
			}
			/* The new sequence is a prefix of the existing one. In other words,
			 * something has changed meaning we wouldn't create the last bit
			 * of the existing sequence now. Simply chop it off. */
			write_string("Warning: mapping sequence was silently truncated at ");
			write_ulong((unsigned long) seq->end);
			write_string(" up to ");
			write_ulong((unsigned long) existing_seq->end);
			write_string("\n");
			memcpy(existing_seq, seq, sizeof *seq);
			__liballocs_truncate_bigalloc_at_end(parent_begin, seq->end);
			return;
		}
		else if (mapping_sequence_suffix(seq, existing_seq))
		{
			/* The new sequence is a suffix of the existing one. */
			goto report_problem;
		}
		else
		{
			write_string("Hit mapping sequence bounds-matched content-unequal case we can't handle\n");
			goto report_problem;
		}
	}
	else if (parent_end && parent_begin && parent_begin != parent_end)
	{
		/* HM. We cover more than one mapping sequence. Not good. */
		write_string("Hit mapping sequence multi-overlap case we can't handle\n");
		goto report_problem;
	}
	else abort(); // we should have covered all the cases

go_ahead: ;
	/* Extra test: is this the stack sequence? */
	struct big_allocation *b = add_mapping_sequence_bigalloc(seq);
	if (seq->filename && 0 == strncmp(seq->filename, "[stack", 6))
	{
		__auxv_allocator_notify_init_stack_mapping_sequence(b);
	}
	return;
report_problem:
	write_string("Saw a mapping sequence conflicting with existing one\n");
	write_string("New seq begin address: ");
	write_ulong((unsigned long) seq->begin);
	write_string("\nNew seq end address: ");
	write_ulong((unsigned long) seq->end);
	write_string("\nNew seq mapping count: ");
	write_ulong((unsigned long) seq->nused);
	for (unsigned i = 0; i < seq->nused; ++i)
	{
		write_string("\nNew seq mapping ");
		write_ulong((unsigned long) i);
		write_string(": begin ");
		write_ulong((unsigned long) seq->mappings[i].begin);
		write_string(" end ");
		write_ulong((unsigned long) seq->mappings[i].end);
	}
	if (parent_end)
	{
		write_string("\nExisting end-bigalloc begin address: ");
		write_ulong((unsigned long) parent_end->begin);
		write_string("\nExisting end-bigalloc end address: ");
		write_ulong((unsigned long) parent_end->end);
	}
	if (parent_begin)
	{
		write_string("\nExisting begin-bigalloc begin address: ");
		write_ulong((unsigned long) parent_end->begin);
		write_string("\nExisting begin-bigalloc end address: ");
		write_ulong((unsigned long) parent_end->end);
	}
	if (existing_seq)
	{
		write_string("\nExisting seq begin address: ");
		write_ulong((unsigned long) existing_seq->begin);
		write_string("\nExisting seq end address: ");
		write_ulong((unsigned long) existing_seq->end);
		write_string("\nExisting seq mapping count: ");
		write_ulong((unsigned long) existing_seq->nused);
		for (unsigned i = 0; i < existing_seq->nused; ++i)
		{
			write_string("\nExisting seq mapping ");
			write_ulong((unsigned long) i);
			write_string(": begin ");
			write_ulong((unsigned long) existing_seq->mappings[i].begin);
			write_string(" end ");
			write_ulong((unsigned long) existing_seq->mappings[i].end);
		}
	}
	write_string("\n");
	if (existing_seq)
	{
		write_string("Nuking any overlapping bigallocs and attempting continue...\n");
		/* If we're about to nuke any mapping sequence crossing the data segment start,
		 * clear our pointers to those bigallocs. Note that a change in the program break
		 * is the big reason for hitting this case in the first place. FIXME: so why
		 * isn't tihs entirely handled by our __*_allocator_notify_brk() logic? */
		if (executable_data_segment_start_addr
				&& (char*) executable_data_segment_start_addr
					>= (char*) existing_seq->begin
				&& (char*) executable_data_segment_start_addr
					< (char*) existing_seq->end)
		{
			executable_mapping_bigalloc = NULL; // FIXME: when will it get reinstated?
			__brk_bigalloc = NULL;
		}
		__liballocs_delete_all_bigallocs_overlapping_range(existing_seq->begin,
			existing_seq->end);
		goto go_ahead;
	}
	abort();
}

static void delete_mapping_sequence_span(struct mapping_sequence *seq,
	void *addr, size_t length)
{
	check_mapping_sequence_sanity(seq);
	for (int i = 0; i < MAPPING_SEQUENCE_MAX_LEN; ++i)
	{
		if ((char*) seq->mappings[i].begin <= (char*) addr + length
				&& (char*) seq->mappings[i].end > (char*) addr)
		{
			/* We have some overlap. Is it partial or total? */

			// we can't punch holes, yet (FIXME)
			_Bool splits_mapping = ((char*) addr > (char*) seq->mappings[i].begin
					&& (char*) addr + length < (char*) seq->mappings[i].end);
			if (splits_mapping) abort();
			
			size_t left_at_beginning = 
				((char*) addr > (char*) seq->mappings[i].begin) 
					? (char*) addr - (char*) seq->mappings[i].begin
					: 0;
			size_t left_at_end = ((char*) addr + length > (char*) seq->mappings[i].end)
					? 0
					: (char*) seq->mappings[i].end - ((char*) addr + length);
			
			_Bool total = (left_at_beginning == 0) && (left_at_end == 0);
			
			if (total)
			{
				/* clear it */
				memset(&seq->mappings[i], 0, sizeof (struct mapping_entry));
			}
			else
			{
				assert(left_at_beginning == 0 || left_at_end == 0);
				unsigned long current_length =  seq->mappings[i].end - seq->mappings[i].begin;
				if (left_at_beginning == 0)
				{
					seq->mappings[i].begin = (char*) seq->mappings[i].begin
						 + (current_length - left_at_end);
					if (i == 0) seq->begin = seq->mappings[i].begin;
				}
				else
				{
					seq->mappings[i].end = (char*) seq->mappings[i].end
						 - (current_length - left_at_beginning);
					if (i == seq->nused - 1) seq->end = seq->mappings[i].end;
				}
			}
		}
	}
	
	/* Now compact the sequence. */
	int i = 0;
	while (i < seq->nused)
	{
		if (!seq->mappings[i].begin)
		{
			// it's cleared; move all subsequent mappings down one
			memmove(&seq->mappings[i], &seq->mappings[i + 1],
					(seq->nused - (i + 1)) * sizeof (struct mapping_entry));
			memset(&seq->mappings[seq->nused - 1], 0, sizeof (struct mapping_entry));
			--(seq->nused);
		}
		else ++i;
	}
	
	/* Update the overall metadata.
	 * If the beginning is in the deleted span, push it to the end of the deleted span. 
	 * If the end is in the deleted span, push it to the beginning of the deleted span. */
	if ((char*) seq->begin >= (char*) addr
			&& (char*) seq->begin < (char*) addr + length)
	{
		seq->begin = (char*) addr + length;
	}
	if ((char*) seq->end > (char*) addr
			&& (char*) seq->end <= (char*) addr + length)
	{
		seq->end = addr;
	}
	check_mapping_sequence_sanity(seq);
}

static void do_munmap(void *addr, size_t length, void *caller)
{
	char *cur = (char*) addr;
	/* Linux lets us munmap *less* than a full page, with the effect of 
	 * unmapping the whole page. Sigh. */
	size_t remaining_length = ROUND_UP(length, PAGE_SIZE);
	while (cur < (char*) addr + length)
	{
		/* We're always working at level 0 */
		struct big_allocation *b = __lookup_bigalloc_from_root(cur, &__mmap_allocator, NULL);
		if (!b)
		{
			/* Okay, no mapping present. Zoom to the next bigalloc. */
			cur += PAGE_SIZE;
			remaining_length -= PAGE_SIZE;
			continue; // FIXME: use wide-character string funcs instead
		}
		struct mapping_sequence *seq = b->allocator_private;
		
		/* Are we pre-truncating, post-truncating, splitting or wholesale deleting? */
		assert(cur >= (char*) b->begin);
		if (cur == (char*) b->begin)
		{
			/* We're either pre-truncating or wholesale deleting. */
			if (cur + remaining_length >= (char*) b->end)
			{
				/* wholesale deletion */
				remaining_length -= (char*) b->end - cur;
				cur = b->end;
				__liballocs_delete_bigalloc_at(b->begin, &__mmap_allocator);
			}
			else
			{
				/* Pre-truncation. */
				__liballocs_truncate_bigalloc_at_beginning(b, cur + remaining_length);
				delete_mapping_sequence_span(seq, cur, remaining_length);
				/* We're necessarily finished */
				break;
			}
		}
		else // cur > b->begin
		{
			assert(cur + remaining_length > (char*) b->begin);
			if (cur + remaining_length >= (char*) b->end)
			{
				/* We're removing from the end of the mapping. */
				size_t amount_removed = (char*) b->end - cur;
				remaining_length -= amount_removed;
				__liballocs_truncate_bigalloc_at_end(b, cur);
				delete_mapping_sequence_span(seq, cur, amount_removed);
				cur += amount_removed;
			}
			else
			{
				/* We're chopping out a hole in the middle of the mapping. 
				 * First split the bigalloc. The metadata pointer will be shared
				 * between the two. Then copy and update the metadata. From each
				 * half's mapping_sequence, we delete the hole *and* the other's 
				 * part. */
				
				void *old_end = b->end;
				struct big_allocation *second_half = 
					__liballocs_split_bigalloc_at_page_boundary(b, (char*) addr + length);
				if (!second_half) abort();
				__liballocs_truncate_bigalloc_at_end(b, addr);
				/* Now the bigallocs are in the right place, but their metadata is wrong. */
				struct mapping_sequence *new_seq = __private_malloc(sizeof (struct mapping_sequence));
				struct mapping_sequence *orig_seq = b->allocator_private;
				memcpy(new_seq, orig_seq, sizeof (struct mapping_sequence));
				/* From the first, delete from the hole all the way. */
				delete_mapping_sequence_span(orig_seq, addr, (char*) old_end - (char*) addr);
				/* From the second, delete from the old begin to the end of the hole. */
				delete_mapping_sequence_span(new_seq, b->begin, 
						((char*) addr + length) - (char*) b->begin);
				second_half->allocator_private = new_seq;
				/* same free function as before */
			}
		}
	}
}

void __mmap_allocator_notify_munmap(void *addr, size_t length, void *caller)
{
	/* HACK: Is it actually a stack or sbrk area? Branch out if so. */
	// FIXME
	do_munmap(addr, length, caller);
}

struct mapping_entry *__mmap_allocator_find_entry(const void *addr, struct mapping_sequence *seq)
{
	for (unsigned i = 0; i < seq->nused; ++i)
	{
		if ((char*) addr >= (char*) seq->mappings[i].begin
				&& (char*) addr < (char*) seq->mappings[i].end)
		{
			return &seq->mappings[i];
		}
	}
	return NULL;
}

static void do_mmap(void *mapped_addr, void *requested_addr, size_t length, int prot, int flags,
                  const char *filename, off_t offset, void *caller);
static _Bool augment_sequence(struct mapping_sequence *cur, 
	void *begin, void *end, int prot, int flags, off_t offset, const char *filename, void *caller);

static __thread int remembered_prot;
static __thread const char *remembered_filename;
static __thread off_t remembered_offset;
static __thread void *remembered_old_addr;

void __mmap_allocator_notify_mremap_before(void *old_addr, size_t old_size, size_t new_size, int flags, void *new_address, void *caller)
{
	/* HACK: Is it actually a stack or sbrk area? We can abort if so; remapping a
	 * stack is a weird enough thing to do that it's not urgent to support it. */
	// FIXME
	remembered_old_addr = old_addr;
	struct big_allocation *bigalloc_before = __lookup_bigalloc_from_root(old_addr,
		&__mmap_allocator, NULL);
	if (!bigalloc_before) abort();
	struct mapping_sequence *seq = bigalloc_before->allocator_private;
	if (!seq)
	{
		/* It's a chunk malloc'd by our own dlmalloc. HMM. */
		abort();
	}
	struct mapping_entry *maybe_ent = __mmap_allocator_find_entry(old_addr, seq);
	if (!maybe_ent) abort();
	remembered_prot = maybe_ent->prot;
	remembered_offset = maybe_ent->offset;
	remembered_filename = seq->filename;
}
void __mmap_allocator_notify_mremap_after(void *ret_addr, void *old_addr, size_t old_size, size_t new_size, int flags, void *new_address, void *caller)
{
	if (ret_addr != MAP_FAILED)
	{
		/* Does the address match the remembered one? This is a HACK, i.e. 
		 * we should really thread these through from mremap_replacement. */
		if (remembered_old_addr == old_addr)
		{
			do_munmap(old_addr, old_size, caller);
			do_mmap(ret_addr, 
					(flags & MREMAP_FIXED) ? new_address : NULL,
					new_size, remembered_prot, flags,
					remembered_filename, 
					/* What has happened to the offset? I think it is unchanged. */
					remembered_offset,
					caller);
		}
		else abort(); // FIXME: could do something best-effort
	}
}

static void do_mmap(void *mapped_addr, void *requested_addr, size_t requested_length, int prot, int flags,
                  const char *filename, off_t offset, void *caller)
{
	if (mapped_addr != MAP_FAILED)
	{
		if (mapped_addr == NULL) abort();
		
		/* The actual length is rounded up to page size. */
		size_t mapped_length = ROUND_UP(requested_length, PAGE_SIZE);
		
		/* Do we *overlap* any existing mapping? If so, we must discard
		 * that part -- but only if MAP_FIXED was specified, else it's an error. */
		_Bool saw_overlap = 0;
		for (unsigned i = 0; i < mapped_length >> LOG_PAGE_SIZE; ++i)
		{
			if (pageindex[((uintptr_t) mapped_addr >> LOG_PAGE_SIZE) + i] != 0)
			{
				/* We found an overlap. Do nothing for now, except remember
				 * that overlaps exist. */
				saw_overlap = 1;
			}
		}
		if (saw_overlap && !(flags & MAP_FIXED)) abort();
		/* We can now handle overlap in mmap(), but it should only happen
		 * when the caller really wants to map something over the top, 
		 * not when asking for a free addr. */
		
		/* Do we abut any existing mapping? Just do the 'before' case. */
		struct big_allocation *bigalloc_before = __lookup_bigalloc_from_root((char*) mapped_addr - 1,
			&__mmap_allocator, NULL);
		if (!bigalloc_before)
		{
			struct big_allocation *overlap_begin = __lookup_bigalloc_from_root((char*) mapped_addr,
				&__mmap_allocator, NULL);
			struct big_allocation *overlap_end = __lookup_bigalloc_from_root((char*) mapped_addr + mapped_length - 1,
				&__mmap_allocator, NULL);
			if (overlap_begin && (!overlap_end || overlap_begin == overlap_end))
			{
				/* okay, try extending this one */
				bigalloc_before = overlap_begin;
			}
		}
		if (bigalloc_before)
		{
			/* See if we can extend it. */
			struct mapping_sequence *seq = (struct mapping_sequence *) 
				bigalloc_before->allocator_private;
			_Bool success = augment_sequence(seq, mapped_addr, (char*) mapped_addr + mapped_length, 
				prot, flags, offset, filename, caller);
			char *requested_new_end = (char*) mapped_addr + mapped_length;
			if (success && requested_new_end > (char*) bigalloc_before->end)
			{
				/* Okay, now the bigalloc is bigger. */
				_Bool success = __liballocs_extend_bigalloc(bigalloc_before, 
					(char*) requested_new_end);
				if (!success) abort();
				assert(seq->begin == bigalloc_before->begin);
				assert(seq->end == bigalloc_before->end);
			}
			if (success) return;
			debug_printf(0, "Warning: mapping of %s could not extend preceding bigalloc\n", filename);
		}

		/* If we got here, we have to create a new bigalloc. */
		struct mapping_sequence new_seq;
		memset(&new_seq, 0, sizeof new_seq);
		/* "Extend" the empty sequence. */
		_Bool success = augment_sequence(&new_seq, mapped_addr, (char*) mapped_addr + mapped_length, 
				prot, flags, offset, filename, caller);
		if (!success) abort();
		if (!__private_realloc_active && !__private_memalign_active && !__private_posix_memalign_active
				&& !__private_calloc_active && !__private_malloc_active)
		{
			add_mapping_sequence_bigalloc(&new_seq);
		}
		else /* HMM -- probably an mmap from the private malloc. Not sure */
		{
			// HACK: Try to avoid infinite recursion by using a static version.
			// FIXME: Will fail if called too many times
			add_mapping_sequence_bigalloc_nomalloc(&new_seq);
		}
	}
}
void __mmap_allocator_notify_mmap(void *mapped_addr, void *requested_addr, size_t length, 
		int prot, int flags, int fd, off_t offset, void *caller)
{
	/* HACK: Is it actually a stack or sbrk area? Branch out if so. */
	// FIXME
	do_mmap(mapped_addr, requested_addr, length, prot, flags, filename_for_fd(fd), offset, caller);
}

void __mmap_allocator_notify_mprotect(void *addr, size_t len, int prot)
{
	
}

static int add_missing_cb(struct maps_entry *ent, char *linebuf, void *arg);
struct add_missing_cb_args
{
	struct mapping_sequence *seq;
	void *end_addr;
};
void add_missing_mappings_from_proc(void *executable_end_addr)
{
	struct maps_entry entry;

	char proc_buf[4096];
	int ret;
	ret = snprintf(proc_buf, sizeof proc_buf, "/proc/%d/maps", getpid());
	if (!(ret > 0)) abort();
	int fd = open(proc_buf, O_RDONLY);
	if (fd == -1) abort();
	
	/* We used to use getline(), but in some deployments it's not okay to 
	 * use malloc when we're called early during initialization. So we write
	 * our own read loop. */
	char linebuf[8192];
	
	struct mapping_sequence current = {
		.begin = NULL
	};
	struct add_missing_cb_args args = {
		.seq = &current,
		.end_addr = executable_end_addr
	};
	for_each_maps_entry(fd, get_a_line_from_maps_fd, linebuf, sizeof linebuf, &entry,
		add_missing_cb, &args);
	/* Finish off the last mapping. */
	if (current.nused > 0) add_mapping_sequence_bigalloc_if_absent(&current);

	close(fd);
}
static _Bool initialized;
static _Bool trying_to_initialize;

_Bool __mmap_allocator_is_initialized(void)
{
	return initialized;
}

static void *executable_end_addr;
static void *data_segment_start_addr;

struct big_allocation *executable_mapping_bigalloc __attribute__((visibility("hidden")));
struct big_allocation *executable_file_bigalloc __attribute__((visibility("hidden")));
struct big_allocation *executable_data_segment_bigalloc __attribute__((visibility("hidden")));
void __adjust_bigalloc_end(struct big_allocation *b, void *new_curbrk);

_Bool __mmap_allocator_notify_unindexed_address(const void *mem)
{
	if (!initialized) return 0;
	return __brk_allocator_notify_unindexed_address(mem);
}

static void set_executable_mapping_bigalloc(void *real_end)
{
	/* We can be called more than once. */
	if (executable_mapping_bigalloc) return;
	
	/* Can't do anything if we haven't seen the data segment yet. */
	if (!executable_data_segment_start_addr) return;
	
	/* Which bigalloc is top-level and spans the executable's data segment
	 * *start*? */
	for (int i = 1; BIGALLOC_IN_USE(&big_allocations[i]); ++i)
	{
		if (!big_allocations[i].parent)
		{
			// write_string("Top-level bigalloc end ");
			// write_ulong((unsigned long) big_allocations[i].end);
			// write_string("\n");
			/* Does this include the data segment? */
			if ((uintptr_t) big_allocations[i].end >= executable_data_segment_start_addr
					&& (uintptr_t) big_allocations[i].begin <= executable_data_segment_start_addr)
			{
				executable_mapping_bigalloc = &big_allocations[i];
				if ((uintptr_t) executable_mapping_bigalloc->end < (uintptr_t) real_end)
				{
					__liballocs_extend_bigalloc(executable_mapping_bigalloc, real_end);
				}
				break;
			}
		}
	}
	if (!executable_mapping_bigalloc) abort();
}

void ( __attribute__((constructor(101))) __mmap_allocator_init)(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;

		/* We require the pageindex to be init'd. */
		__pageindex_init();

		/* Delay start-up here if the user asked for it. We do this here
		 * because we should run earlier than the startup code in
		 * liballocs.c. */
		if (getenv("LIBALLOCS_DELAY_STARTUP"))
		{
			sleep(10);
		}

		/* Grab the executable's end address
		 * We used to try dlsym()'ing "_end", but that doesn't work:
		 * not all executables have _end and _begin exported as dynamic syms.
		 * Also, we don't want to call dlsym since it might not be safe to malloc.
		 * Instead, get the executable's program headers directly from the auxv. */
		char dummy;
		ElfW(auxv_t) *auxv = get_auxv(environ, &dummy);
		assert(auxv);
		ElfW(auxv_t) *ph_auxv = auxv_lookup(auxv, AT_PHDR);
		ElfW(auxv_t) *phnum_auxv = auxv_lookup(auxv, AT_PHNUM);
		assert(ph_auxv);
		assert(phnum_auxv);
		uintptr_t biggest_start_seen = 0;
		uintptr_t biggest_end_seen = 0;
		uintptr_t executable_load_addr = 0; /* might get overridden by PHDR */
		for (int i = 0; i < phnum_auxv->a_un.a_val; ++i)
		{
			ElfW(Phdr) *phdr = ((ElfW(Phdr)*) ph_auxv->a_un.a_val) + i;
			if (phdr->p_type == PT_PHDR)
			{
				executable_load_addr = (char*) phdr - (char*) phdr->p_vaddr;
				break;
			}
		}
		// this is just used for detecting and filling holes, opportunistically
		uintptr_t last_seen_end_vaddr_rounded_up = (uintptr_t) -1;
		for (int i = 0; i < phnum_auxv->a_un.a_val; ++i)
		{
			ElfW(Phdr) *phdr = ((ElfW(Phdr)*) ph_auxv->a_un.a_val) + i;
			if (phdr->p_type == PT_LOAD)
			{
				/* Kernel's treatment of extra-memsz is not reliable -- i.e. the 
				 * memsz bit needn't show up in /proc/<pid>/maps -- so use the
				 * beginning. */
				uintptr_t end = ROUND_UP(executable_load_addr + 
					(uintptr_t) phdr->p_vaddr + phdr->p_memsz, PAGE_SIZE);
				if (end > biggest_end_seen)
				{
					biggest_end_seen = end;
					biggest_start_seen = executable_load_addr + 
						(uintptr_t) phdr->p_vaddr;
				}
				if (last_seen_end_vaddr_rounded_up != (uintptr_t) -1
						&& ROUND_DOWN(phdr->p_vaddr, PAGE_SIZE) != last_seen_end_vaddr_rounded_up)
				{
					/* We have a hole. Map a PROT_NONE region in the space. */
					void* hole_base = (void*)(executable_load_addr + last_seen_end_vaddr_rounded_up);
					size_t hole_size = ROUND_DOWN(phdr->p_vaddr, PAGE_SIZE)
						 - last_seen_end_vaddr_rounded_up;
					assert(hole_size > 0);
					void *ret = raw_mmap(hole_base, hole_size,
						PROT_NONE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
					assert(ret == hole_base);
				}
				last_seen_end_vaddr_rounded_up = ROUND_UP(phdr->p_vaddr + phdr->p_memsz, PAGE_SIZE);

				// write_string("Saw executable phdr end address: ");
				// write_ulong((unsigned long) end);
				// write_string("\n");

				if (!(phdr->p_flags & PF_X) &&
					(char*) executable_load_addr + phdr->p_vaddr > (char*) data_segment_start_addr)
				{
					data_segment_start_addr = (void*) (executable_load_addr + phdr->p_vaddr);
				}
			}
		}
		executable_end_addr = (void*) biggest_end_seen;
		executable_data_segment_start_addr = biggest_start_seen;
		assert(executable_end_addr != 0);
		// assert((char*) executable_end_addr < (char*) BIGGEST_SANE_EXECUTABLE_VADDR);
		// write_string("Executable highest phdr end address: ");
		// write_ulong((unsigned long) executable_end_addr);
		// write_string("\n");
		
		
		/* Do the liballocs global init now. This is important! It's 
		 * going to walk the loaded objects and load the types/allocsites
		 * objects. We have to do this before we init systrap, because
		 * systrap needs that metadata. We also have to do it before we
		 * add the missing mappings; if we do it afterwards, the mappings
		 * created when loading the metadata objects won't be seen. 
		 * PROBLEM: the dlopens that we do here will call malloc, which
		 * want to do indexing using the pageindex, which wants the
		 * bigallocs already populated. FIXME: how to avoid this? I think
		 * the answer is to do a "rough" preliminary pass over /proc/pid/maps
		 * first, then do another pass. Needs to make add_missing_cb
		 * idemopotent. OH, but that doesn't work because the malloc() may
		 * move the sbrk() arbitrarily far, and by definition we won't see it
		 * because we're not trapping sbrk() yet. We need the bigalloc lookup
		 * (in the indexing logic, or in pageindex) to have a second-attempt
		 * at getting the bigalloc after re-checking the sbrk(). */
		add_missing_mappings_from_proc(executable_end_addr);
		/* Also extend the data segment to account for the current brk. */
		set_executable_mapping_bigalloc(executable_end_addr);
		/* brk allocator init can initialize even before systrap -- we
		 * need to worry about out-of-date __curbrk manually, though. */
		__brk_allocator_init();
		/* Before we ask libsystrap to do anything, ensure the file metadata
		 * for the early libs is in place. This will skip the meta-objects,
		 * which we're not ready to do yet (it's a dlopen/mmap that we want
		 * to trap). */
		__runt_files_init();
		assert(early_lib_handles[0]);
		/* Now we're ready to take traps for subsequent mmaps and sbrk. */
		__liballocs_systrap_init();
		__brk_allocator_notify_brk(sbrk(0), __builtin_return_address(0));
		/* Now we can dlopen the meta-objects for the early libs, which librunt
		 * skipped because it couldn't catch the mmaps happening during dlopen. */
		load_meta_objects_for_early_libs();
		__liballocs_post_systrap_init(); /* does the libdlbind symbol creation */
		__liballocs_global_init(); // will add mappings; may change sbrk
		// we want to trap syscalls in "__brk"; // glibc HACK!
		// but "__brk" in glibc isn't an exportd symbol.
		// instead, we need to walk its allocations
		__systrap_brk_hack();
		/* Now we are initialized. */
		initialized = 1;
		trying_to_initialize = 0;
		__brk_allocator_init();
	}
}

void __systrap_brk_hack(void) __attribute__((visibility("hidden")));
void __systrap_brk_hack(void)
{
#ifdef GUESS_RELEVANT_SYSCALL_SITES
	// we want to trap syscalls in "__brk"; // glibc HACK!
	// but "__brk" in glibc isn't an exportd symbol.
	// instead, we need to walk its allocations
	for (struct link_map *l = find_r_debug()->r_map; l; l = l->l_next)
	{
		if ((const void *) l->l_ld != &_DYNAMIC && (intptr_t) l->l_addr > 0
			&& strlen(l->l_name) > 0)
		{
			/* This is a reasonable object that isn't us. Look up "sbrk" in its
			 * symtab. Then do the more expensive search for "__brk". */
			Elf64_Sym *found = symbol_lookup_in_object(l, "sbrk"); // HACK
			if (found)
			{
				if (&__lookup_static_allocation_by_name)
				{
					/* We want to trap syscalls in "__brk" but "__brk" in glibc 
					 * isn't an exported symbol. So consult our allocs data for 
					 * a definition named "__brk" and trap that. */
					void *addr;
					size_t len;
					_Bool success = __lookup_static_allocation_by_name(l, "__brk", &addr, &len);
					if (success)
					{
						trap_one_instruction_range((unsigned char*) addr, 
							(unsigned char*) addr + len, 0, 1);
					}
				}
			}
		}
	}
#endif
}

void copy_all_left_from_by(struct mapping_sequence *s, int from, int by)
{
	memmove(s->mappings + from - by, s->mappings + from,
		sizeof (struct mapping_entry) * (s->nused - from));
	s->nused -= by;
}

void copy_all_right_from_by(struct mapping_sequence *s, int from, int by)
{
	memmove(s->mappings + from + by, s->mappings + from,
		sizeof (struct mapping_entry) * (s->nused - from));
	s->nused += by;
}

static void check_mapping_sequence_sanity(struct mapping_sequence *cur)
{
	assert(cur->nused >= 0);
	if (cur->nused == 0) return;
	assert(cur->begin == cur->mappings[0].begin);
	assert(cur->end == cur->mappings[cur->nused - 1].end);
	for (unsigned i = 0; i < cur->nused; ++i)
	{
		assert(cur->mappings[i].begin);
		assert(cur->mappings[i].end);
		assert((unsigned char *) cur->mappings[i].end > (unsigned char *) cur->mappings[i].begin);
		if (i > 0) assert(cur->mappings[i-1].end == cur->mappings[i].begin);
	}
}

static _Bool augment_sequence(struct mapping_sequence *cur, 
	void *begin, void *end, int prot, int flags, off_t offset, const char *filename,
	void *caller)
{
	_Bool ret;
	const char *reason = NULL;
	if (!cur) { ret = 0; reason = "no sequence yet"; goto out; }
	check_mapping_sequence_sanity(cur);
#define OVERLAPS(b1, e1, b2, e2) \
    ((char*) (b1) < (char*) (e2) \
    && (char*) (e1) >= (char*) (b2))
	/* Can we extend the current mapping sequence?
	 * This is tricky because a whole mapped file (as seen by
	 * __static_file_allocator) must have a single parent mapping sequence.
	 * In the case of segments with memsz > filesz, we have to make sure
	 * that the *trailing* anonymous mapping gets lumped into the preceding 
	 * mapping sequence, not the next one. We handle this with the
	 * filename_is_consistent logic. */
	_Bool is_clean_extension = (!cur->end || cur->end == begin);
	_Bool bounds_would_remain_contiguous
		 = is_clean_extension || /* overlaps */ OVERLAPS(cur->begin, cur->end, begin, end);
	_Bool begin_addr_unchanged = (char*) begin >= (char*) cur->begin;
	_Bool not_too_many = cur->nused != MAPPING_SEQUENCE_MAX_LEN; /* FIXME: check against increase */
	if (bounds_would_remain_contiguous && begin_addr_unchanged
		&& not_too_many)
	{
		if (is_clean_extension)
		{
			_Bool filename_is_consistent = 
					(!filename && !cur->filename) // both anonymous -- continue sequence
					|| (cur->nused == 0) // can always begin afresh
					|| (prot == PROT_NONE && !filename) // anonymous guard-page regions can always be added
					|| /* can contiguous-append at most one anonymous (memsz > filesz) at the end 
						* (I had said "maybe >1 of them" -- WHY?) 
						* and provided that caller is in the same object (i.e. both ldso, say).
						* One point of this rule is to avoid swallowing anonymous mappings
						* that happen to be placed in memory following a loaded file.
						*/
						(!filename && cur->filename && !(cur->mappings[cur->nused - 1].is_anon)
						&& ((!caller && !cur->mappings[cur->nused - 1].caller) ||
							get_highest_loaded_object_below(caller)
						  == get_highest_loaded_object_below(cur->mappings[cur->nused - 1].caller)))
					// ... but if we're not beginning afresh, can't go from anonymous to with-name
					|| (filename && cur->filename && 0 == strcmp(filename, cur->filename));
			if (!filename_is_consistent) { ret = 0; reason = "inconsistent filename (1)";  goto out; }
			
			if (!cur->begin) cur->begin = begin;
			cur->end = end;
			if (!cur->filename) cur->filename = filename ? __liballocs_private_strdup(filename) : NULL;
			cur->mappings[cur->nused] = (struct mapping_entry) {
				.begin = begin,
				.end = end,
				.flags = flags,
				.prot = prot,
				.offset = offset,
				.is_anon = !filename,
				.caller = caller
			};
			++(cur->nused);
			ret = 1; goto out;
		}
		else
		{
			/* Skip to the first affected (overlapped) element in the sequence. */
			int i = 0;
			while (!(OVERLAPS(cur->mappings[i].begin, cur->mappings[i].end, begin, end))) ++i;
			int first_overlapped = i;
			
			/* Find the last affected (overlapped) element in the sequence. */
			i = cur->nused - 1;
			while (!(OVERLAPS(cur->mappings[i].begin, cur->mappings[i].end, begin, end))) --i;
			int last_overlapped = i;

			_Bool begin_overlap_is_partial = 
				cur->mappings[first_overlapped].begin != begin;
			//_Bool begin_overlap_is_partial = 
			//	!(first_overlap_covers_from_begin
			//		&& cur->mappings[first_overlapped].end == end);
			_Bool end_overlap_is_partial = 
				cur->mappings[last_overlapped].end != end;
			//_Bool end_overlap_is_partial = 
			//	!(cur->mappings[last_overlapped].begin == begin
			//		&& last_overlap_covers_to_end);
			
			/* Do the filename consistency check. This is important to ensure that
			 * mappings from unrelated objects do not get grouped together as one sequence. */
			_Bool filename_is_consistent;
			if ((!filename && !cur->filename) // both anonymous -- continue sequence
					|| (cur->nused == 0))
			{
				// can always begin afresh
				filename_is_consistent = 1;
			}
			else
			{
				/* It's never okay to involve more than one filename. */
				if (filename && cur->filename && 0 != strcmp(filename, cur->filename))
				{
					filename_is_consistent = 0;
				}
				else
				{
					/* Check that we maintain the invariant that all the anonymous
					 * mappings are at the end. */
					int maybe_mapping_preceding_overlap = 
							begin_overlap_is_partial ? first_overlapped : first_overlapped - 1;
					int maybe_mapping_following_overlap = 
							end_overlap_is_partial ? last_overlapped : last_overlapped + 1;
					if (maybe_mapping_following_overlap >= cur->nused)
					{
						maybe_mapping_following_overlap = -1;
					}
					
					/* Are we creating an anonymous-to-filename'd "rising edge"? */
					if ((maybe_mapping_preceding_overlap != -1
							&& (cur->mappings[maybe_mapping_preceding_overlap].is_anon
								&& filename))
						|| (maybe_mapping_following_overlap != -1
							&& (!filename
								&& !cur->mappings[maybe_mapping_following_overlap].is_anon))
						)
					{
						/* Edge detected -- oh dear. */
						filename_is_consistent = 0;
					}
					else filename_is_consistent = 1;
					
					/* Final check on caller */
					filename_is_consistent &= 
						(!caller || !cur->mappings[first_overlapped].caller ||
							get_highest_loaded_object_below(caller)
						  == get_highest_loaded_object_below(cur->mappings[first_overlapped].caller));
				}
			}
			if (!filename_is_consistent) { ret = 0; reason = "inconsistent filename (2)"; goto out; }

			/* If there's only one affected, *and* it's being cleanly replaced,
			 * just update it directly. */
// 			if (first_overlapped == last_overlapped &&
// 					!begin_overlap_is_partial)
// 			{
// 				cur->mappings[first_overlapped] = (struct mapping_entry) {
// 					.begin = begin,
// 					.end = end,
// 					.flags = flags,
// 					.prot = prot,
// 					.offset = offset,
// 					.is_anon = !filename,
// 					.caller = caller
// 				};
// 				ret = 1; goto out;
// 			}

			/* First, check we have room to copy right. */
			unsigned nspare = MAPPING_SEQUENCE_MAX_LEN - cur->nused;
			if (nspare < 
					(begin_overlap_is_partial ? 1 : 0)
				  + (end_overlap_is_partial ? 1 : 0))
			{
				ret = 0; reason = "no more room in sequence structure (1)"; goto out;
			}

			/* The number of obsolete mappings is the number to be
			 * completely replaced. We want it to equal 1. */
			/* Eliminate partial overlap at the beginning. */

			if (begin_overlap_is_partial)
			{
				copy_all_right_from_by(cur, first_overlapped, 1);
				if (first_overlapped != last_overlapped) ++last_overlapped;

				cur->mappings[first_overlapped].end = begin;
				cur->mappings[first_overlapped+1].begin = begin;

				/* Update our state. */
				begin_overlap_is_partial = 0;
				if (first_overlapped == last_overlapped) ++last_overlapped;
				++first_overlapped;
			}
			/* Eliminate partial overlap at the end. */
			if (end_overlap_is_partial)
			{
				copy_all_right_from_by(cur, last_overlapped, 1);
				/* last overlapped stays where it is */
				
				cur->mappings[last_overlapped + 1].begin = end;
				cur->mappings[last_overlapped].end = end;

				/* Update our state. */
				end_overlap_is_partial = 0;
			}
			#define N_OBSOLETE_MAPPINGS (last_overlapped - first_overlapped) + 1
			
			assert(N_OBSOLETE_MAPPINGS >= 1);
			
			if (N_OBSOLETE_MAPPINGS > 1)
			{
				/* Delete in-the-middle mappings that are fully overlapped. */
				unsigned n = N_OBSOLETE_MAPPINGS - 1;
				copy_all_left_from_by(cur, last_overlapped + 1, n);
				last_overlapped -= n;
			}
			
			assert(N_OBSOLETE_MAPPINGS == 1);
			assert(first_overlapped == last_overlapped);
			cur->mappings[first_overlapped] = (struct mapping_entry) {
				.begin = begin,
				.end = end,
				.flags = flags,
				.prot = prot,
				.offset = offset,
				.is_anon = !filename,
				.caller = caller
			};
			ret = 1; goto out;
			
		}
	}
	else
	{
		ret = 0;
		if (!bounds_would_remain_contiguous) reason = "discontiguous bounds";
		else if (!begin_addr_unchanged) reason = "begins before current sequence";
		else if (!not_too_many) reason = "no more room in sequence structure (2)";
		else assert(0);
		goto out;
	}
	
	abort();
out:
	if (cur) check_mapping_sequence_sanity(cur);
	if (!ret)
	{
		/* Print a warning if the old not-extendable sequence
		 * and the new mapping share a filename. It's usually
		 * a sign of something going wrong. */
		if (filename && cur->filename && 0 == strcmp(filename, cur->filename))
		{
			debug_printf(0,
				"mapping of same file could not extend preceding sequence (reason: %s); BUG?",
				reason
			);
		}
	}
	return ret;
}

_Bool __augment_mapping_sequence(struct mapping_sequence *cur,
	void *begin, void *end, int prot, int flags, off_t offset, const char *filename,
	void *caller)
{
	return augment_sequence(cur, begin, end, prot, flags, offset, filename, caller);
}

static _Bool extend_current(struct mapping_sequence *cur, struct maps_entry *ent)
{
	const char *filename;
	// if 'rest' is '/' it's static, else it's heap or thread
	switch (ent->rest[0])
	{
		case '\0': 
			filename = NULL;
			break;
		case '/':
			filename = ent->rest;
			break;
		case '[':
			filename = NULL;
			if (0 == strncmp(ent->rest, "[stack", 6))
			{
				/* FIXME: probably don't want '[stack]' hanging around as a filename,
				 * but we use it to identify this sequence later, so keep it for now. */
				filename = ent->rest;
			}
			else // it might say '[heap]'; treat it as heap
			{
				filename = NULL;
			}
			break;
		default:
			debug_printf(1, "Warning: could not classify maps entry with base %p\n,",
				(void*) ent->first);
			return 0; // keep going
	}
	
	return augment_sequence(cur, (void*) ent->first, (void*) ent->second, 
				  ((ent->r == 'r') ? PROT_READ : 0)
				| ((ent->w == 'w') ? PROT_WRITE : 0)
				| ((ent->x == 'x') ? PROT_EXEC : 0),
				(ent->p == 'p' ? MAP_PRIVATE : MAP_SHARED)
				| (!filename ? MAP_ANONYMOUS : 0),
				ent->offset,
				filename, NULL);
};

static int add_missing_cb(struct maps_entry *ent, char *linebuf, void *args_as_void)
{
	unsigned long size = ent->second - ent->first;
	struct add_missing_cb_args *args = (struct add_missing_cb_args *) args_as_void;
	struct mapping_sequence *cur = args->seq;
	
	// if this mapping looks like a memtable, we skip it
	if (size > BIGGEST_SANE_USER_ALLOC) return 0; // keep going

	if (size == 0 || (intptr_t) ent->first < 0)  return 0; // don't add kernel pages
	
	assert(pageindex);
	/* We might already have this mapping [sequence] as a bigalloc.
	 * But there's a race condition: suppose a temorary mmap (from malloc, say)
	 * exists during the first time we add_missing_maps_from_proc,
	 * and later has gone away... but *another* mapping partially covers where
	 * it used to be, or some of it.
	 *
	 * We keep on pretending we're doing a fresh mapping, and let
	 * add_mapping_sequence_bigalloc_if_absent reconcile any discrepancies
	 * with what already exists.
	 */
	void *obj = (void *)(uintptr_t) ent->first;
	void *obj_lastbyte __attribute__((unused)) = (void *)((uintptr_t) ent->second - 1);
	struct maps_entry fake_ent;

	if (0 == strncmp(ent->rest, "[heap", 5)) // it might say '[heap]'; treat it as heap
	{
		/* We will get this when we do the sbrk. Do nothing for now. */
		/* PROBLEM: Linux sometimes says '[heap]' when actually some or all
		 * of the mapping is bss from the executable. This messes us up because
		 * static_file_allocator wants there to be a mapping_entry for the
		 * highest vaddr in the file, which could be the end of bss. */
		if ((uintptr_t) obj < (uintptr_t) args->end_addr)
		{
			/* This mapping is actually partly bss. Fake up an entry
			 * that covers just the bss. */
			debug_printf(1, "Linux says [heap] but we think it's partly BSS\n");
			memcpy(&fake_ent, ent, sizeof *ent);
			fake_ent.rest[0] = '\0';
			fake_ent.second = (uintptr_t) args->end_addr;
			ent = &fake_ent;
			obj_lastbyte = args->end_addr;
		}
		else return 0;
	}

	// ... but if we do, and it's not square-bracketed and nonzero-sizes, it's a mapping
	_Bool extended = extend_current(cur, ent);
	if (!extended)
	{
		add_mapping_sequence_bigalloc_if_absent(cur);
		memset(cur, 0, sizeof (struct mapping_sequence));
		_Bool began_new = extend_current(cur, ent);
		if (!began_new) abort();
	}

	return 0; // keep going
}

void __mmap_allocator_notify_brk(void *new_curbrk)
{
	/* HMM. If we are called in a signal context sit's probably not 
	 * safe to just do the init now. But we don't start taking traps until
	 * we're initialized, so that's okay. BUT see the note in 
	 * __mmap_allocator_init... before we're initialized, we need
	 * another mechanism to probe for brk updates. */

	/* If we haven't made the bigalloc yet, sbrk needs no action.
	 * Otherwise we must update the end. */
	if (executable_mapping_bigalloc)
	{
		void *old_end = executable_mapping_bigalloc->end;
		void *new_end = ROUND_UP_PTR(new_curbrk, PAGE_SIZE);
		__adjust_bigalloc_end(executable_mapping_bigalloc,
			new_end);
		struct mapping_sequence *seq
		 = executable_mapping_bigalloc->allocator_private;
		seq->end = new_end;
		/* If we've expanded... */
		if ((uintptr_t) new_end > (uintptr_t) old_end)
		{
			void *prev_mapping_end = seq->mappings[seq->nused - 1].end;
			if (!seq->mappings[seq->nused - 1].is_anon)
			{
				/* Most likely, the program has not yet called sbrk().
				 * /proc/<pid>/maps does *not* necessarily list the break area.
				 * We have to pretend an anonymous mapping is there.
				 * FIXME: this behaviour is fine when we're called for
				 * sbrk(), but not in other cases. */
				seq->mappings[seq->nused++] = (struct mapping_entry) {
					.begin = prev_mapping_end,
					.end = new_end,
					.prot = PROT_READ | PROT_WRITE,
					.flags = 0,
					.offset = 0,
					.is_anon = 1,
				};
			}
			else seq->mappings[seq->nused - 1].end = new_end;
			check_mapping_sequence_sanity(seq);
		}
		else if ((uintptr_t) new_end < (uintptr_t) old_end)
		{
			struct mapping_sequence *seq
			 = executable_mapping_bigalloc->allocator_private;
			delete_mapping_sequence_span(seq, new_end, (uintptr_t) old_end - (uintptr_t) new_end);
			check_mapping_sequence_sanity(seq);
		}

	}
}

static liballocs_err_t get_info(void *obj, struct big_allocation *b, 
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void **out_site)
{
	/* The info is simply the top-level bigalloc for that address. */
	// Why do we support the b == NULL case? None of the other allocators do.
	// The caller should grab the bigalloc number from the pageindex if they want.
	//if (!b) b = &big_allocations[pageindex[PAGENUM(obj)]];
	//while (b && b->parent) b = b->parent;
	//if (!b) return &__liballocs_err_object_of_unknown_storage;
	assert(b);

	if (out_type) *out_type = NULL;
	if (out_base) *out_base = b->begin;
	if (out_size) *out_size = (char*) b->end - (char*) b->begin;
	if (out_site) *out_site = ((struct mapping_sequence *) b->allocator_private)->
		mappings[0].caller; // bit of a HACK: just use the first one in the seq
	
	// success
	return NULL;
}

struct allocator __mmap_allocator = {
	.name = "mmap",
	.min_alignment = PAGE_SIZE, /* should be MIN_PAGE_SIZE */
	.is_cacheable = 1,
	.get_info = get_info
	/* FIXME: meta-protocol implementation */
};

#ifndef NDEBUG
static void test_mapping_overlap(void)
{
	const struct mapping_entry ms[] = {
		{ .begin = (void*) 0xbeef10000ul, .end = (void*) 0xbeef18000ul },
		{ .begin = (void*) 0xbeef18000ul, .end = (void*) 0xbeef1c000ul },
		{ .begin = (void*) 0xbeef1c000ul, .end = (void*) 0xbeef1e000ul },
		{ .begin = (void*) 0xbeef1e000ul, .end = (void*) 0xbeef22000ul },
		{ .begin = (void*) 0xbeef22000ul, .end = (void*) 0xbeef2a000ul }
	};
#define MAKE_FRESH_MAPPING_SEQUENCE(name) \
	struct mapping_sequence name = { ms[0].begin, ms[4].end, "/test", sizeof ms / sizeof (struct mapping_entry) }; \
	memcpy(name.mappings, ms, sizeof ms); \
	bzero(name.mappings + name.nused, \
	    sizeof (struct mapping_entry) * (MAPPING_SEQUENCE_MAX_LEN - name.nused));
	
	/* case 1: precise pre-overlap on first mapping only */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms1);
	_Bool success1 = augment_sequence(&ms1, (void*) 0xbeef10000ul, (void*) 0xbeef14000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success1);
	assert(ms1.nused == 6);
	assert(ms1.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms1.mappings[0].end == (void*) 0xbeef14000ul);
	assert(ms1.mappings[0].flags == 1);
	assert(ms1.mappings[1].begin == (void*) 0xbeef14000ul);
	assert(ms1.mappings[1].end == (void*) 0xbeef18000ul);
	assert(ms1.mappings[1].flags == 0);
	assert(ms1.mappings[5].end == (void*) 0xbeef2a000ul);
	}

	/* case 2: mid-overlap on first mapping only */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms2);
	_Bool success2 = augment_sequence(&ms2, (void*) 0xbeef14000ul, (void*) 0xbeef15000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success2);
	assert(ms2.nused == 7);
	assert(ms2.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms2.mappings[0].end == (void*) 0xbeef14000ul);
	assert(ms2.mappings[0].flags == 0);
	assert(ms2.mappings[1].begin == (void*) 0xbeef14000ul);
	assert(ms2.mappings[1].end == (void*) 0xbeef15000ul);
	assert(ms2.mappings[1].flags == 1);
	assert(ms2.mappings[2].begin == (void*) 0xbeef15000ul);
	assert(ms2.mappings[2].end == (void*) 0xbeef18000ul);
	assert(ms2.mappings[2].flags == 0);
	assert(ms2.mappings[6].end == (void*) 0xbeef2a000ul);
	}

	/* case 3: precise end-overlap on first mapping only */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms3);
	_Bool success3 = augment_sequence(&ms3, (void*) 0xbeef14000ul, (void*) 0xbeef18000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success3);
	assert(ms3.nused == 6);
	assert(ms3.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms3.mappings[0].end == (void*) 0xbeef14000ul);
	assert(ms3.mappings[0].flags == 0);
	assert(ms3.mappings[1].begin == (void*) 0xbeef14000ul);
	assert(ms3.mappings[1].end == (void*) 0xbeef18000ul);
	assert(ms3.mappings[1].flags == 1);
	assert(ms3.mappings[5].end == (void*) 0xbeef2a000ul);
	}

	/* case 4: overrunning mid-overlap on first mapping spanning 0 more, no last-mapping overlap  */
	// this doesn't make sense

	/* case 5: overrunning mid-overlap on first mapping spanning 1 more, no last-mapping overlap  */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms5);
	_Bool success5 = augment_sequence(&ms5, (void*) 0xbeef14000ul, (void*) 0xbeef1c000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success5);
	assert(ms5.nused == 5);
	assert(ms5.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms5.mappings[0].end == (void*) 0xbeef14000ul);
	assert(ms5.mappings[0].flags == 0);
	assert(ms5.mappings[1].begin == (void*) 0xbeef14000ul);
	assert(ms5.mappings[1].end == (void*) 0xbeef1c000ul);
	assert(ms5.mappings[1].flags == 1);
	assert(ms5.mappings[4].end == (void*) 0xbeef2a000ul);
	}

	/* case 6: overrunning mid-overlap on first mapping spanning 2 more, no last-mapping overlap  */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms6);
	_Bool success6 = augment_sequence(&ms6, (void*) 0xbeef14000ul, (void*) 0xbeef1e000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success6);
	assert(ms6.nused == 4);
	assert(ms6.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms6.mappings[0].end == (void*) 0xbeef14000ul);
	assert(ms6.mappings[0].flags == 0);
	assert(ms6.mappings[1].begin == (void*) 0xbeef14000ul);
	assert(ms6.mappings[1].end == (void*) 0xbeef1e000ul);
	assert(ms6.mappings[1].flags == 1);
	assert(ms6.mappings[3].end == (void*) 0xbeef2a000ul);
	}

	/* case 7: overrunning mid-overlap on first mapping spanning 0 more, last-mapping pre-overlap */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms7);
	_Bool success7 = augment_sequence(&ms7, (void*) 0xbeef14000ul, (void*) 0xbeef1a000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success7);
	assert(ms7.nused == 6);
	assert(ms7.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms7.mappings[0].end == (void*) 0xbeef14000ul);
	assert(ms7.mappings[0].flags == 0);
	assert(ms7.mappings[1].begin == (void*) 0xbeef14000ul);
	assert(ms7.mappings[1].end == (void*) 0xbeef1a000ul);
	assert(ms7.mappings[1].flags == 1);
	assert(ms7.mappings[2].begin == (void*) 0xbeef1a000ul);
	assert(ms7.mappings[2].end == (void*) 0xbeef1c000ul);
	assert(ms7.mappings[2].flags == 0);
	assert(ms7.mappings[5].end == (void*) 0xbeef2a000ul);
	}

	/* case 8: overrunning mid-overlap on first mapping spanning 1 more, last-mapping pre-overlap */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms8);
	_Bool success8 = augment_sequence(&ms8, (void*) 0xbeef14000ul, (void*) 0xbeef1d000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success8);
	assert(ms8.nused == 5);
	assert(ms8.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms8.mappings[0].end == (void*) 0xbeef14000ul);
	assert(ms8.mappings[0].flags == 0);
	assert(ms8.mappings[1].begin == (void*) 0xbeef14000ul);
	assert(ms8.mappings[1].end == (void*) 0xbeef1d000ul);
	assert(ms8.mappings[1].flags == 1);
	assert(ms8.mappings[2].begin == (void*) 0xbeef1d000ul);
	assert(ms8.mappings[2].end == (void*) 0xbeef1e000ul);
	assert(ms8.mappings[2].flags == 0);
	assert(ms8.mappings[4].end == (void*) 0xbeef2a000ul);
	}

	/* case 9: overrunning mid-overlap on first mapping spanning 2 more, last-mapping pre-overlap */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms9);
	_Bool success9 = augment_sequence(&ms9, (void*) 0xbeef14000ul, (void*) 0xbeef1f000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success9);
	assert(ms9.nused == 4);
	assert(ms9.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms9.mappings[0].end == (void*) 0xbeef14000ul);
	assert(ms9.mappings[0].flags == 0);
	assert(ms9.mappings[1].begin == (void*) 0xbeef14000ul);
	assert(ms9.mappings[1].end == (void*) 0xbeef1f000ul);
	assert(ms9.mappings[1].flags == 1);
	assert(ms9.mappings[2].begin == (void*) 0xbeef1f000ul);
	assert(ms9.mappings[2].end == (void*) 0xbeef22000ul);
	assert(ms9.mappings[2].flags == 0);
	assert(ms9.mappings[3].end == (void*) 0xbeef2a000ul);
	}
	
	/* case 10: overlap spanning 1 middle mapping exactly */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms10);
	_Bool success10 = augment_sequence(&ms10, (void*) 0xbeef18000ul, (void*) 0xbeef1c000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success10);
	assert(ms10.nused == 5);
	assert(ms10.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms10.mappings[0].end == (void*) 0xbeef18000ul);
	assert(ms10.mappings[0].flags == 0);
	assert(ms10.mappings[1].begin == (void*) 0xbeef18000ul);
	assert(ms10.mappings[1].end == (void*) 0xbeef1c000ul);
	assert(ms10.mappings[1].flags == 1);
	assert(ms10.mappings[2].begin == (void*) 0xbeef1c000ul);
	assert(ms10.mappings[2].end == (void*) 0xbeef1e000ul);
	assert(ms10.mappings[2].flags == 0);
	assert(ms10.mappings[4].end == (void*) 0xbeef2a000ul);
	}

	/* case 11: overlap spanning 2 middle mappings exactly */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms11);
	_Bool success11 = augment_sequence(&ms11, (void*) 0xbeef18000ul, (void*) 0xbeef1e000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success11);
	assert(ms11.nused == 4);
	assert(ms11.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms11.mappings[0].end == (void*) 0xbeef18000ul);
	assert(ms11.mappings[0].flags == 0);
	assert(ms11.mappings[1].begin == (void*) 0xbeef18000ul);
	assert(ms11.mappings[1].end == (void*) 0xbeef1e000ul);
	assert(ms11.mappings[1].flags == 1);
	assert(ms11.mappings[2].begin == (void*) 0xbeef1e000ul);
	assert(ms11.mappings[2].end == (void*) 0xbeef22000ul);
	assert(ms11.mappings[2].flags == 0);
	assert(ms11.mappings[3].end == (void*) 0xbeef2a000ul);
	}
	
	/* case 12: precise overlap from first mapping, overrunning 1, precise end */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms12);
	_Bool success12 = augment_sequence(&ms12, (void*) 0xbeef10000ul, (void*) 0xbeef1c000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success12);
	assert(ms12.nused == 4);
	assert(ms12.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms12.mappings[0].end == (void*) 0xbeef1c000ul);
	assert(ms12.mappings[0].flags == 1);
	assert(ms12.mappings[1].begin == (void*) 0xbeef1c000ul);
	assert(ms12.mappings[1].end == (void*) 0xbeef1e000ul);
	assert(ms12.mappings[1].flags == 0);
	assert(ms12.mappings[3].end == (void*) 0xbeef2a000ul);
	}

	/* case 13: precise overlap from first mapping, overrunning 1, pre-overlapping end */
	{MAKE_FRESH_MAPPING_SEQUENCE(ms13);
	_Bool success13 = augment_sequence(&ms13, (void*) 0xbeef10000ul, (void*) 0xbeef1d000ul, 
		0x1, 0x1, 0xfeef, "/test", test_mapping_overlap);
	assert(success13);
	assert(ms13.nused == 4);
	assert(ms13.mappings[0].begin == (void*) 0xbeef10000ul);
	assert(ms13.mappings[0].end == (void*) 0xbeef1d000ul);
	assert(ms13.mappings[0].flags == 1);
	assert(ms13.mappings[1].begin == (void*) 0xbeef1d000ul);
	assert(ms13.mappings[1].end == (void*) 0xbeef1e000ul);
	assert(ms13.mappings[1].flags == 0);
	assert(ms13.mappings[3].end == (void*) 0xbeef2a000ul);
	}
}

/* HACK: to integrate this with the test/ infrastructure,
 * the 'lib-test' test loads the liballocs_test.so library with dlopen.
 * This *should* run its constructors, including this function. */
#ifdef TEST
static void run_tests(void) __attribute__((constructor));
static void run_tests(void)
{
	test_mapping_overlap();
}
#endif
#endif
