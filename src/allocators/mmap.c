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
#include "relf.h"
#include "maps.h"
#include "liballocs_private.h"

/* We talk about "allocators" but in the case of retrofitted 
 * allocators, they actually come in up to three parts:
 * 
 * - the actual implementation;
 * - the index (separate);
 * - the instrumentation that keeps the index in sync.
 * 
 * By convention, each of our allocators also exposes "notify_*"
 * operations that the instrumentation uses to talk to the index. */

struct allocator __mmap_allocator = {
	.name = "mmap",
	.is_cacheable = 1
	/* FIXME: meta-protocol implementation */
};

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
	int ret = snprintf(proc_path, sizeof proc_path, "/proc/%d/fd/%d", getpid(), fd);
	assert(ret > 0);
	ret = readlink(proc_path, out_buf, sizeof out_buf);
	assert(ret != -1);
	out_buf[ret] = '\0';
	
	return out_buf;
}

#define MAPPING_SEQUENCE_MAX_LEN 8
struct mapping_entry
{
	void *begin;
	void *end;
	int prot;
	int flags;
	off_t offset;
	_Bool is_anon;
	void *caller;
};
struct mapping_sequence 
{
	void *begin;
	void *end;
	const char *filename;
	unsigned nused;
	struct mapping_entry mappings[MAPPING_SEQUENCE_MAX_LEN];
};

/* How are we supposed to allocate the mapping sequence metadata? */

static struct big_allocation *add_bigalloc(void *begin, size_t size)
{
	struct big_allocation *b = __liballocs_new_bigalloc(
		begin,
		size,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: {
					.data_ptr = NULL, // placeholder
					.free_func = NULL
				}
			}
		},
		NULL,
		&__mmap_allocator
	);
	if (!b) abort();
	return b;
}

static void add_mapping_sequence_bigalloc(struct mapping_sequence *seq)
{
	struct big_allocation *b = add_bigalloc(seq->begin, (char*) seq->end - (char*) seq->begin);
	if (!b) abort();
	
	/* Note that this will use early_malloc if we would otherwise be reentrant. */
	struct mapping_sequence *copy = malloc(sizeof (struct mapping_sequence));
	if (!copy) abort();
	memcpy(copy, seq, sizeof (struct mapping_sequence));
	
	b->meta = (struct meta_info) {
		.what = DATA_PTR,
		.un = {
			opaque_data: {
				.data_ptr = copy,
				.free_func = free
			}
		}
	};
}

/* HACK: we have a special link to the stack allocator. */
void __stack_allocator_notify_init_stack_mapping(void *begin, void *end);

static void delete_mapping_sequence_span(struct mapping_sequence *seq,
	void *addr, size_t length)
{
	int new_indices[MAPPING_SEQUENCE_MAX_LEN];
	for (int i = 0; i < MAPPING_SEQUENCE_MAX_LEN; ++i)
	{
		if ((char*) seq->mappings[i].begin <= (char*) addr 
				&&  (char*) addr < (char*) seq->mappings[i].end)
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
				seq->mappings[i].begin = (char*) seq->mappings[i].begin + left_at_beginning;
				seq->mappings[i].end = (char*) seq->mappings[i].end - left_at_end;
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
	if ((char*) seq->end >= (char*) addr
			&& (char*) seq->end < (char*) addr + length)
	{
		seq->end = addr;
	}
}

static void do_munmap(void *addr, size_t length, void *caller)
{
	char *cur = (char*) addr;
	size_t remaining_length = length;
	while (cur < (char*) addr + length)
	{
		/* We're always working at level 0 */
		struct big_allocation *b = __lookup_bigalloc(cur, &__mmap_allocator, NULL);
		if (!b)
		{
			/* Okay, no mapping present. Zoom to the next bigalloc. */
			cur += PAGE_SIZE;
			remaining_length -= PAGE_SIZE;
			continue; // FIXME: use wide-character string funcs instead
		}
		struct mapping_sequence *seq = b->meta.un.opaque_data.data_ptr;
		
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
				struct mapping_sequence *new_seq = malloc(sizeof (struct mapping_sequence));
				struct mapping_sequence *orig_seq = b->meta.un.opaque_data.data_ptr;
				memcpy(new_seq, orig_seq, sizeof (struct mapping_sequence));
				/* From the first, delete from the hole all the way. */
				delete_mapping_sequence_span(orig_seq, addr, (char*) old_end - (char*) addr);
				/* From the second, delete from the old begin to the end of the hole. */
				delete_mapping_sequence_span(new_seq, b->begin, 
						((char*) addr + length) - (char*) b->begin);

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

static struct mapping_entry *find_entry(void *addr, struct mapping_sequence *seq)
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
static _Bool extend_sequence(struct mapping_sequence *cur, 
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
	struct big_allocation *bigalloc_before = __lookup_bigalloc(old_addr,
		&__mmap_allocator, NULL);
	if (!bigalloc_before) abort();
	struct mapping_sequence *seq = bigalloc_before->meta.un.opaque_data.data_ptr;
	struct mapping_entry *maybe_ent = find_entry(old_addr, seq);
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
		if (saw_overlap && (flags & MAP_FIXED))
		{
			/* Okay, we behave as if we'd unmapped the overlapped area first. */
			do_munmap(mapped_addr, mapped_length, caller);
		}
		else if (saw_overlap) abort();
		
		/* Do we abut any existing mapping? Just do the 'before' case. */
		struct big_allocation *bigalloc_before = __lookup_bigalloc((char*) mapped_addr - 1, 
			&__mmap_allocator, NULL);
		if (bigalloc_before)
		{
			/* See if we can extend it. */
			struct mapping_sequence *seq = (struct mapping_sequence *) 
				bigalloc_before->meta.un.opaque_data.data_ptr;
			_Bool extended = extend_sequence(seq, mapped_addr, (char*) mapped_addr + mapped_length, 
				prot, flags, offset, filename, caller);
			if (extended)
			{
				/* Okay, now the bigalloc is bigger. */
				_Bool success = __liballocs_extend_bigalloc(bigalloc_before, 
					(char*) mapped_addr + mapped_length);
				if (!success) abort();
				return;
			}
		}

		/* If we got here, we have to create a new bigalloc. */
		struct mapping_sequence new_seq;
		memset(&new_seq, 0, sizeof new_seq);
		/* "Extend" the empty sequence. */
		_Bool success = extend_sequence(&new_seq, mapped_addr, (char*) mapped_addr + mapped_length, 
				prot, flags, offset, filename, caller);
		if (!success) abort();
		if (!__private_realloc_active && !__private_memalign_active && !__private_posix_memalign_active
				&& !__private_calloc_active && !__private_malloc_active)
		{
			add_mapping_sequence_bigalloc(&new_seq);
		}
		else /* HMM */
		{
			add_bigalloc(mapped_addr, mapped_length);
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

static int add_missing_cb(struct proc_entry *ent, char *linebuf, size_t bufsz, void *arg);
void add_missing_mappings_from_proc(void)
{
	struct proc_entry entry;

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
	for_each_maps_entry(fd, linebuf, sizeof linebuf, &entry, add_missing_cb, &current);
	/* Finish off the last mapping. */
	if (current.nused > 0) add_mapping_sequence_bigalloc(&current);

	close(fd);
}
static _Bool initialized;
static _Bool trying_to_initialize;

void __mmap_allocator_init(void) __attribute__((constructor(101)));
void __mmap_allocator_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		add_missing_mappings_from_proc();
		/* Now we're ready to take traps for subsequent mmaps. */
		__liballocs_systrap_init();
		initialized = 1;
		trying_to_initialize = 0;
	}
}

static _Bool extend_sequence(struct mapping_sequence *cur, 
	void *begin, void *end, int prot, int flags, off_t offset, const char *filename,
	void *caller)
{
	if (!cur) return 0;
	/* Can we extend the current mapping sequence?
	 * This is tricky because ELF segments, "allocated" by __static_allocator,
	 * must have a single parent mapping sequence.
	 * In the case of segments with memsz > filesz, we have to make sure
	 * that the *trailing* anonymous mapping gets lumped into the preceding 
	 * mapping sequence, not the next one. We handle this with the
	 * filename_is_consistent logic. */
	_Bool is_contiguous = (!cur->end || cur->end == begin);
	_Bool filename_is_consistent = 
			(!filename && !cur->filename) // both anonymous -- continue sequence
			|| (cur->nused == 0) // can always begin afresh
			|| /* can append at most one anonymous (memsz > filesz) at the end 
			    * (I had said "maybe >1 of them" -- WHY?) 
			    * and provided that caller is in the same object (i.e. both ldso, say). */ 
			   (!filename && cur->filename && !(cur->mappings[cur->nused - 1].is_anon)
			    && ((!caller && !cur->mappings[cur->nused - 1].caller) ||
					get_highest_loaded_object_below(caller)
			      == get_highest_loaded_object_below(cur->mappings[cur->nused - 1].caller)))
			// ... but if we're not beginning afresh, can't go from anonymous to with-name
			|| (filename && cur->filename && 0 == strcmp(filename, cur->filename));
	_Bool not_too_many = cur->nused != MAPPING_SEQUENCE_MAX_LEN;
	if (is_contiguous && filename_is_consistent && not_too_many)
	{
		if (!cur->begin) cur->begin = begin;
		cur->end = end;
		if (!cur->filename) cur->filename = filename ? private_strdup(filename) : NULL;
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
		return 1;
	} else return 0;
	
}

static _Bool extend_current(struct mapping_sequence *cur, struct proc_entry *ent)
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
				/* We should have caught this earlier in add_missing_cb. */
				abort();
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
	
	return extend_sequence(cur, (void*) ent->first, (void*) ent->second, 
				  ((ent->r == 'r') ? PROT_READ : 0)
				| ((ent->w == 'w') ? PROT_WRITE : 0)
				| ((ent->x == 'x') ? PROT_EXEC : 0),
				(ent->p == 'p' ? MAP_PRIVATE : MAP_SHARED),
				ent->offset,
				filename, NULL);
};

static int add_missing_cb(struct proc_entry *ent, char *linebuf, size_t bufsz, void *arg)
{
	unsigned long size = ent->second - ent->first;
	struct mapping_sequence *cur = (struct mapping_sequence *) arg;
	
	// if this mapping looks like a memtable, we skip it
	if (size > BIGGEST_SANE_USER_ALLOC) return 0; // keep going

	/* If it looks like a stack... */
	if (0 == strncmp(ent->rest, "[stack", 6))
	{
		__stack_allocator_notify_init_stack_mapping(
			(void*) ent->first, (void*) ent->second
		);
		return 0;
	}
	else if (0 == strncmp(ent->rest, "[heap", 5)) // it might say '[heap]'; treat it as heap
	{
		/* We will get this when we do the sbrk. Do nothing for now. */
		return 0;
	}

	// ... but if we do, and it's not square-bracketed and nonzero-sizes, it's a mapping
	if (size > 0 && (intptr_t) ent->first >= 0) // don't add kernel pages
	{
		void *obj = (void *)(uintptr_t) ent->first;
		void *obj_lastbyte __attribute__((unused)) = (void *)((uintptr_t) ent->second - 1);
		
		_Bool extended = extend_current(cur, ent);
		if (!extended)
		{
			add_mapping_sequence_bigalloc(cur);
			memset(cur, 0, sizeof (struct mapping_sequence));
			_Bool began_new = extend_current(cur, ent);
			if (!began_new) abort();
		}
	} // end if size > 0

	return 0; // keep going
}
