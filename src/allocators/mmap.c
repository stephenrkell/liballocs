#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
// #include <fcntl.h>     // problem with raw-syscalls conflict
int open(const char *, int, ...);
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include "relf.h"
#include "maps.h"
#include "liballocs_private.h"
#include "raw-syscalls.h"
#include "dlbind.h"

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

#define MAPPING_SEQUENCE_MAX_LEN 8
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
	struct mapping_sequence *copy = __wrap_dlmalloc(sizeof (struct mapping_sequence));
	/* FIXME: free this somewhere? */
	if (!copy) abort();
	memcpy(copy, seq, sizeof (struct mapping_sequence));
	
	b->meta = (struct meta_info) {
		.what = DATA_PTR,
		.un = {
			opaque_data: {
				.data_ptr = copy,
				.free_func = __wrap_dlfree
			}
		}
	};
}

/* HACK: we have a special link to the auxv allocator. */
void __auxv_allocator_notify_init_stack_mapping(void *begin, void *end);

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
	/* Linux lets us munmap *less* than a full page, with the effect of 
	 * unmapping the whole page. Sigh. */
	size_t remaining_length = ROUND_UP(length, PAGE_SIZE);
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
				struct mapping_sequence *new_seq = __wrap_dlmalloc(sizeof (struct mapping_sequence));
				struct mapping_sequence *orig_seq = b->meta.un.opaque_data.data_ptr;
				memcpy(new_seq, orig_seq, sizeof (struct mapping_sequence));
				/* From the first, delete from the hole all the way. */
				delete_mapping_sequence_span(orig_seq, addr, (char*) old_end - (char*) addr);
				/* From the second, delete from the old begin to the end of the hole. */
				delete_mapping_sequence_span(new_seq, b->begin, 
						((char*) addr + length) - (char*) b->begin);
				second_half->meta.un.opaque_data.data_ptr = new_seq;
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
	struct big_allocation *bigalloc_before = __lookup_bigalloc(old_addr,
		&__mmap_allocator, NULL);
	if (!bigalloc_before) abort();
	struct mapping_sequence *seq = bigalloc_before->meta.un.opaque_data.data_ptr;
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
		struct big_allocation *bigalloc_before = __lookup_bigalloc((char*) mapped_addr - 1, 
			&__mmap_allocator, NULL);
		if (!bigalloc_before)
		{
			struct big_allocation *overlap_begin = __lookup_bigalloc((char*) mapped_addr,
				&__mmap_allocator, NULL);
			struct big_allocation *overlap_end = __lookup_bigalloc((char*) mapped_addr + mapped_length - 1, 
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
				bigalloc_before->meta.un.opaque_data.data_ptr;
			_Bool success = augment_sequence(seq, mapped_addr, (char*) mapped_addr + mapped_length, 
				prot, flags, offset, filename, caller);
			char *requested_new_end = (char*) mapped_addr + mapped_length;
			if (success && requested_new_end > (char*) bigalloc_before->end)
			{
				/* Okay, now the bigalloc is bigger. */
				_Bool success = __liballocs_extend_bigalloc(bigalloc_before, 
					(char*) requested_new_end);
				if (!success) abort();
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

void __mmap_allocator_notify_mprotect(void *addr, size_t len, int prot)
{
	
}

static int add_missing_cb(struct maps_entry *ent, char *linebuf, void *arg);
void add_missing_mappings_from_proc(void)
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
	for_each_maps_entry(fd, get_a_line_from_maps_fd, linebuf, sizeof linebuf, &entry, add_missing_cb, &current);
	/* Finish off the last mapping. */
	if (current.nused > 0) add_mapping_sequence_bigalloc(&current);

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

// we always define a __curbrk -- it may override one in glibc, but fine
void *__curbrk;
static void *current_sbrk(void)
{
	return __curbrk;
}
void __mmap_allocator_notify_brk(void *new_curbrk);

struct big_allocation *executable_data_segment_mapping_bigalloc __attribute__((visibility("hidden")));
static void update_data_segment_end(void *new_curbrk);

_Bool __mmap_allocator_notify_unindexed_address(const void *mem)
{
	if (initialized) return 0;
	if (!executable_data_segment_mapping_bigalloc) return 0; // can't do anything
	void *old_sbrk = current_sbrk(); // what we *think* sbrk is
	void *new_sbrk = sbrk(0);
	update_data_segment_end(new_sbrk); // ... update it to what it actually is
	return ((char *) mem >= (char*) old_sbrk 
		&& (char *) mem < (char *) new_sbrk);
}

void __mmap_allocator_init(void) __attribute__((constructor(101)));
void __mmap_allocator_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		
		/* Grab the executable's end address
		 * We used to try dlsym()'ing "_end", but that doesn't work:
		 * not all executables have _end and _begin exported as dynamic syms.
		 * Also, we don't want to call dlsym since it might not be safe to malloc.
		 * Instead, get the executable's program headers directly from the auxv. */
		char dummy;
		ElfW(auxv_t) *auxv = get_auxv((const char **) environ, &dummy);
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
			}
			else if (phdr->p_type == PT_LOAD)
			{
				/* Kernel's treatment of extra-memsz is not reliable -- i.e. the 
				 * memsz bit needn't show up in /proc/<pid>/maps -- so use the
				 * beginning. */
				// FIXME: assumes executable load addr is 0
				uintptr_t end = executable_load_addr + 
					(uintptr_t) phdr->p_vaddr + phdr->p_memsz;
				if (end > biggest_end_seen)
				{
					biggest_end_seen = end;
					biggest_start_seen = executable_load_addr + 
						(uintptr_t) phdr->p_vaddr;
				}
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
		uintptr_t executable_data_segment_start_addr = biggest_start_seen;
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
		add_missing_mappings_from_proc();
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
					executable_data_segment_mapping_bigalloc = &big_allocations[i];
					break;
				}
			}
		}
		if (!executable_data_segment_mapping_bigalloc) abort();
		/* We expect the data segment's suballocator to be malloc, so pre-ordain that.
		 * NOTE that there will also be a nested allocation under it, that is the 
		 * static allocator's segment bigalloc. We don't consider the sbrk area
		 * to be a child of that; it's a sibling. FIXME: is this okay? */
		executable_data_segment_mapping_bigalloc->suballocator = &__generic_malloc_allocator;
		
		/* Also extend the data segment to account for the current brk. */
		update_data_segment_end(sbrk(0));
		__liballocs_global_init(); // will add mappings; may change sbrk
		add_missing_mappings_from_proc();

		/* Now we're ready to take traps for subsequent mmaps and sbrk. */
		__liballocs_systrap_init();
		__liballocs_post_systrap_init();

		initialized = 1;
		trying_to_initialize = 0;
	}
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

static _Bool augment_sequence(struct mapping_sequence *cur, 
	void *begin, void *end, int prot, int flags, off_t offset, const char *filename,
	void *caller)
{
	if (!cur) return 0;
#define OVERLAPS(b1, e1, b2, e2) \
    ((char*) (b1) < (char*) (e2) \
    && (char*) (e1) >= (char*) (b2))
	/* Can we extend the current mapping sequence?
	 * This is tricky because ELF segments, "allocated" by __static_allocator,
	 * must have a single parent mapping sequence.
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
					|| /* can contiguous-append at most one anonymous (memsz > filesz) at the end 
						* (I had said "maybe >1 of them" -- WHY?) 
						* and provided that caller is in the same object (i.e. both ldso, say). */ 
						(!filename && cur->filename && !(cur->mappings[cur->nused - 1].is_anon)
						&& ((!caller && !cur->mappings[cur->nused - 1].caller) ||
							get_highest_loaded_object_below(caller)
						  == get_highest_loaded_object_below(cur->mappings[cur->nused - 1].caller)))
					// ... but if we're not beginning afresh, can't go from anonymous to with-name
					|| (filename && cur->filename && 0 == strcmp(filename, cur->filename));
			if (!filename_is_consistent) return 0;
			
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
			return 1;
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
			if (!filename_is_consistent) return 0;

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
// 				return 1;
// 			}
			
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
			return 1;
			
		}
	} else return 0;
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
	
	return augment_sequence(cur, (void*) ent->first, (void*) ent->second, 
				  ((ent->r == 'r') ? PROT_READ : 0)
				| ((ent->w == 'w') ? PROT_WRITE : 0)
				| ((ent->x == 'x') ? PROT_EXEC : 0),
				(ent->p == 'p' ? MAP_PRIVATE : MAP_SHARED),
				ent->offset,
				filename, NULL);
};

static int add_missing_cb(struct maps_entry *ent, char *linebuf, void *arg)
{
	unsigned long size = ent->second - ent->first;
	struct mapping_sequence *cur = (struct mapping_sequence *) arg;
	
	// if this mapping looks like a memtable, we skip it
	if (size > BIGGEST_SANE_USER_ALLOC) return 0; // keep going

	if (size == 0 || (intptr_t) ent->first < 0)  return 0; // don't add kernel pages
	
	// is it present already?
	assert(pageindex);
	if (pageindex[PAGENUM(ent->first)]) return 0;

	/* If it looks like a stack... */
	if (0 == strncmp(ent->rest, "[stack", 6))
	{
		__auxv_allocator_notify_init_stack_mapping(
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

	return 0; // keep going
}

static void update_data_segment_end(void *new_curbrk)
{
	struct mapping_sequence *seq
	 = executable_data_segment_mapping_bigalloc->meta.un.opaque_data.data_ptr;
	char *old_end = executable_data_segment_mapping_bigalloc->end;
	
	/* We also update the metadata. */
	if ((char*) new_curbrk < (char*) old_end)
	{
		/* We're contracting. */
		__liballocs_truncate_bigalloc_at_end(executable_data_segment_mapping_bigalloc, new_curbrk);
		delete_mapping_sequence_span(seq, new_curbrk, (char*) old_end - (char*) new_curbrk);
	}
	else if ((char*) new_curbrk > (char*) old_end)
	{
		/* We're expanding. */
		__liballocs_extend_bigalloc(executable_data_segment_mapping_bigalloc, new_curbrk);
		void *prev_mapping_end = seq->mappings[seq->nused - 1].end;
		if (!seq->mappings[seq->nused - 1].is_anon)
		{
			/* Most likely, the program has not yet called sbrk().
			 * /proc/<pid>/maps does *not* necessarily list the break area.
			 * We have to pretend an anonymous mapping is there. */
			seq->mappings[seq->nused++] = (struct mapping_entry) {
				.begin = prev_mapping_end,
				.end = ROUND_UP_PTR(new_curbrk, PAGE_SIZE), 
				.prot = PROT_READ | PROT_WRITE,
				.flags = 0,
				.offset = 0,
				.is_anon = 1,
			};
		}
		else seq->mappings[seq->nused - 1].end = new_curbrk;
	}
}

void __mmap_allocator_notify_brk(void *new_curbrk)
{
	if (!initialized)
	{
		/* HMM. This is called in a signal context so it's probably not 
		 * safe to just do the init now. But we don't start taking traps until
		 * we're initialized, so that's okay. BUT see the note in 
		 * __mmap_allocator_init... before we're initialized, we need
		 * another mechanism to probe for brk updates. */
		return;
	}
	update_data_segment_end(new_curbrk);
}

static liballocs_err_t get_info(void *obj, struct big_allocation *maybe_bigalloc, 
	struct uniqtype **out_type, void **out_base, 
	unsigned long *out_size, const void **out_site)
{
	/* The info is simply the top-level bigalloc for that address. */
	struct big_allocation *b = maybe_bigalloc;
	if (!b) b = &big_allocations[pageindex[PAGENUM(obj)]];
	while (b && b->parent) b = b->parent;
	if (!b) return &__liballocs_err_object_of_unknown_storage;
	
	if (out_type) *out_type = NULL;
	if (out_base) *out_base = b->begin;
	if (out_size) *out_size = (char*) b->end - (char*) b->begin;
	if (out_site) *out_site = ((struct mapping_sequence *) b->meta.un.opaque_data.data_ptr)->
		mappings[0].caller; // bit of a HACK: just use the first one in the seq
	
	// success
	return NULL;
}

struct allocator __mmap_allocator = {
	.name = "mmap",
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
static void run_tests(void) __attribute__((constructor));
static void run_tests(void)
{
	test_mapping_overlap();
}
#endif
