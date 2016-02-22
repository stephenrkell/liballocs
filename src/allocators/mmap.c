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

/* Since all indexed big allocations span some number of pages, 
 * we record the memory-mapping properties of those pages. */
typedef struct mapping_flags
{
	int prot;
	int flags;
} mapping_flags_t;
_Bool mapping_flags_equal(mapping_flags_t f1, mapping_flags_t f2);

static const char *filename_for_fd(int fd)
{
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
	mapping_flags_t flags;
	_Bool is_anon;
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

static void add_mapping_sequence(struct mapping_sequence *seq)
{
	/* Note that this will use early_malloc if we would otherwise be reentrant. */
	struct mapping_sequence *copy = malloc(sizeof (struct mapping_sequence));
	if (!copy) abort();
	memcpy(copy, seq, sizeof (struct mapping_sequence));
	const struct big_allocation *b = __liballocs_new_bigalloc(
		seq->begin,
		(char*) seq->end - (char*) seq->begin,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: { 
					.data_ptr = copy,
					.free_func = free
				}
			}
		},
		NULL,
		&__mmap_allocator
	);
	if (!b) abort();
}

/* HACK: we have a special link to the stack allocator. */
void __stack_allocator_notify_init_stack_mapping(void *begin, void *end);

void __mmap_allocator_notify_munmap(void *addr, size_t length)
{
	
}
void __mmap_allocator_notify_mremap(void *ret, void *old_addr, size_t old_size, size_t new_size, int flags, void *new_address)
{
	
}

void __mmap_allocator_notify_mmap(void *ret, void *requested_addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
	/*mapping_flags_t f = { .kind = (fd == -1) ? HEAP : MAPPED_FILE, 
		.r = (flags & PROT_READ), 
		.w = (flags & PROT_WRITE),
		.x = (flags & PROT_EXEC) 
	};*/
	
	/* Do we abut any existing mapping? */
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
	if (current.nused > 0) add_mapping_sequence(&current);

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
		initialized = 1;
		trying_to_initialize = 0;
	}
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
		case '[':
			filename = NULL;
			if (0 == strncmp(ent->rest, "[stack", 6))
			{
				__stack_allocator_notify_init_stack_mapping((void*) ent->first, (void*) ent->second);
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
	
	/* can we extend the current? */
	if ((!cur->end || cur->end == (void*) ent->first)
			&& (!cur->filename || (0 == strcmp(filename, cur->filename)))
			&& cur->nused != MAPPING_SEQUENCE_MAX_LEN)
	{
		if (!cur->begin) cur->begin = (void*) ent->first;
		cur->end = (void*) ent->second;
		if (!cur->filename) cur->filename = strdup(filename);
		cur->mappings[cur->nused] = (struct mapping_entry) {
			.begin = (void*) ent->first,
			.end = (void*) ent->second,
			.flags = (mapping_flags_t) { 
				.prot = (ent->r == 'r') ? PROT_READ : 0
				                | (ent->w == 'w') ? PROT_WRITE : 0
				                | (ent->x == 'x') ? PROT_EXEC : 0,
				.flags = (ent->p == 'p' ? MAP_PRIVATE : MAP_SHARED)
			},
			.is_anon = !filename
		};
		++(cur->nused);
		return 1;
	} else return 0;
};

static int add_missing_cb(struct proc_entry *ent, char *linebuf, size_t bufsz, void *arg)
{
	unsigned long size = ent->second - ent->first;
	struct mapping_sequence *cur = (struct mapping_sequence *) arg;
	
	// if this mapping looks like a memtable, we skip it
	if (size > BIGGEST_BIGALLOC) return 0; // keep going

	// ... but if we do, and it's not square-bracketed and nonzero-sizes, it's a mapping
	if (size > 0 && (intptr_t) ent->first >= 0) // don't add kernel pages
	{
		void *obj = (void *)(uintptr_t) ent->first;
		void *obj_lastbyte __attribute__((unused)) = (void *)((uintptr_t) ent->second - 1);
		
		_Bool extended = extend_current(cur, ent);
		if (!extended)
		{
			add_mapping_sequence(cur);
			memset(cur, 0, sizeof (struct mapping_sequence));
			_Bool began_new = extend_current(cur, ent);
			if (!began_new) abort();
		}
	} // end if size > 0

	return 0; // keep going
}
