/* What we don't (yet) trap: 
 * 
 *  fork(), vfork(), clone()     -- FIXME: do we care about the fork-without-exec case?
 *
 *  dlopen(), dlclose()  -- hoping that mmap is enough
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "libcrunch_private.h"

static _Bool done_init;
void __libcrunch_preload_init(void) /*__attribute__((constructor(102)))*/;
// NOTE: runs *after* the constructor in libcrunch.c
void __libcrunch_preload_init(void)
{
	//assert(!done_init);
	
	if (!done_init) init_prefix_tree_from_maps();
	
	done_init = 1;
}

static const char *filename_for_fd(int fd)
{
	/* We read from /proc into a thread-local buffer. */
	static char __thread out_buf[8192];
	
	static char __thread proc_path[4096];
	int ret = snprintf(proc_path, sizeof proc_path, "/proc/%d/fd/%d", getpid(), fd);
	assert(ret > 0);
	ret = readlink(proc_path, out_buf, sizeof out_buf);
	assert(ret != -1);
	
	return out_buf;
}

/* NOTE that our wrappers are all init-on-use. This is because 
 * we might get called very early, and even if we're not trying to
 * intercept the early calls, we still need to be able to delegate. 
 * For that, we need our underyling function pointers. */

void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
	// HACK: let through the memtable mmaps and other things that 
	// run before our constructor

	static void *(*orig_mmap)(void *, size_t, int, int, int, off_t);
	if (!orig_mmap)
	{
		orig_mmap = dlsym(RTLD_NEXT, "mmap");
		assert(orig_mmap);
	}
	
	if (!done_init) return orig_mmap(addr, length, prot, flags, fd, offset);
	else
	{
		void *ret = orig_mmap(addr, length, prot, flags, fd, offset);
		if (ret != MAP_FAILED)
		{
			/* Add to the prefix tree */
			prefix_tree_add(ret, length, filename_for_fd(fd));
		}
		return ret;
	}
}

int munmap(void *addr, size_t length)
{
	static int (*orig_munmap)(void *, size_t);
	if (!orig_munmap)
	{
		orig_munmap = dlsym(RTLD_NEXT, "munmap");
		assert(orig_munmap);
	}
	
	if (!done_init) return orig_munmap(addr, length);
	else
	{
		int ret = orig_munmap(addr, length);
		if (ret == 0)
		{
			prefix_tree_del(addr, length);
		}
		return ret;
	}
}

static int add_all_mappings_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	const char *filename = (const char *) data;
	if (0 == strcmp(filename, info->dlpi_name))
	{
		// this is the file we care about, so iterate over its phdrs
		for (int i = 0; i < info->dlpi_phnum; ++i)
		{
			// if this phdr's a LOAD and matches our filename, 
			if (info->dlpi_phdr[i].p_type == PT_LOAD)
			{
				prefix_tree_add((unsigned char *) info->dlpi_addr + info->dlpi_phdr[i].p_vaddr, 
					info->dlpi_phdr[i].p_memsz, filename);
			}
		}
	
		// can stop now
		return 1;
	}
	else 
	// keep going
	return 0;
	
}

void *dlopen(const char *filename, int flag)
{
	static void *(*orig_dlopen)(const char *, int);
	if (!orig_dlopen)
	{
		orig_dlopen = dlsym(RTLD_NEXT, "dlopen");
		assert(orig_dlopen);
	}
	
	if (!done_init) return orig_dlopen(filename, flag);
	else
	{
		void *ret = orig_dlopen(filename, flag);
		if (ret != NULL)
		{
			/* Note that in general we will get one mapping for every 
			 * LOAD phdr. So we use dl_iterate_phdr. */
			int dlpi_ret = dl_iterate_phdr(add_all_mappings_cb, 
				((struct link_map *) ret)->l_name);
			assert(dlpi_ret != 0);
		}
		return ret;
	}
}

#define MAX_MAPPINGS 16
struct mapping
{
	void *base;
	size_t size;
};
struct mapping_set
{
	const char *filename;
	void *handle;
	int nmappings;
	struct mapping mappings[MAX_MAPPINGS];
};

static int gather_mappings_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct mapping_set *mappings = (struct mapping_set *) data;
	const char *filename = mappings->filename;
	if (0 == strcmp(filename, info->dlpi_name))
	{
		// this is the file we care about, so iterate over its phdrs
		for (int i = 0; i < info->dlpi_phnum; ++i)
		{
			// if this phdr's a LOAD and matches our filename, 
			if (info->dlpi_phdr[i].p_type == PT_LOAD)
			{
				assert(mappings->nmappings < MAX_MAPPINGS);
				mappings->mappings[mappings->nmappings++] = (struct mapping) {
					(unsigned char *) ((struct link_map *) mappings->handle)->l_addr + info->dlpi_phdr[i].p_vaddr, 
					info->dlpi_phdr[i].p_memsz, 
				};
			}
		}
	
		// can stop now
		return 1;
	} // else keep going
	else return 0;
}

int dlclose(void *handle)
{
	static int (*orig_dlclose)(void *);
	static void *(*orig_dlopen)(const char *, int);
	if(!orig_dlclose)
	{
		orig_dlclose = dlsym(RTLD_NEXT, "dlclose");
		orig_dlopen = dlsym(RTLD_NEXT, "dlopen");
		assert(orig_dlclose);
	}
	
	if (!done_init) return orig_dlclose(handle);
	else
	{
		char *copied_filename = strdup(((struct link_map *) handle)->l_name);
		assert(copied_filename != NULL);
		
		/* Use dl_iterate_phdr to gather the mappings that we will 
		 * remove from the tree *if* the dlclose() actually unloads
		 * the library. */
		struct mapping_set mappings;
		mappings.filename = copied_filename;
		mappings.handle = handle;
		mappings.nmappings = 0;
		int dlpi_ret = dl_iterate_phdr(gather_mappings_cb, &mappings);
		assert(dlpi_ret != 0);
		
		int ret = orig_dlclose(handle);
		/* NOTE that a successful dlclose doesn't necessarily unload 
		 * the library! To see whether it's really unloaded, we use 
		 * dlopen *again* with RTLD_NOLOAD. */
		if (ret == 0)
		{
			// was it really unloaded?
			void *h = orig_dlopen(copied_filename, RTLD_NOLOAD);
			if (h == NULL)
			{
				// yes, it was unloaded
				for (int i = 0; i < mappings.nmappings; ++i)
				{
					prefix_tree_del(mappings.mappings[i].base, 
						mappings.mappings[i].size);
				}
			}
			else 
			{
				// it wasn't unloaded, so we do nothing
			}
		}
	
	// out:
		free(copied_filename);
		return ret;
	}
}
