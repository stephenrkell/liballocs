#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include "liballocs_private.h"

_Bool initialized_maps __attribute__((visibility("hidden")));
// static _Bool trying_to_initialize;

void __liballocs_init_l0(void)
{
	if (!initialized_maps /* && !trying_to_initialize */)
	{
		// trying_to_initialize = 1;
		/* First use dl_iterate_phdr to check that all library mappings are in the tree 
		 * with a STATIC kind. Since we hook dlopen(), at least from the point where we're
		 * initialized, we should only have to do this on startup.  */
		dl_iterate_phdr(__liballocs_add_all_mappings_cb, NULL);

		/* Now fill in the rest from /proc. */
		__liballocs_add_missing_maps();
		initialized_maps = 1;
		// trying_to_initialize = 0;
	}
}

void __liballocs_add_missing_maps(void)
{
	#define NUM_FIELDS 11
	unsigned long first, second;
	char r, w, x, p;
	unsigned offset;
	unsigned devmaj, devmin;
	unsigned inode;
	char rest[4096];

	char proc_buf[4096];
	int ret;
	ret = snprintf(proc_buf, sizeof proc_buf, "/proc/%d/maps", getpid());
	assert(ret > 0);
	FILE *maps = fopen(proc_buf, "r");
	assert(maps);

	struct link_map *executable_handle = dlopen(NULL, RTLD_NOW|RTLD_NOLOAD);
	assert(executable_handle);
	
	char *linebuf = NULL;
	ssize_t nread;
	while (getline(&linebuf, &nread, maps) != -1)
	{
		rest[0] = '\0';
		int fields_read = sscanf(linebuf, 
			"%lx-%lx %c%c%c%c %8x %2x:%2x %d %4095[\x01-\x09\x0b-\xff]\n",
			&first, &second, &r, &w, &x, &p, &offset, &devmaj, &devmin, &inode, rest);

		assert(fields_read >= (NUM_FIELDS-1)); // we might not get a "rest"
		unsigned long size = second - first;
		
		// if this mapping looks like a memtable, we skip it
		if (size > BIGGEST_MAPPING) continue;
		
		// ... but if we do, and it's not square-bracketed and nonzero-sizes, it's a mapping
		if (size > 0 && first < STACK_BEGIN) // don't add kernel pages
		{
			void *obj = (void *)(uintptr_t) first;
			void *obj_lastbyte = (void *)((uintptr_t) second - 1);
			
			enum object_memory_kind kind;
			void *data_ptr;
			// if 'rest' is '/' it's static, else it's heap or thread
			switch (rest[0])
			{
				case '\0': 
					kind = HEAP;
					data_ptr = NULL;
					break;
				case '/': 
					/* library mappings are handled in the dlopen hook, so this 
					 * is normally be a mapped file that is *not* part of a library. 
					 * We call these MAPPED_FILE because we don't have type info for 
					 * them, and this way we will fail faster (and report it as 
					 * "unknown storage").
					 * ...
					 * BUT when we're adding missing maps at start-up, we don't know
					 * if we're looking at a bona fide mapped file or a library/
					 * executable. So we have to go with what dlopen says.
					 *
					 * Further wart: in the case of the executable name, we can't
					 * dlopen() that. Even if we dlopen(NULL), its l_name is likely
					 * to be "". So we have to use /proc/getpid()/exe (above).  */
					assert(exe_fullname[0] != '\0');
					if (0 == strcmp(exe_fullname, rest))
					{
						kind = STATIC;
						data_ptr = exe_fullname;
					} 
					else
					{
						void *handle = dlopen(rest, RTLD_NOW|RTLD_NOLOAD);
						if (handle)
						{
							kind = STATIC; // FIXME FIXME FIXME FIXME FIXME
							data_ptr = strdup(realpath_quick(((struct link_map *) handle)->l_name));
						}
						else
						{
							kind = MAPPED_FILE;
							/* How can we get the filename with static storage duration? 
							 * Does it even exist? I don't want to have to strdup() / free() 
							 * these things. */
							data_ptr = strdup(rest); // FIXME FIXME FIXME FIXME FIXME
						}
					}
					break;
				case '[':
					if (0 == strcmp(rest, "[stack]"))
					{
						kind = STACK;
						data_ptr = (void*) second;
						// NOTE that for stacks, the "obj" is the upper bound
					}
					else // treat it as heap
					{
						kind = HEAP;
						data_ptr = NULL;
					}
					break;
				default:
					debug_printf(1, "Warning: could not classify maps entry with base %p\n,", obj);
					continue;
			}
			
			// is there already a matching entry in the tree?
			/* Get a list
			 * of *all* intervening mappings, then remove any that "conflict"
			 * i.e. are obviously obsolete (so we won't lose any important
			 * state by throwing them away, cf. heap mapping extensions 
			 * where we really want to keep what we know). */
			#define MAX_OVERLAPPING 32
			struct prefix_tree_node *overlapping[MAX_OVERLAPPING];
			// struct prefix_tree_node **match_prevptr;
			//match_first
			// = prefix_tree_deepest_match_from_root(obj, &match_prevptr);
			//struct prefix_tree_node *match_second
			// = prefix_tree_deepest_match_from_root(obj_lastbyte, &match_prevptr);
			size_t n_overlapping = prefix_tree_get_overlapping_mappings(
					&overlapping[0], MAX_OVERLAPPING, obj, (char*) obj + size);
			assert(n_overlapping < MAX_OVERLAPPING); // '<=' would mean we might have run out of space
			
			// if we have nothing overlapping, we should definitely add it....
			_Bool need_to_add = (n_overlapping == 0);
					
			/* Else some other number of overlapping mappings exists. */
			for (unsigned i = 0; i < n_overlapping; ++i)
			{
				/* Handle the common case where the mapping we saw is already there
				 * with the right kind and, where appropriate, filename. 
				 * Note that the mappings's dimensions needn't be the same, because we merge
				 * adjacent entries, etc.. */
				if ((overlapping[i]->kind == kind
						/* match STATIC and MAPPED_FILE interchangeably, because 
						 * we can't always tell the difference */
						|| (overlapping[i]->kind == STATIC && kind == MAPPED_FILE
							|| overlapping[i]->kind == MAPPED_FILE && kind == STATIC
						)
					)
					&& (overlapping[i]->info.what != DATA_PTR 
						|| // we do have a data ptr
							node_info_has_data_ptr_equal_to(kind, &overlapping[i]->info, data_ptr))) continue;
				
				need_to_add = 1;
				
				// if we got here, is this a different mapped file? it's clearly not mapped there any more
				if (overlapping[i]->kind == STATIC || overlapping[i]->kind == MAPPED_FILE)
				{
					assert(overlapping[i]->info.what == DATA_PTR);
					const char *existing_data_ptr = overlapping[i]->info.un.data_ptr;
					if ((data_ptr != NULL && existing_data_ptr == NULL)
							|| (data_ptr == NULL && existing_data_ptr != NULL)
							|| (data_ptr != NULL && existing_data_ptr != NULL && 
							0 != strcmp(existing_data_ptr, data_ptr)))
					{
						debug_printf(2, "a static or mapped-file mapping, kind %d, data_ptr \"%s\", overlapping %p-%p "
								"seems to have gone away: now covered by kind %d, data_ptr \"%s\"\n",
							overlapping[i]->kind, (const char *) existing_data_ptr, 
							obj, (char*) obj + size, 
							kind, (const char *) data_ptr);
						prefix_tree_del_node(overlapping[i]);
						continue;
					}
					
					/* If we got here, it means we have a static mapping which compared 
					 * equal in content, but might not have the same dimensions. Anyway, 
					 * when we try to add this it will still cause a problem. */
					debug_printf(2, "skipping static or mapped-file mapping (\"%s\") "
						"overlapping %p-%p and apparently already present\n",
						(const char *) overlapping[i]->info.un.data_ptr, obj, (char*) obj + size);
					goto continue_loop;
				}
			}
			
			#undef MAX_OVERLAPPING
			
			/* We always add heap and stack because they're sloppier, and because 
			 * our checks above didn't account for changes in size. */
			if (need_to_add || kind == HEAP || kind == STACK)
			{
				if (kind == HEAP) prefix_tree_add_sloppy(obj, second - first, kind, data_ptr);
				else prefix_tree_add(obj, second - first, kind, data_ptr);
			}
		} // end if size > 0
continue_loop:
		0;
	} // end while
	if (linebuf) free(linebuf);
	
	fclose(maps);
}
