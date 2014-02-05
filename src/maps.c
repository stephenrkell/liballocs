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
#include "libcrunch_private.h"

void init_prefix_tree_from_maps(void)
{
	/* First use dl_iterate_phdr to check that all library mappings are in the tree 
	 * with a STATIC kind. Since we hook dlopen(), at least from the point where we're
	 * initialized, we should only have to do this on startup.  */
	dl_iterate_phdr(__libcrunch_add_all_mappings_cb, NULL);
	
	/* Now fill in the rest from /proc. */
	prefix_tree_add_missing_maps();
}

void prefix_tree_add_missing_maps(void)
{
	#define NUM_FIELDS 11
	unsigned long first, second;
	char r, w, x, p;
	unsigned offset;
	unsigned devmaj, devmin;
	unsigned inode;
	char rest[4096];

	char proc_buf[4096];
	int ret = snprintf(proc_buf, sizeof proc_buf, "/proc/%d/maps", getpid());
	assert(ret > 0);
	FILE *maps = fopen(proc_buf, "r");
	assert(maps);
	
	char *linebuf = NULL;
	ssize_t nread;
	while (getline(&linebuf, &nread, maps) != -1)
	{
		rest[0] = '\0';
		int fields_read = sscanf(linebuf, 
			"%lx-%lx %c%c%c%c %8x %2x:%2x %d %s\n",
			&first, &second, &r, &w, &x, &p, &offset, &devmaj, &devmin, &inode, rest);

		assert(fields_read >= (NUM_FIELDS-1)); // we might not get a "rest"
		
		// ... but if we do, and it's not square-bracketed and nonzero-sizes, it's a mapping
		if (second - first > 0 && first < STACK_BEGIN) // don't add kernel pages
		{
			// is there already a matching entry in the tree?
			void *obj = (void *)(uintptr_t) first;
			struct prefix_tree_node **match_prevptr;
			struct prefix_tree_node *match
			 = prefix_tree_deepest_match_from_root(obj, &match_prevptr);
			
			if (!match)
			{
				// if 'rest' is '/' it's static, else it's heap or thread
				switch (rest[0])
				{
					case '\0': 
						prefix_tree_add(obj, second - first, HEAP, NULL);
						break;
					case '/': 
						/* library mappings are handled in the dlopen hook, so this 
						 * must be a mapped file that is *not* part of a library. 
						 * We call it MAPPED_FILE because we don't have type info for 
						 * these, and this way we will fail faster (and report it as 
						 * "unknown storage"). */
						prefix_tree_add(obj, second - first, MAPPED_FILE, rest);
						break;
					case '[':
						if (0 == strcmp(rest, "[stack]"))
						{
							prefix_tree_add(obj, second - first, STACK, obj);
						}
						else // treat it as heap
						{
							prefix_tree_add(obj, second - first, HEAP, NULL);
						}
						break;
					default:
						debug_printf(1, "Warning: could not classify maps entry with base %p\n,", obj);
				}
			}
		}
	}
	if (linebuf) free(linebuf);
	
	fclose(maps);
}
