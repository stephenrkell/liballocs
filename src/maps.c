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
static _Bool trying_to_initialize;

void __liballocs_init_l0(void)
{
	if (!initialized_maps && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		/* First use dl_iterate_phdr to check that all library mappings are in the tree 
		 * with a STATIC kind. Since we hook dlopen(), at least from the point where we're
		 * initialized, we should only have to do this on startup.  */
		dl_iterate_phdr(__liballocs_add_all_mappings_cb, NULL);

		/* Now fill in the rest from /proc. */
		__liballocs_add_missing_maps();
		initialized_maps = 1;
		trying_to_initialize = 0;
	}
}

__attribute__((visibility("hidden")))
int __liballocs_add_all_mappings_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	static _Bool running;
	/* HACK: if we have an instance already running, quit early. */
	if (running) return 1;
	running = 1;
	const char *filename = (const char *) data;
	if (filename == NULL || 0 == strcmp(filename, info->dlpi_name))
	{
		// this is the file we care about, so iterate over its phdrs
		for (int i = 0; i < info->dlpi_phnum; ++i)
		{
			// if this phdr's a LOAD
			if (info->dlpi_phdr[i].p_type == PT_LOAD)
			{
				// adjust start/end to be multiples of the page size
				uintptr_t rounded_down_base = MAPPING_BASE_FROM_PHDR_VADDR(info->dlpi_addr, info->dlpi_phdr[i].p_vaddr);
				uintptr_t rounded_up_end_of_file = MAPPING_END_FROM_PHDR_VADDR(info->dlpi_addr, 
						info->dlpi_phdr[i].p_vaddr, info->dlpi_phdr[i].p_filesz);
				uintptr_t rounded_up_end_of_mem = MAPPING_END_FROM_PHDR_VADDR(info->dlpi_addr, 
						info->dlpi_phdr[i].p_vaddr, info->dlpi_phdr[i].p_memsz);

				const char *dynobj_name = dynobj_name_from_dlpi_name(info->dlpi_name, 
					(void*) info->dlpi_addr);
				// HACK HACK HACK HACK: memory leak: please don't strdup
				char *data_ptr = dynobj_name ? strdup(dynobj_name) : NULL;

				/* If this mapping has memsz bigger than filesz, the memory kind
				 * should still be STATIC. 
				 * 
				 * PROBLEM: if we create it from the maps file, it will be HEAP
				 * because we can't tell that it's a STATIC file's bss.
				 * BUT we hope that later, HEAP will get rewritten to STATIC.
				 * We do this below, i.e. whenever we iterate over all loaded objs'
				 * mappings. We arrange that we always do this.
				 * 
				 * So all we need to do is arrange that the bss and file-backed
				 * parts of the mappings we create here are created separately,
				 * so that the bss part does not have a data_ptr (but is still
				 * STATIC). This will prevent bad coalescings that confuse
				 * us later.
				 * 
				 * Recall: only the memory kind matters for our metadata;
				 * the data ptr is irrelevant. Still, we should use the STATIC
				 * memory kind for bss.
				 */
				
				mapping_flags_t f = { .kind = STATIC, 
					.r = (_Bool) (info->dlpi_phdr[i].p_flags & PF_R), 
					.w = (_Bool) (info->dlpi_phdr[i].p_flags & PF_W), 
					.x = (_Bool) (info->dlpi_phdr[i].p_flags & PF_X)
				};
				 
				/* Look for a PT_GNU_RELRO entry covering any part of this 
				 * mapping. If there is one, we create *two* mappings. This
				 * is so that we don't confuse l0index by mapping a single
				 * big mapping over distinct-permission mappings that we got
				 * from /proc/pid/maps. */
				for (int j = 0; j < info->dlpi_phnum; ++j)
				{
					// if this phdr's a PT_GNU_RELRO
					if (info->dlpi_phdr[j].p_type == PT_GNU_RELRO)
					{
						/* Does it fall within our mapping? */
						// adjust start/end to be multiples of the page size
						uintptr_t relro_rounded_down_base
						 = MAPPING_BASE_FROM_PHDR_VADDR(info->dlpi_addr, info->dlpi_phdr[j].p_vaddr);
						uintptr_t relro_rounded_up_end_of_file = MAPPING_END_FROM_PHDR_VADDR(
							info->dlpi_addr, info->dlpi_phdr[j].p_vaddr, info->dlpi_phdr[j].p_filesz);
						uintptr_t relro_rounded_up_end_of_mem = MAPPING_END_FROM_PHDR_VADDR(
							info->dlpi_addr, info->dlpi_phdr[j].p_vaddr, info->dlpi_phdr[j].p_memsz);
						
						if (relro_rounded_down_base >= rounded_down_base
							&& relro_rounded_up_end_of_mem <= rounded_up_end_of_mem)
						{
							/* First add a ro mapping for any *whole pages* 
							 * that the RO span includes. 
							 * This means we need to do the *opposite* rounding. */
							uintptr_t relro_rounded_up_base
							 = MAPPING_NEXT_PAGE_START_FROM_PHDR_BEGIN_VADDR(
									info->dlpi_addr, info->dlpi_phdr[j].p_vaddr);
							uintptr_t relro_rounded_down_end_of_mem = MAPPING_PRECEDING_PAGE_START_FROM_PHDR_END_VADDR(
								info->dlpi_addr, info->dlpi_phdr[j].p_vaddr, info->dlpi_phdr[j].p_memsz);
							
							/* Add a mapping in this region. Do we need to handle the file/mem
							 * distinction? HMM. Try without for now. If the ro span covers
							 * some of the mem-but-not-file region, I don't think the boundary
							 * will be in the l0index already (because it got indexed from maps
							 * or from this code). Not sure though -- in which circumstances did 
							 * the distinction matter in the non-RO case? Maybe the memsz bit 
							 * got created as an anonymous section? Why wouldn't that happen here? */
							mapping_flags_t ro_f = f;
							ro_f.w = 0;
							struct mapping_info *added = mapping_add(
								(void*) relro_rounded_up_base, 
								relro_rounded_down_end_of_mem - relro_rounded_up_base,
								ro_f, data_ptr);
							// bit of a HACK: if it was added earlier by our mmap() wrapper, fix up its kind
							if (added && added->f.kind != STATIC) added->f.kind = STATIC;
							
							/* Add a pre-mapping if we have to. */
							if (relro_rounded_up_base > rounded_down_base)
							{
								struct mapping_info *added = mapping_add(
									(void*) rounded_down_base, 
									relro_rounded_up_base - rounded_down_base,
									f, data_ptr);
								// bit of a HACK: if it was added earlier by our mmap() wrapper, fix up its kind
								if (added && added->f.kind != STATIC) added->f.kind = STATIC;
							}
							
							/* Proceed with just the tail end of the mapping. */
							rounded_down_base = relro_rounded_down_end_of_mem;
						}
					}
				}
				
				if (rounded_down_base < rounded_up_end_of_file)
				{
					struct mapping_info *added = mapping_add(
						(void*) rounded_down_base, 
						rounded_up_end_of_file - rounded_down_base,
						f, data_ptr);
					// bit of a HACK: if it was added earlier by our mmap() wrapper, fix up its kind
					if (added && added->f.kind != STATIC) added->f.kind = STATIC;
				}
				
				if (rounded_up_end_of_mem > rounded_up_end_of_file
						&& rounded_up_end_of_mem > rounded_down_base)
				{
					struct mapping_info *added = mapping_add(
						(void*) rounded_up_end_of_file, 
						rounded_up_end_of_mem - rounded_up_end_of_file,
						f, NULL);
					// bit of a HACK: if it was added earlier by our mmap() wrapper, fix up its kind
					if (added && added->f.kind != HEAP) added->f.kind = HEAP;
				}
			}
		}
		
		// if we're looking for a single file, can stop now
		if (filename != NULL) return 1;
	}

	running = 0;
	
	// keep going
	return 0;
	
}

static ssize_t get_a_line(char *buf, size_t size, FILE *stream)
{
	if (size == 0) return -1; // now size is at least 1
	
	// read some stuff, at most `size - 1' bytes (we're going to add a null), into the buffer
	size_t bytes_read = fread(buf, 1, size - 1, stream);
	
	// if we got EOF and read zero bytes, return -1
	if (bytes_read == 0) return -1;
	
	// did we get enough that we have a whole line?
	char *found = memchr(buf, '\n', bytes_read);
	// if so, rewind the file to just after the newline
	if (found)
	{
		size_t end_of_newline_displacement = (found - buf) + 1;
		(void) fseek(stream, 
				end_of_newline_displacement - bytes_read /* i.e. negative if we read more */,
				SEEK_CUR);
		buf[end_of_newline_displacement] = '\0';
		return end_of_newline_displacement;
	}
	else
	{
		/* We didn't read enough. But that should only be because of EOF of error.
		 * So just return whatever we got. */
		buf[bytes_read] = '\0';
		return bytes_read;
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
	
	/* We used to use getline(), but in some deployments it's not okay to 
	 * use malloc when we're called early during initialization. So we write
	 * our own read loop. */
	char linebuf[8192];
	while (get_a_line(linebuf, sizeof linebuf, maps) != -1)
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
			
			enum object_memory_kind kind = UNKNOWN;
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
					if (0 == strncmp(rest, "[stack", 6))
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
			struct mapping_info *overlapping[MAX_OVERLAPPING];
			size_t n_overlapping = mapping_get_overlapping(
					&overlapping[0], MAX_OVERLAPPING, obj, (char*) obj + size);
			assert(n_overlapping < MAX_OVERLAPPING); // '<=' would mean we might have run out of space
			
			// if we have nothing overlapping, we should definitely add it....
			_Bool need_to_add = (n_overlapping == 0);
			
			mapping_flags_t f = { .kind = kind, .r = (r == 'r'), .w = (w == 'w'), .x = (x == 'x') };
			
			/* Else some other number of overlapping mappings exists. */
			for (unsigned i = 0; i < n_overlapping; ++i)
			{
				/* Handle the common case where the mapping we saw is already there
				 * with the right kind and, where appropriate, filename. 
				 * Note that the mappings's dimensions needn't be the same, because we merge
				 * adjacent entries, etc.. */
				if ((mapping_flags_equal(overlapping[i]->f, f)
						/* match STATIC and MAPPED_FILE interchangeably, because 
						 * we can't always tell the difference */
						|| ((overlapping[i]->f.kind == STATIC && f.kind == MAPPED_FILE)
							|| (overlapping[i]->f.kind == MAPPED_FILE && f.kind == STATIC)
						)
					)
					&& (overlapping[i]->what != DATA_PTR 
						|| // we do have a data ptr
							mapping_info_has_data_ptr_equal_to(f, overlapping[i], data_ptr))) continue;
				
				need_to_add = 1;
				
				// if we got here, is this a different mapped file? it's clearly not mapped there any more
				if (overlapping[i]->f.kind == STATIC || overlapping[i]->f.kind == MAPPED_FILE)
				{
					assert(overlapping[i]->what == DATA_PTR);
					const char *existing_data_ptr = overlapping[i]->un.data_ptr;
					if ((data_ptr != NULL && existing_data_ptr == NULL)
							|| (data_ptr == NULL && existing_data_ptr != NULL)
							|| (data_ptr != NULL && existing_data_ptr != NULL && 
							0 != strcmp(existing_data_ptr, data_ptr)))
					{
						debug_printf(2, "a static or mapped-file mapping, kind %d, data_ptr \"%s\", overlapping %p-%p "
								"seems to have gone away: now covered by kind %d, data_ptr \"%s\"\n",
							overlapping[i]->f.kind, (const char *) existing_data_ptr, 
							obj, (char*) obj + size, 
							f.kind, (const char *) data_ptr);
						mapping_del_node(overlapping[i]);
						continue;
					}
					
					/* If we got here, it means we have a static mapping which compared 
					 * equal in content, but might not have the same dimensions. Anyway, 
					 * when we try to add this it will still cause a problem. */
					// DO NOT UNDERSTAND!
					// Try just deleting this node. 
					debug_printf(2, "skipping POSSIBLY NOT static or mapped-file mapping (\"%s\") "
						"overlapping %p-%p and apparently already present\n",
						(const char *) overlapping[i]->un.data_ptr, obj, (char*) obj + size);
					//goto continue_loop;
					mapping_del_node(overlapping[i]);
					continue;
				}
			}
			
			#undef MAX_OVERLAPPING
			
			/* We always add heap and stack because they're sloppier, and because 
			 * our checks above didn't account for changes in size. */
			if (need_to_add || f.kind == HEAP || f.kind == STACK)
			{
				if (f.kind == HEAP) mapping_add_sloppy(obj, second - first, f, data_ptr);
				else mapping_add(obj, second - first, f, data_ptr);
			}
		} // end if size > 0
continue_loop:
		0;
	} // end while
	
	fclose(maps);
}
