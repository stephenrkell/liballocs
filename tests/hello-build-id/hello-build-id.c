#include <stdio.h>
#include <string.h>
#include <link.h>
#include "allocs.h"
#include "allocmeta.h"

int main(void)
{
	/* Assert that we can look up ourselves. */
	assert(__liballocs_get_alloc_type(main));
	/* Assert that we have, in our link map, something
	 * that looks like our by-build-ID meta-DSO. This is
	 * also testing that we try the meta-DSO path *first*, before
	 * the path based on the base binary's path... see meta-dso.c.
	 * Actually, rather than testing the link map, just directly
	 * grab the meta-DSO path from the file metadata. */
	void *file_metadata = __liballocs_get_specific_by_allocator(main, &__static_file_allocator, NULL);
	assert(file_metadata);
	struct allocs_file_metadata *meta = file_metadata;
	assert(meta->meta_obj_handle);
	struct link_map *meta_l = meta->meta_obj_handle;
	assert(NULL != strstr(meta_l->l_name, ".build-id"));
	return 0;
}
