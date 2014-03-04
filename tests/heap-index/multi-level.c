#define _GNU_SOURCE // for memtable, for asprintf...
#include <stdlib.h>
#include "heap_index.h"


int main(void)
{
	// allocate a chunk
	void *arena = malloc(4096);

	// pretend we're parcelling it out l2-style
	__index_deep_alloc(arena, 2, 2048);
	__index_deep_alloc((char*) arena + 2048, 2, 2048);

	// can we retrieve the deep allocs?
	struct deep_entry_region *ignored;
	struct deep_entry *alloc1 = __lookup_deep_alloc(arena, 2, 2, &ignored);
	assert(alloc1);
	assert(alloc1->size_4bytes == 512);
	struct deep_entry *alloc2 = __lookup_deep_alloc((char*) arena + 2048, 2, 2, &ignored);
	assert(alloc2);
	assert(alloc2->size_4bytes == 512);

	// now parcel alloc1 out further
	__index_deep_alloc(arena, 3, 4);
	__index_deep_alloc((char*) arena + 4, 3, 4);
	struct deep_entry *alloc3 = __lookup_deep_alloc((char*) arena, 3, 3, &ignored);
	assert(alloc3);
	assert(alloc3->size_4bytes == 1);
	struct deep_entry *alloc4 = __lookup_deep_alloc((char*) arena + 4, 3, 3, &ignored);
	assert(alloc4);
	assert(alloc4->size_4bytes == 1);

	return 0;
}
