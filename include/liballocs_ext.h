#ifndef LIBALLOCS_EXT_H_
#define LIBALLOCS_EXT_H_

/* This file is for declarations that might be needed
 * in code external to the liballocs DSO,
 * but that calls into usually private parts of the
 * liballocs implementation.
 *
 * Examples include allocator stubs (linked in to a built exe)
 * and possibly 'extensions' residing in other DSOs (like the
 * ELF file allocator in example/). */

void *__liballocs_private_malloc(size_t);
void *__liballocs_private_realloc(void*, size_t);
void __liballocs_private_free(void *);

void __liballocs_free_arena_bitmap_and_info(void *info  /* really struct arena_bitmap_info * */);

/* All the above are created as global aliases (would ideally
 * be protected ). */

void __notify_copy(void *dest, const void *src, unsigned long n);
void __notify_free(void *dest);
// FIXME: seems wrong that this is declared only in the CIL inlines?
void __liballocs_uncache_all(const void *allocptr, unsigned long size);

#endif
