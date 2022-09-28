# FIXME: really want these to be protected not hidden.
HIDDEN(__private_malloc = dlmalloc);
HIDDEN(__private_calloc = dlcalloc);
HIDDEN(__private_free = dlfree);
HIDDEN(__private_realloc = dlrealloc);
HIDDEN(__private_memalign = dlmemalign);
HIDDEN(__private_posix_memalign = dlposix_memalign);
__liballocs_private_malloc = __private_malloc;
__liballocs_private_realloc = __private_realloc;
__liballocs_private_free = __private_free;
