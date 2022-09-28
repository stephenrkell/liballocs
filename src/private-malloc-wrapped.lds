# FIXME: really want these to be protected not hidden.
HIDDEN(__private_malloc =__wrap_dlmalloc);
HIDDEN(__private_calloc = __wrap_dlcalloc);
HIDDEN(__private_free = __wrap_dlfree);
HIDDEN(__private_realloc = __wrap_dlrealloc);
HIDDEN(__private_memalign = __wrap_dlmemalign);
HIDDEN(__private_posix_memalign = __wrap_dlposix_memalign);
__liballocs_private_malloc = __private_malloc;
__liballocs_private_realloc = __private_realloc;
__liballocs_private_free = __private_free;
