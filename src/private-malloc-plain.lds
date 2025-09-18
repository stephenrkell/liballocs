# This is used by the dummyweaks library only.
# It need a private malloc because it uses private strdup.
# (Why? For incidental reasons to do with librunt and libcrunch.
# See the comment in dummyweaks.c.)
# We don't include the dlmalloc extension / wrapping stuff, as it is not needed.
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
HIDDEN(__private_nommap_malloc = nommap_dlmalloc);
HIDDEN(__private_nommap_calloc = nommap_dlcalloc);
HIDDEN(__private_nommap_free = nommap_dlfree);
HIDDEN(__private_nommap_realloc = nommap_dlrealloc);
HIDDEN(__private_nommap_memalign = nommap_dlmemalign);
HIDDEN(__private_nommap_posix_memalign = nommap_dlposix_memalign);
__liballocs_private_nommap_malloc = __private_nommap_malloc;
__liballocs_private_nommap_realloc = __private_nommap_realloc;
__liballocs_private_nommap_free = __private_nommap_free;
