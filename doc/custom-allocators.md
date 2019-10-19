To declare wrappers, set environment variables something like this at
build time.

    LIBALLOCS_ALLOC_FNS="mymalloc(Z)p mycalloc(zZ)p myrealloc(pZ)p"
    LIBALLOCS_FREE_FNS="myfree(P)"

 ... where in the signature mini-language, "z" stands for "size_t", "p"
for any pointer, and "i" for int. Capitals denote the significant
argument (type-determining size or alloc-being-freed).

This is necessary for C code, to analyse the use of `sizeof` which
provides type information for allocator calls.

To declare allocators, use something like this.

    LIBALLOCS_SUBALLOC_FNS="mysubmalloc(Z)p"
    LIBALLOCS_SUBFREE_FNS="mysubfree(P)->mysubmalloc"

This will ensure that these functions are wrapped such that new
allocations are indexed in a generic (but slow!) structure. If code
changes are feasible, is also possible to write a custom index and
perform the wrapping yourself.

The above facilities are very ad-hoc and will at some point be
redesigned into something more general (contributions welcome!).
