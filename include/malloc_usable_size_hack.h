/* On some systems, i.e. NetBSD, I have had the following weird
 * problem.
 *
 * 1. libc has no malloc_usable_size, so I statically link in
 *    dlmalloc with --export-dynamic.
 * 2. Then I LD_PRELOAD these hooks (compiled for preload).
 * 3. I get a run-time error

/usr/local/src/libpmirror.hg/lib/libheap_index_preload_hooks.so:
Undefined PLT symbol "malloc_usable_size" (symnum = 21)

 *   ... suggesting that rtld doesn't know how to fix up PLT
 *   entries in the --export-dynamic use case.
 *   (Objdump confirms that --export-dynamic is taking effect.)
 *
 * So here I define my own malloc_usable_size, and use the
 * dynamic linker to find the underlying one.
 */

#ifdef __cplusplus
typedef bool _Bool;
extern "C" {
#endif

static inline size_t malloc_usable_size(void *ptr)
{
        static size_t (*my_malloc_usable_size)(void*) = 0;
        static _Bool init_failed = 0;

        if (!my_malloc_usable_size && !init_failed)
        {
		dlerror();
                my_malloc_usable_size
		 = (size_t(*)(void*)) dlsym(/*RTLD_NEXT*/RTLD_DEFAULT,
                        "malloc_usable_size");
                if (!my_malloc_usable_size)
                {
			char *msg = dlerror();
                        init_failed = 1;
                        fprintf(stderr,
                                "Failed to get malloc_usable_size. " 
				"Error: %s.\n", msg);
                }
        }
        if (my_malloc_usable_size) return my_malloc_usable_size(ptr);
        else return 0;
}

#ifdef __cplusplus
} /* end extern "C" */
#endif
