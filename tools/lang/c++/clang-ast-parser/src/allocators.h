#ifndef ALLOCATORS_H

#define ALLOCATORS_H

#include <string>
#include <set>

static std::set<std::string> allocator_funcs = {"malloc", "calloc", "realloc", "reallocarray", "alloca", "__builtin_alloca", "posix_memalign"};

// number of args is needed to filter out some of the user defined custom mallocs
static int sizeOfArgIndex(std::string name, int numOfArgs) {
    // void *malloc(size_t size);
    if (name == "malloc" && numOfArgs == 1) return 0;
    // void *calloc(size_t n, size_t size);
    if (name == "calloc" && numOfArgs == 2) return 1;
    // void *realloc(void *p, size_t size);
    if (name == "realloc" && numOfArgs == 2) return 1;
    // void *reallocarray(void *p, size_t n, size_t size);
    if (name == "reallocarray" && numOfArgs == 3) return 2;
    // void *alloca(size_t size);
    if (name == "alloca" && numOfArgs == 1) return 0;
    // void *__builtin_alloca(size_t size);
    if (name == "__builtin_alloca" && numOfArgs == 1) return 0;
    // void *posix_memalign(void **memptr, size_t alignment, size_t size);
    if (name == "posix_memalign" && numOfArgs == 3) return 2;

    return -1;
};


#endif
