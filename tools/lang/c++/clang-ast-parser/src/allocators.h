#ifndef ALLOCATORS_H

#define ALLOCATORS_H

#include <string>
#include <set>

static std::set<std::string> allocator_funcs = {"malloc", "calloc", "realloc", "reallocarray"};

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

    return -1;
};


#endif
