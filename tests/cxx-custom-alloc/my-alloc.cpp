#include <cstdlib>

void *my_malloc(size_t size)           { return malloc(size); }
void *my_calloc(size_t n, size_t size) { return calloc(n, size); }
