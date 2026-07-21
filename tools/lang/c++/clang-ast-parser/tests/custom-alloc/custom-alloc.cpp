#include <cstdlib>

struct Point { int x, y; };
struct Node  { int val; Node *next; };

// User-defined allocators (declared but defined elsewhere)
void *my_malloc(unsigned long size);
void *my_calloc(unsigned long n, unsigned long size);
void *pool_alloc(void *pool, unsigned long size);

int main() {
    // LIBALLOCS_ALLOC_FNS="my_malloc(Z)p"
    my_malloc(sizeof(Point));           // __uniqtype__Point 0
    my_malloc(2 * sizeof(Point));       // __uniqtype__Point 1

    // LIBALLOCS_ALLOC_FNS="my_calloc(zZ)p"  (size arg is second = index 1)
    my_calloc(10, sizeof(Node));        // __uniqtype__Node 1

    // LIBALLOCS_SUBALLOC_FNS="pool_alloc(pZ)p"  (pool ptr + size)
    pool_alloc(nullptr, sizeof(Point)); // __uniqtype__Point 0
}
