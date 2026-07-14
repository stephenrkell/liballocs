#include <allocs.h>
#include <cstdlib>
#include <cstdio>
#include <cassert>

struct Point { int x, y; };
struct Node  { int val; Node *next; };

// Defined in my-alloc.cpp so the linker can wrap these cross-TU calls.
void *my_malloc(size_t size);
void *my_calloc(size_t n, size_t size);

int main() {
    Point *p = static_cast<Point *>(my_malloc(sizeof(Point)));
    assert(p);
    struct uniqtype *pt = __liballocs_get_alloc_type(p);
    assert(pt);
    printf("my_malloc(sizeof(Point)) type: %s\n", NAME_FOR_UNIQTYPE(pt));

    Node *ns = static_cast<Node *>(my_calloc(5, sizeof(Node)));
    assert(ns);
    struct uniqtype *nt = __liballocs_get_alloc_type(ns);
    assert(nt);
    printf("my_calloc(5, sizeof(Node)) type: %s\n", NAME_FOR_UNIQTYPE(nt));

    free(p);
    free(ns);
    return 0;
}
