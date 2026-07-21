#include <allocs.h>
#include <cassert>
#include <cstdio>
#include <cstring>

struct Point { int x, y; };
struct Node  { int val; struct Node *next; };

int main() {
    // Scalar new
    Point *p = new Point{1, 2};
    assert(p);
    struct uniqtype *pt = __liballocs_get_alloc_type(p);
    assert(pt);
    printf("new Point type: %s\n", NAME_FOR_UNIQTYPE(pt));
    assert(strstr(NAME_FOR_UNIQTYPE(pt), "Point") != nullptr);

    // Scalar new, different type
    Node *n = new Node{42, nullptr};
    assert(n);
    struct uniqtype *nt = __liballocs_get_alloc_type(n);
    assert(nt);
    printf("new Node type: %s\n", NAME_FOR_UNIQTYPE(nt));
    assert(strstr(NAME_FOR_UNIQTYPE(nt), "Node") != nullptr);

    // Array new
    Point *arr = new Point[3];
    assert(arr);
    struct uniqtype *at = __liballocs_get_alloc_type(arr);
    assert(at);
    printf("new Point[3] type: %s\n", NAME_FOR_UNIQTYPE(at));
    assert(strstr(NAME_FOR_UNIQTYPE(at), "Point") != nullptr);

    delete p;
    delete n;
    delete[] arr;
    return 0;
}
