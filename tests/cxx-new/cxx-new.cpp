#include <allocs.h>
#include <cstdio>

struct Point { int x, y; };

int main() {
    Point *p  = new Point;
    Point *ps = new Point[10];
    int   *n  = new int(42);

    printf("p  type: %s\n", UNIQTYPE_NAME(__liballocs_get_alloc_type(p)));
    printf("ps type: %s\n", UNIQTYPE_NAME(__liballocs_get_alloc_type(ps)));
    printf("n  type: %s\n", UNIQTYPE_NAME(__liballocs_get_alloc_type(n)));

    delete p;
    delete[] ps;
    delete n;
    return 0;
}
