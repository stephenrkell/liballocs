#include <stdlib.h>

void *(*ALLOCATOR)(unsigned long sz);

int main()
{
    ALLOCATOR = malloc;
    return 0;
}
