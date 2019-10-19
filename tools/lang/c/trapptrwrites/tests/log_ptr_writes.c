#include <stdio.h>

void __notify_ptr_write(const void **dest, const void *val)
{
    fprintf(stderr, "Write %p to %p\n", val, dest);
}

void __notify_copy(void *dest, const void *src, size_t count)
{
    fprintf(stderr, "Copy %d bytes at %p to %p\n", count, src, dest);
}
