#include <allocs.h>
#include <stdio.h>
#include <stdlib.h>
#include <new>

struct Point{
	int x, y;
};

int main() {
	unsigned long size = sizeof(Point);
	void *raw = malloc(size * 10);
	printf("size = %zu\n", size * 10);
	printf("raw type: %s\n", UNIQTYPE_NAME(__liballocs_get_alloc_type(raw)));
	//Point *p = new (raw) Point;
	//printf("raw type: %s\n", UNIQTYPE_NAME(__liballocs_get_alloc_type(raw)));
	//printf("p type: %s\n", UNIQTYPE_NAME(__liballocs_get_alloc_type(p)));
	free(raw);
}
