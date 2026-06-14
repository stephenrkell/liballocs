#include <cstdlib>
#include <stdio.h>

struct Point {
	int x, y;
};

struct A {
	int val;
};

void* malloc(size_t size, int n) {
	// user defined malloc allocates memory somewhere else
	return nullptr;
}

void* malloc(Point p) {
	// user defined malloc allocates memory somewhere else
	return nullptr;
}

int main() {
	printf("sizeof Point: %zu\n", sizeof(Point)); 

	// std's malloc
	void *s1 = std::malloc(sizeof(Point)); // __uniqtype__Point
	// user defined malloc
	void *u1 = malloc(42, 2); // skipped
	struct Point p;
	void *u2 = malloc(p); // skipped
	// malloc + sizeof
	void *a1 = malloc(sizeof(Point)); // __uniqtype__Point
	void *a2 = malloc(sizeof p); // __uniqtype__Point
	void *a3 = malloc(42 * sizeof(Point)); // __uniqtype__Point
	void *a4 = malloc(sizeof(Point) * sizeof(A)); // __uniqtype__Point
	void *a5  = malloc(sizeof(int)); // __uniqtype__int$$32
	unsigned long sz = sizeof(Point) * 10;
	void *a6 = malloc(sz); // __uniqtype__unsigned_long$$64 
	size_t sz2 = sizeof(Point) * 10;
	void *a7 = malloc(sz2); // __uniqtype__unsigned_long$$64 
	// casting
	void *p1 = (Point*) malloc(sizeof(2) * 2); // __uniqtype__Point
	void *p2 = (Point*) malloc(sizeof(int) * 2); // __uniqtype__Point
	void *p3 = static_cast<Point*>(malloc(sizeof(int) * 2)); // ___uniqtype__Point


	free(s1);
	free(u1); free(u2);
	free(a1); free(a2); free(a3); free(a4); free(a5); free(a6); free(a7);
	free(p1); free(p2); free(p3);
}
