#include <cstdlib>
#include <stdio.h>
#include <vector>

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
	auto v_ptr = new std::vector<void*>();

	// std's malloc
	std::malloc(sizeof(Point)); // __uniqtype__Point
	// user defined malloc
	malloc(42, 2); // skipped
	struct Point p;
	malloc(p); // __uniqtype__Point
	// malloc + sizeof
	malloc(sizeof(Point)); // __uniqtype__Point
	malloc(2);
	malloc(sizeof p); // __uniqtype__Point
	malloc(2 * sizeof(Point)); // __uniqtype__Point
	malloc(1 * sizeof(Point)); // __uniqtype__Point
	malloc((2 + 2) * sizeof(Point)); // __uniqtype__Point
	malloc((4 - 2) * sizeof(Point)); // __uniqtype__Point
	malloc((4 / 2) * sizeof(Point)); // __uniqtype__Point
	malloc(sizeof(Point) * sizeof(A)); // __uniqtype____uninterpreted_byte
	malloc(sizeof(int)); // __uniqtype__int$$32
	unsigned long sz = sizeof(Point) * 10; 
	malloc(sz); // __uniqtype__Point
	size_t sz2 = sizeof(Point) * 10;
	malloc(sz2); // __uniqtype__Point
	auto sz3 = sizeof(Point);
	malloc(sz3);
	// NOTE: what to do ?
	size_t sz4 = 0;
	if (true) {
		sz4 = sizeof(Point);
	} else {
		sz4 = sizeof(A);
	}
	malloc(sz4); // __uniqtype__int$$32
	malloc(sizeof("hello")); // __uniqtype_char$$8
	// casting
	(Point*) malloc(sizeof(2) * 2); // __uniqtype__Point
	(Point*) malloc(sizeof(int) * 2); // __uniqtype__Point
	static_cast<Point*>(malloc(sizeof(int) * 2)); // ___uniqtype__Point
	
	// TODO: reassigned sizeof
	size_t sz_re = 0;
	sz_re = sizeof(Point);
	malloc(sz_re);

	// TODO: more mallocs
	using AllocatorFunc = void* (*)(std::size_t);
	AllocatorFunc foo;
	if (true) {
		foo = std::malloc;
	} else {
		foo = malloc; // some fake allocator
	}
	void *f1 = foo(sizeof(Point));

	// TODO: offsetof
	void *o = malloc(sizeof(Point) - sizeof(int));

	// TODO: synthetic
	void *s = malloc(1);

	// TODO: array
	int arr[10];
	void *ptr_arr = new int[10];

	// TODO: template structs
	auto v = new std::vector<int>();

	// TODO: anonymous structs
	
	// TODO: enums
}
