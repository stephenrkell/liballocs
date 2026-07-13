#include <cstdlib>
#include <stdio.h>

struct Point {
	int x, y;
};

struct A {
	int val;
};

struct {
	int val;
} point;

typedef struct {
	int code;
} Status;

int getSizeOf(int x) {
	if (x > 5) {
		return sizeof(Point);
	} else {
		return sizeof(A);
	}
}

int main(int argc, char **argv) {
	struct Point p;

	malloc(sizeof(Point)); // __uniqtype__Point 0
	malloc(sizeof(Point)); // __uniqtype__Point 0
	malloc(2); // __uniqtype__uninterpreted_byte 1
	malloc(sizeof p); // __uniqtype__Point 0
	malloc(2 * sizeof(Point)); // __uniqtype__Point 1
	malloc(1 * sizeof(Point)); // __uniqtype__Point 1
	malloc((2 + 2) * sizeof(Point)); // __uniqtype__Point 1
	malloc((4 - 2) * sizeof(Point)); // __uniqtype__Point 1
	malloc((4 / 2) * sizeof(Point)); // __uniqtype__Point 1
	malloc(sizeof(Point) * sizeof(A)); // __uniqtype__Point 1
	malloc(sizeof(int)); // __uniqtype__int$$32 0
	unsigned long sz = sizeof(Point) * 10; 
	malloc(sz); // __uniqtype__Point 1
	size_t sz2 = sizeof(Point) * 10;
	malloc(sz2); // __uniqtype__Point 1
	auto sz3 = sizeof(Point);
	malloc(sz3); // __uniqtype__Point 0
	malloc(getSizeOf(1)); // __uniqtype__A 0
	malloc(getSizeOf(6)); // __uniqtype__Point 0
	malloc(getSizeOf(argc)); // __uniqtype____uninterpreted_byte 1
	malloc(sizeof("hello")); // __uniqtype_char$$8 1
	// casting
	(Point*) malloc(sizeof(2) * 2); // __uniqtype__Point 1
	(Point*) malloc(sizeof(int) * 2); // __uniqtype__Point 1
	static_cast<Point*>(malloc(sizeof(int) * 2)); // __uniqtype__Point 1
	
	size_t sz_re = 0;
	sz_re = sizeof(Point);
	malloc(sz_re); // __uniqtype__Point 0

	// anonymous struct (no typedef - can't name it)
	malloc(sizeof(point)); // __uniqtype____uninterpreted_byte 0
	// anonymous struct via typedef - should use typedef name
	Status s;
	malloc(sizeof(Status));        // __uniqtype__Status 0
	malloc(sizeof(s));             // __uniqtype__Status 0
	malloc(2 * sizeof(Status));    // __uniqtype__Status 1

	// TODO: enums
	enum Light {
		Red, Yellow, Green
	};
	malloc(sizeof(Light));

	enum class Light2 {
		Red, Yellow, Green
	};
	malloc(sizeof(Light2));
}
