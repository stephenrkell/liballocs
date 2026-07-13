#include <cstdlib>

template <typename T>
struct Point {
	int x, y;
	T t;
};

struct A {
	int val;
};

int main() {
	void *raw = new Point<A>();
	free(raw);
	return 0;
}
