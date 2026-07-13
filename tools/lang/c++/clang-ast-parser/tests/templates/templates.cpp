#include <cstdlib>

template <typename T>
struct Point {
	int x, y;
	T t;
};

struct A {
	int val;
};

template <typename K, typename V>
struct Pair {
	K key;
	V value;
};

template <typename T>
struct Box {
	T item;
	int tag;
};

int main() {
	// Simple template instantiation
	void *p1 = new Point<A>();

	// Two type parameters
	void *p2 = malloc(sizeof(Pair<int, A>));

	// One level of nesting: Box<Point<A>>
	void *p3 = new Box<Point<A>>();

	// Long chain: Pair<Point<A>, Box<Pair<int, A>>>
	void *p4 = malloc(sizeof(Pair<Point<A>, Box<Pair<int, A>>>));

	free(p1);
	free(p2);
	free(p3);
	free(p4);
	return 0;
}
