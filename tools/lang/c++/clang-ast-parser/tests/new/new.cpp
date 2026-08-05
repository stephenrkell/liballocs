#include <cstdio>
#include <vector>
#include <new>
#include <cstdlib>

struct Point { 
    int x, y; 
    Point(): x(0), y(0) {}
    Point(int x, int y): x(x), y(y) {}
};

int main() {
    Point *p  = new Point;
    Point *ps = new Point[10];
    int   *n  = new int(42);

    std::vector<int> *v = new std::vector<int>;

    void* raw = std::malloc(sizeof(Point));
    Point* pr = new (raw) Point(1, 2);

    return 0;
}
