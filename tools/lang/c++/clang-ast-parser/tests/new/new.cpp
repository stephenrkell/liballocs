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

    // TODO: 1. try to resolve type info in allocated region
    void* raw = std::malloc(sizeof(Point));
    // TODO: 2. reassign type info to the Point
    Point* pr = new (raw) Point(1, 2);

    delete p;
    delete[] ps;
    delete n;
    delete pr;
    delete v;
    return 0;
}
