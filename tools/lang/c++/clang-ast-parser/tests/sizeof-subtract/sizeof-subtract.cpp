#include <cstdlib>
#include <cstddef>

struct s1 {
    float blah;
    unsigned int ns[1];
};

struct s2 {
    void *ptr;
    char data[1];
};

int main() {
    // Base case: sizeof(T) - sizeof(field) + constant
    void *p1 = malloc(sizeof(struct s1) - sizeof(int) + 24);

    // With multiplied tail: sizeof(T) - sizeof(field) + n * sizeof(field)
    void *p2 = malloc(sizeof(struct s1) - sizeof(unsigned int) + 6 * sizeof(unsigned int));

    // Different struct
    void *p3 = malloc(sizeof(struct s2) - sizeof(char) + 100);

    // Variable propagation: size computed before the call
    size_t sz = sizeof(struct s1) - sizeof(int) + 24;
    void *p4 = malloc(sz);

    free(p1); free(p2); free(p3); free(p4);
    return 0;
}
