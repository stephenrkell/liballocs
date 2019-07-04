#include <stdio.h>
#include <stdlib.h>

struct with_array
{
    int *num;
    int *arr[5];
};

int ANSWER = 42;

int main()
{
    struct with_array a;
    a.num = &ANSWER;
    a.arr[3] = &ANSWER;

    struct with_array *b = malloc(sizeof(struct with_array));
    *b = a;

    printf("%d\n", *b->arr[3]);

    free(b);

    return 0;
}
