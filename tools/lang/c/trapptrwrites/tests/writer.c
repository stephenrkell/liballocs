#include <stdio.h>
#include <stdlib.h>

int *GLOBAL_PTR;
char HW[] = "hello world ?";

struct list
{
    int head;
    struct list *tail;
};
struct list *LIST;

void print_str(const char *str)
{
    printf("%s\n", str);
}

void set_global_ptr(int *gptr)
{
    GLOBAL_PTR = gptr;
}

struct list *cons_list(int val, struct list *tail)
{
    struct list *l = malloc(sizeof(struct list));
    *l = (struct list){.head = val, .tail = tail};
    return l;
}

void print_list(struct list *l)
{
    if(l)
    {
        printf("%d ", l->head);
        print_list(l->tail);
    }
    else printf("\n");
}

int main()
{
    int i;
    i = 12;
    HW[i] = '!';
    print_str(HW);

    set_global_ptr(&i);

    struct list *l0 = cons_list(0, NULL);
    LIST = cons_list(1, l0);
    print_list(LIST);

    return 0;
}
