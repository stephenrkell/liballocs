#define _GNU_SOURCE
#include <glib.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <assert.h>

static _Bool initialized;

extern _Bool __libcrunch_is_initialized __attribute__((weak));

static void (__attribute__((constructor)) init)(void)
{
	initialized = 1;
}

_Bool __thread doing_deep_call = 0;

char early_heap[4 * 1048576];
char *early_heap_cur = &early_heap[0];
void *xmalloc(size_t size)
{
	uintptr_t *ret = g_slice_alloc(size + sizeof (uintptr_t));
	*ret = size;
	return ret + 1;
}
void *xcalloc(size_t nmemb, size_t size)
{
	uintptr_t *ret = g_slice_alloc0(size * nmemb + sizeof (uintptr_t));
	*ret = size;
	return ret + 1;
}

void xfree(void *ptr)
{
	if (!ptr) return;
	uintptr_t *p = ptr;
	g_slice_free1(*(p-1), p-1); // a.k.a. size allocated
}

void *xrealloc(void *ptr, size_t size)
{
	// use gslice
	// -- is the old region big enough?
	uintptr_t *p = ptr;
	if (*(p-1) >= size) return p;
	else
	{
		// copy and reallocate
		uintptr_t *new = g_slice_alloc(size + sizeof (uintptr_t));
		memcpy(new + 1, p, *(p-1));
		g_slice_free1(*(p-1), p-1);
		return new;
	}
}

int main(void)
{
	int *blah = (int *) xmalloc(200 * sizeof (int));
	for (int i = 0; i < 200; ++i) blah[i] = 42;
	
	void *fake = blah;

	int *recovered = (int *) fake;

	printf("It says: %d\n", recovered[0]);

	xfree(blah);
	
	return 0;
}
