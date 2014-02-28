#include <dlfcn.h>
#include "libcrunch.h"

void *l1(int arg)
{
	void *resolved = dlsym(__libcrunch_my_typeobj(), "__uniqtype__int$32");
	return resolved;
}
