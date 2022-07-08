malloc-from-dso: libdso.so
malloc-from-dso: LDLIBS += -Wl,-rpath,$(shell pwd) libdso.so
libdso.so: LDLIBS :=
libdso.so: dso.c
	$(CC) -shared -o $@ $+ $(CFLAGS) $(LDFLAGS) $(LDLIBS)

LIBALLOCS_ALLOC_FNS := dso_malloc_caller(Z)p
export LIBALLOCS_ALLOC_FNS
