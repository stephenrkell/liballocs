ACLOCAL_AMFLAGS = -I ../m4
AM_CFLAGS = -std=gnu99 -ggdb3 -O0 -I../include -fPIC -DPIC -Wall  -Wno-unused-variable -Wno-unused-but-set-variable -Werror -ffreestanding -fno-omit-frame-pointer 
AM_LDFLAGS = -lstdc++ -lm -lboost_regex $(LIBSRK31CXX_LIBS) $(LIBCXXFILENO_LIBS) $(LIBDWARFPP_LIBS) $(LIBCXXGEN_LIBS) $(DWARFIDL_LIBS) -L../src -L../tools -Wl,--hash-style=sysv -Wl,--dynamic-list,dynamic-list -Wl,--version-script,version-script

noinst_PROGRAMS = test_footprints test_syscalls
test_footprints_SOURCES = test_footprints.c linux-syscall-ifacetypes.c
test_footprints_LDADD = -lantlr3c ../src/liballocs_nonshared.a ../tools/liballocstool.a liballocs_footprints.a

test_syscalls_SOURCES = test_syscalls.c perform_syscall.c
test_syscalls_LDADD = -lantlr3c ../src/liballocs_nonshared.a ../tools/liballocstool.a liballocs_footprints.a
test_syscalls_DEPENDENCIES = ../src/liballocs_nonshared.a ../tools/liballocstool.a liballocs_footprints.a dynamic-list

dynamic-list: $(patsubst %.c,%.o,linux-syscall-ifacetypes.c)
	( echo '{'; nm --format=posix "$<" | sed 's/[[:blank:]].*/;/'; echo '};') > "$@" || rm -f "$@"

lib_LIBRARIES = liballocs_footprints.a
liballocs_footprints_a_SOURCES = binary_ops.c eval.c footprints.c parser.c subscripts.c unary_ops.c values.c control_flow.c exprs.c idents.c objects.c printer.c unions.c linux-syscall-ifacetypes.c
liballocs_footprints_a_LIBADD = ../src/liballocs_nonshared.a ../tools/liballocstool.a

lib_LTLIBRARIES = liballocs_syscalls.la
liballocs_syscalls_la_SOURCES = binary_ops.c eval.c footprints.c parser.c subscripts.c unary_ops.c values.c control_flow.c exprs.c idents.c objects.c printer.c unions.c linux-syscall-ifacetypes.c perform_syscall.c
liballocs_syscalls_la_CFLAGS = $(AM_CFLAGS)
liballocs_syscalls_la_LIBADD = -lantlr3c ../src/liballocs_nonshared.a ../tools/liballocstool.a liballocs_footprints.a
liballocs_syscalls_la_DEPENDENCIES = ../src/liballocs_nonshared.a ../tools/liballocstool.a liballocs_footprints.a dynamic-list

