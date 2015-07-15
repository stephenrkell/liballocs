ACLOCAL_AMFLAGS = -I ../m4
AM_CFLAGS = -std=gnu99 -ggdb3 -O0 -I../include -Wp,-w -fPIC
AM_LDFLAGS = -lstdc++ -lm -lboost_regex $(LIBSRK31CXX_LIBS) $(LIBCXXFILENO_LIBS) $(LIBDWARFPP_LIBS) $(LIBCXXGEN_LIBS) $(DWARFIDL_LIBS) -L../src -L../tools

noinst_PROGRAMS = test_footprints
test_footprints_SOURCES = test_footprints.c footprints.c linux-syscall-ifacetypes.c
test_footprints_LDADD = -lantlr3c ../src/liballocs_nonshared.a ../tools/liballocstool.a

lib_LIBRARIES = liballocs_footprints.a
liballocs_footprints_a_SOURCES = footprints.c
liballocs_footprints_a_LIBADD = ../src/liballocs_nonshared.a ../tools/liballocstool.a
