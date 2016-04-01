ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . tools/lang src

# NOTE: being C++, these only affect build of the tools, not the liballocs core.
AM_CXXFLAGS = -std=c++11 -ggdb -O2 -Wall -Wno-deprecated-declarations -fPIC -Wp,-w -Iinclude $(LIBSRK31CXX_CFLAGS) $(LIBCXXFILENO_CFLAGS) $(LIBDWARFPP_CFLAGS) $(LIBCXXGEN_CFLAGS) $(LIBANTLR3CXX_CFLAGS) $(DWARFIDL_CFLAGS)

AM_CFLAGS = -Wall -std=gnu99 -ggdb -O3 -flto -Iinclude -fPIC -Wp,-w

AM_LDFLAGS = -Wl,--no-as-needed -lstdc++ -lm -lboost_regex $(DWARFIDL_LIBS) $(LIBCXXGEN_LIBS) $(LIBDWARFPP_LIBS) $(LIBSRK31CXX_LIBS) $(LIBCXXFILENO_LIBS) 

extra_DIST = liballocs.pc.in
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = liballocs.pc

liballocs_includedir = $(includedir)/liballocs
liballocs_include_HEADERS = include/heap_index.h include/malloc_usable_size_hack.h include/liballocs.h include/uniqtype-bfs.h include/liballocs_cil_inlines.h include/relf.h include/uniqtype.h include/memtable.h include/fake-libunwind.h include/allocsmt.h include/vas.h 

bin_PROGRAMS = tools/dumptypes tools/allocsites tools/usedtypes tools/ifacetypes tools/find-allocated-type-size
lib_LIBRARIES = tools/liballocstool.a 

tools_liballocstool_a_SOURCES = tools/helpers.cpp tools/uniqtypes.cpp

tools_dumptypes_SOURCES = tools/dumptypes.cpp
tools_dumptypes_LDADD = tools/liballocstool.a -ldwarf -lelf
tools_allocsites_SOURCES = tools/allocsites.cpp $(HELPERS)
tools_allocsites_LDADD = tools/liballocstool.a -ldwarf -lelf
tools_usedtypes_SOURCES = tools/usedtypes.cpp $(HELPERS)
tools_usedtypes_LDADD = tools/liballocstool.a -ldwarf -lelf
tools_ifacetypes_SOURCES = tools/ifacetypes.cpp $(HELPERS)
tools_ifacetypes_LDADD = tools/liballocstool.a -ldwarf -lelf
tools_find_allocated_type_size_SOURCES = tools/find-allocated-type-size.cpp $(HELPERS)
tools_find_allocated_type_size_LDADD = tools/liballocstool.a -ldwarf -lelf

# pkg-config doesn't understand PKG_CXXFLAGS, but I'm buggered
# if I'm going to have my Makefiles use _CFLAGS to mean _CXXFLAGS.
# So, if we find we have _CFLAGS set for these, either from pkg.m4
# or because pkg.m4 told the user to set this var, and if we *don't*
# have _CXXFLAGS for these things, propagate. Only one of the USER_*_CFLAGS
# and *_CFLAGS should be non-empty. Note that if we got this far,
# we *must* have a _CFLAGS, even if the user (sanely) didn't call it that,
# because pkg-config will have complained if we didn't fake it up.
if SUPPLIED_LIBCXXFILENO_CFLAGS
LIBCXXFILENO_CXXFLAGS = $(USER_LIBCXXFILENO_CFLAGS)
else
LIBCXXFILENO_CXXFLAGS = $(LIBCXXFILENO_CFLAGS)
endif
if SUPPLIED_LIBDWARFPP_CFLAGS
LIBDWARFPP_CXXFLAGS = $(USER_LIBDWARFPP_CFLAGS)
else
LIBDWARFPP_CXXFLAGS = $(LIBDWARFPP_CFLAGS)
endif
if SUPPLIED_LIBCXXGEN_CFLAGS
LIBCXXGEN_CXXFLAGS = $(USER_LIBCXXGEN_CFLAGS)
else
LIBCXXGEN_CXXFLAGS = $(LIBCXXGEN_CFLAGS)
endif
if SUPPLIED_LIBSRK31CXX_CFLAGS
LIBSRK31CXX_CXXFLAGS = $(USER_LIBSRK31CXX_CFLAGS)
else
LIBSRK31CXX_CXXFLAGS = $(LIBSRK31CXX_CFLAGS)
endif
if SUPPLIED_LIBANTLR3CXX_CFLAGS
LIBANTLR3CXX_CXXFLAGS = $(USER_LIBANTLR3CXX_CFLAGS)
else
LIBANTLR3CXX_CXXFLAGS = $(LIBANTLR3CXX_CFLAGS)
endif
if SUPPLIED_DWARFIDL_CFLAGS
DWARFIDL_CXXFLAGS = $(USER_DWARFIDL_CFLAGS)
else
DWARFIDL_CXXFLAGS = $(DWARFIDL_CFLAGS)
endif

export LIBCXXFILENO_CXXFLAGS LIBCXXFILENO_LIBS \
LIBSRK31CXX_CXXFLAGS LIBSRK31CXX_LIBS \
LIBDWARFPP_CXXFLAGS LIBDWARFPP_LIBS \
LIBCXXGEN_CXXFLAGS LIBCXXGEN_LIBS \
LIBANTLR3CXX_CXXFLAGS LIBANTLR3CXX_LIBS \
DWARFIDL_CXXFLAGS DWARFIDL_LIBS
