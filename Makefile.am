ACLOCAL_AMFLAGS = -I m4

SUBDIRS = tools/lang . allocsld src lib

# HACK to disable -O2 if DEBUG is set (to anything) -- thanks for nothing, automake
AM_CXXFLAGS = -O2 $(DEBUG:%=-O0) -fno-omit-frame-pointer -ggdb -fkeep-inline-functions \
  -Wall -Wno-deprecated-declarations -fPIC -Wp,-w -Iinclude $(LIBSRK31CXX_CFLAGS) \
  $(LIBCXXFILENO_CFLAGS) $(LIBDWARFPP_CFLAGS) $(LIBCXXGEN_CFLAGS) $(LIBANTLR3CXX_CFLAGS) \
  $(DWARFIDL_CFLAGS) -I$(LIBRUNT)/include $(LIBALLOCSTOOL_CFLAGS)

AM_CPPFLAGS =
AM_CFLAGS = -Wall -std=gnu99 -ggdb -O3 -flto -Iinclude -fPIC -Wp,-w
AM_LDFLAGS =

# ltdl complains if I don't set these....
noinst_LTLIBRARIES =
include_HEADERS =
lib_LTLIBRARIES =
EXTRA_DIST =
EXTRA_LTLIBRARIES =
CLEANFILES =
BUILT_SOURCES = tools/roottypes.c
MOSTLYCLEANFILES =

extra_DIST = liballocs.pc.in
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = liballocs.pc

# workaround -- thanks https://www.gnu.org/software/automake/manual/html_node/Uniform.html
my_libdir = $(libdir)
my_lib_DATA = lib/interp-pad.o

liballocs_includedir = $(includedir)/liballocs
liballocs_include_HEADERS = include/heap_index.h include/liballocs.h include/uniqtype-bfs.h include/liballocs_cil_inlines.h include/memtable.h include/fake-libunwind.h include/allocsites.h

bin_PROGRAMS = tools/dwarftypes tools/alloctypes tools/frametypes tools/extrasyms tools/metavector tools/dumpptrs tools/allocsites tools/usedtypes tools/ifacetypes tools/find-allocated-type-size tools/cufiles tools/pervasive-types
#tools/objdumpallocs-llvm

LIBELF ?= -lelf
export LIBELF

TOOLS_LDADD = $(LIBALLOCSTOOL_LIBS) \
 $(LIBSRK31CXX_LIBS) $(LIBCXXFILENO_LIBS) $(LIBDWARFPP_LIBS) $(LIBCXXGEN_LIBS) $(LIBANTLR3CXX_LIBS) $(DWARFIDL_LIBS) \
-lantlr3c $(LIBELF) -lz

TOOLS_CXXFLAGS := $(AM_CXXFLAGS) -I$(libsystrap) -I$(librunt)/include

tools_dwarftypes_SOURCES = tools/dwarftypes.cpp
tools_dwarftypes_LDADD = $(TOOLS_LDADD)
tools_dwarftypes_CXXFLAGS = $(TOOLS_CXXFLAGS)
tools_frametypes_SOURCES = tools/frametypes.cpp
tools_frametypes_LDADD = $(TOOLS_LDADD)
tools_frametypes_CXXFLAGS = $(TOOLS_CXXFLAGS)
tools_extrasyms_SOURCES = tools/extrasyms.cpp
tools_extrasyms_LDADD = $(TOOLS_LDADD)
tools_extrasyms_CXXFLAGS = $(TOOLS_CXXFLAGS)
tools_metavector_SOURCES = tools/metavector.cpp
tools_metavector_LDADD = $(TOOLS_LDADD)
tools_metavector_CXXFLAGS = $(TOOLS_CXXFLAGS)
tools_alloctypes_SOURCES = tools/alloctypes.cpp
tools_alloctypes_LDADD = $(TOOLS_LDADD)
tools_alloctypes_CXXFLAGS = $(TOOLS_CXXFLAGS)
tools_dumpptrs_SOURCES = tools/dumpptrs.cpp
tools_dumpptrs_LDADD = $(TOOLS_LDADD)
tools_dumpptrs_CXXFLAGS = $(TOOLS_CXXFLAGS)
tools_cufiles_SOURCES = tools/cufiles.cpp
tools_cufiles_LDADD = $(TOOLS_LDADD)
tools_cufiles_CXXFLAGS = $(TOOLS_CXXFLAGS)
tools_allocsites_SOURCES = tools/allocsites.cpp $(HELPERS)
tools_allocsites_LDADD = $(TOOLS_LDADD)
tools_allocsites_CXXFLAGS = $(TOOLS_CXXFLAGS)
tools_usedtypes_SOURCES = tools/usedtypes.cpp $(HELPERS)
tools_usedtypes_LDADD = $(TOOLS_LDADD)
tools_usedtypes_CXXFLAGS = $(TOOLS_CXXFLAGS)
tools_pervasive_types_SOURCES = tools/pervasive-types.cpp $(HELPERS)
tools_pervasive_types_LDADD = $(TOOLS_LDADD)
tools_pervasive_types_CXXFLAGS = $(TOOLS_CXXFLAGS)
# massive HACKs for ifacetypes
tools_ifacetypes_CXXFLAGS = $(AM_CXXFLAGS) -I$(libsystrap) -I$(librunt)
tools_ifacetypes_SOURCES = tools/ifacetypes.cpp $(HELPERS)
vpath %.c $(libsystrap)/../contrib/x86_emulate
x86_emulate.o: CFLAGS += -include $(libsystrap)/x86_defs.h
x86_emulate.o: .depbase
.depbase:
	mkdir -p "$@"
lib/interp-pad.o: tools/interp-pad.S
	$(CC) -c -o $@ $<
tools_ifacetypes_LDADD = $(TOOLS_LDADD) #x86_emulate.o
tools_find_allocated_type_size_SOURCES = tools/find-allocated-type-size.cpp $(HELPERS)
tools_find_allocated_type_size_LDADD = $(TOOLS_LDADD)
tools_find_allocated_type_size_CXXFLAGS = $(TOOLS_CXXFLAGS)

pkglib_LTLIBRARIES = tools/gold-plugin.la tools/libroottypes.la
tools_gold_plugin_la_SOURCES = tools/gold-plugin.cpp
tools_gold_plugin_la_CXXFLAGS = $(TOOLS_CXXFLAGS)
tools_gold_plugin_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
tools_gold_plugin_la_LIBADD = $(TOOLS_LDADD)

tools_libroottypes_la_SOURCES = tools/roottypes.c
tools_libroottypes_la_CFLAGS = $(LIBALLOCSTOOL_CFLAGS)

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
if SUPPLIED_LIBALLOCSTOOL_CFLAGS
LIBALLOCSTOOL_CXXFLAGS = $(USER_LIBALLOCSTOOL_CFLAGS)
else
LIBALLOCSTOOL_CXXFLAGS = $(LIBALLOCSTOOL_CFLAGS)
endif

LIBSYSTRAP = $(libsystrap)
LIBRUNT = $(librunt)
LIBMALLOCHOOKS = $(libmallochooks)
LIBDLBIND = $(libdlbind)
DONALD = $(donald)

export LIBCXXFILENO_CXXFLAGS LIBCXXFILENO_LIBS \
LIBSRK31CXX_CXXFLAGS LIBSRK31CXX_LIBS \
LIBDWARFPP_CXXFLAGS LIBDWARFPP_LIBS \
LIBCXXGEN_CXXFLAGS LIBCXXGEN_LIBS \
LIBANTLR3CXX_CXXFLAGS LIBANTLR3CXX_LIBS \
DWARFIDL_CXXFLAGS DWARFIDL_LIBS \
LIBALLOCSTOOL_CXXFLAGS LIBALLOCSTOOL_LIBS \
LIBSYSTRAP LIBRUNT LIBMALLOCHOOKS LIBDLBIND DONALD \
CC CXX CPP CXXFLAGS LDFLAGS LDLIBS

if DEBUG
export DEBUG = 1
endif
if USE_FAKE_LIBUNWIND
export USE_FAKE_LIBUNWIND = 1
endif
if LIFETIME_POLICIES
export LIFETIME_POLICIES = 1
endif

include libltdl/ltdl.mk

#tools/gold-plugin.so: $(lib_LTLIBRARIES)
#	echo "gold-plugin.so: creating convenience link from $(abs_builddir)/.libs to $(top_builddir)"; \
#            rm -f $(top_builddir)/tools/gold-plugin.so ; \
#            test -e $(abs_builddir)/tools/.libs/gold-plugin.so && \
#            cd $(top_builddir) && \
#            $(LN_S) $(abs_builddir)/tools/.libs/gold-plugin.so tools/gold-plugin.so || true

tools/libroottypes.a: tools/libroottypes.la
	cd $(top_builddir) && \
            $(LN_S) -f $(abs_builddir)/tools/.libs/libroottypes.a tools/libroottypes.a

tools/roottypes.c: tools/pervasive-types
	$< > $@ || (rm -f $@; false)

#all-am: tools/gold-plugin.so
all-am: tools/libroottypes.la tools/libroottypes.a

clean:
	$(MAKE) clean-recursive
	rm -f tools/gold-plugin.so

# dummy target for now
llvm:
