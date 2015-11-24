ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . tools/lang src

AM_CXXFLAGS = -std=c++11 -ggdb -O0 -Wall -Wno-deprecated-declarations -fPIC -Wp,-w -Iinclude $(LIBSRK31CXX_CFLAGS) $(LIBCXXFILENO_CFLAGS) $(LIBDWARFPP_CFLAGS) $(LIBCXXGEN_CFLAGS) $(DWARFIDL_CFLAGS)
CXXFLAGS += $(AM_CXXFLAGS)

AM_CFLAGS = -Wall -std=gnu99 -ggdb -O0 -Iinclude -fPIC -Wp,-w
CFLAGS += $(AM_CFLAGS)

AM_LDFLAGS = -Wl,--no-as-needed -lstdc++ -lm -lboost_regex $(DWARFIDL_LIBS) $(LIBCXXGEN_LIBS) $(LIBDWARFPP_LIBS) $(LIBSRK31CXX_LIBS) $(LIBCXXFILENO_LIBS) 

extra_DIST = liballocs.pc.in
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = liballocs.pc

liballocs_includedir = $(includedir)/liballocs
liballocs_include_HEADERS = include/heap_index.h include/malloc_usable_size_hack.h include/liballocs.h include/uniqtype-bfs.h include/liballocs_cil_inlines.h include/relf.h include/addrmap.h include/uniqtype.h include/memtable.h include/fake-libunwind.h include/allocsmt.h

#lib_LTLIBRARIES = src/libdwarfidl.la
#src_libdwarfidl_la_SOURCES = src/cxx_model.cpp src/dwarfidl_cxx_target.cpp src/dwarf_interface_walk.cpp src/create.cpp src/lang.cpp src/print.cpp parser/dwarfidlSimpleCLexer.c parser/dwarfidlSimpleCParser.c
#src_libdwarfidl_la_LIBADD = -lantlr3c -lboost_filesystem -lboost_regex -lboost_system -lboost_serialization $(LIBSRK31CXX_LIBS) $(LIBCXXFILENO_LIBS) $(LIBANTLR3CXX_LIBS) $(LIBDWARFPP_LIBS) $(LIBCXXGEN_LIBS)

bin_PROGRAMS = tools/dumptypes tools/allocsites tools/usedtypes tools/ifacetypes tools/find-allocated-type-size
lib_LIBRARIES = tools/liballocstool.a 

tools_liballocstool_a_SOURCES = tools/helpers.cpp tools/uniqtypes.cpp

tools_dumptypes_SOURCES = tools/dumptypes.cpp
tools_dumptypes_LDADD = tools/liballocstool.a
tools_allocsites_SOURCES = tools/allocsites.cpp $(HELPERS)
tools_allocsites_LDADD = tools/liballocstool.a
tools_usedtypes_SOURCES = tools/usedtypes.cpp $(HELPERS)
tools_usedtypes_LDADD = tools/liballocstool.a
tools_ifacetypes_SOURCES = tools/ifacetypes.cpp $(HELPERS)
tools_ifacetypes_LDADD = tools/liballocstool.a
tools_find_allocated_type_size_SOURCES = tools/find-allocated-type-size.cpp $(HELPERS)
tools_find_allocated_type_size_LDADD = tools/liballocstool.a

# lib_LIBRARIES = src/liballocs_preload.so src/liballocs_nonshared.a src/liballocs_noop.so src/liballocs_noop.a src/liballocs_noop.o src/liballocs.a

# SOURCES = src/addrlist.c src/addrmap.c src/event_hooks_fast.c src/heap_index_hooks_fast.c l0index.c src/liballocs.c src/liballocs_nomemtable.c src/malloc_hook_stubs_preload_fast.c src/malloc_hook_stubs_wrap_fast.c src/maps.c src/preload.c src/uniqtype-bfs.c src/uniqtypes.c

# if DEBUG
#     DEFAULT_EXTRA_CFLAGS := -g
# else
# # STRANGE: this
# #DEFAULT_EXTRA_CFLAGS := -flto -O4 # note! no -DNDEBUG
# # is slower than the following (4.61, 4.54, 4.60)
# #DEFAULT_EXTRA_CFLAGS := -O0 -finline-functions
# # ; what about this? it's the same or slightly slower
# #DEFAULT_EXTRA_CFLAGS := -O4 -flto -finline-functions -DNDEBUG
# # what about this one? makes little difference
# #DEFAULT_EXTRA_CFLAGS := -O4 -flto -DNDEBUG
# # what about this one? same or slightly slower
# #DEFAULT_EXTRA_CFLAGS := -Os -flto -DNDEBUG
# # what about this one? slightly faster
# #DEFAULT_EXTRA_CFLAGS := -O0 -DNDEBUG
# # what about this one?  among the fastest (4.52, 4.50, 4.51)
# #DEFAULT_EXTRA_CFLAGS := -O3 -DNDEBUG
# # really double-check that the following isn't faster? nope (4.64, 4.64, 4.59)
# #DEFAULT_EXTRA_CFLAGS := -O4 -flto -DNDEBUG
# # Summary of the above: -O3 -DNDEBUG is the fastest
#     FAST_EXTRA_CFLAGS := -O3 -DNDEBUG
#     DEBUG_EXTRA_CFLAGS := -O0
# endif

# if USE_REAL_LIBUNWIND
#     FAKE_UNWIND_OBJ :=
#     LIBUNWIND_LDLIBS := -lunwind -lunwind-`uname -m` 
#     CFLAGS += -DUSE_REAL_LIBUNWIND
# else
#     FAKE_LIBUNWIND_OBJ := src/fake-libunwind.o
#     CFLAGS += -fno-omit-frame-pointer
#     LIBUNWIND_LDLIBS :=
# endif

# HOOKS_PRELOAD_OBJS := src/heap_index_hooks_fast.o src/malloc_hook_stubs_preload_fast.o src/event_hooks_fast.o
# HOOKS_WRAP_OBJS := src/heap_index_hooks_fast.o src/malloc_hook_stubs_wrap_fast.o src/event_hooks_fast.o
# UTIL_OBJS := src/l0index.o src/maps.o src/addrmap.o src/addrlist.o src/uniqtypes.o src/uniqtype-bfs.o
# MAIN_OBJS := src/liballocs.o $(UTIL_OBJS) $(FAKE_UNWIND_OBJ)
# MAIN_OBJS_NOMEMTABLE := src/liballocs_nomemtable.o $(UTIL_OBJS)
# PRELOAD_OBJS := src/preload.o


# HOOKS_NON_FAST_CFLAGS = -fPIC -DTRACE_MALLOC_HOOKS -DTRACE_HEAP_INDEX #-DTRACE_DEEP_HEAP_INDEX
# HOOKS_FAST_CFLAGS = -fpic -flto -ffat-lto-objects
# if DEBUG
#     HOOKS_FAST_CFLAGS += -O4 -DNDEBUG
# endif

# src/heap_index_hooks_fast.o: CFLAGS += $(HOOKS_FAST_CFLAGS)
# src/heap_index_hooks.o: CFLAGS += $(HOOKS_NON_FAST_CFLAGS)
# src/event_hooks_fast.o: CFLAGS += $(HOOKS_FAST_CFLAGS)
# src/event_hooks.o: CFLAGS += $(HOOKS_NON_FAST_CFLAGS)

# src/liballocs_preload.o: LDFLAGS += -Wl,--wrap,malloc_usable_size

# # What libraries do we build?
# # 
# # liballocs_preload.so -- the main binary
# # liballocs_preload.a  -- in archive form, for extending libraries to link in (libcrunch)
# # liballocs.so         -- nasty linker script for clients, working around uniqueness problem
# # liballocs_nonshared.a -- just uniqtypes; linker script points to this, s.t. client exes (-lallocs) get this linked in statically (uniqtypes)
# # liballocs.a          -- the main binary usable for statically-linked exes -- no uniqueness problem
# # liballocs_noop.so     -- non-client exes, that contain instrumented code, get -l this (but ideally would eliminate)
# # liballocs_noop.a      -- in archive form, for extending noop libraries to link in (libcrunch_noop)
# # liballocs_noop.o      -- non-client solibs, that contain instrumented code, get this linked in (i.e. avoiding a .so dependency; this is okay for solibs because LD_PRELOAD overrides them)
# #
# # What do client solibs get?
# # Easiest is just to treat them like exes. They will get their own copy 
# # of the basic uniqtypes, but this will get uniqued as appropriate.

# src/%_fast.o: src/%.c
# 	$(CC) $(CFLAGS) -c -o "$@" "$<"

# if DEBUG
#     $(MAIN_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ): CFLAGS += -fPIC $(DEBUG_EXTRA_CFLAGS) # hooks have either fpic or fPIC
# else
#     $(MAIN_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ): CFLAGS += -fPIC $(FAST_EXTRA_CFLAGS) # hooks have either fpic or fPIC
# endif

# src/uniqtypes.o: src/uniqtypes.c
# 	$(CC) -o "$@" $(filter-out -flto,$(CFLAGS)) -c "$<" && \
# 	$(LIBALLOCS_BASE)/tools/lang/c/bin/link-used-types "$@" || (rm -f "$@"; false)

# src/liballocs_preload.so: src/liballocs_preload.a
# 	$(CC) $(CFLAGS) -shared -o "$@" -Wl,--whole-archive "$<" -Wl,--no-whole-archive $(LDFLAGS) -ldl $(LIBUNWIND_LDLIBS)

# src/liballocs_preload.a: $(MAIN_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ) $(HOOKS_PRELOAD_OBJS)
# 	$(AR) r "$@" $+

# src/liballocs_nonshared.a: src/uniqtypes.o
# 	$(AR) r "$@" $+

# src/liballocs.a: $(MAIN_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ) $(HOOKS_WRAP_OBJS)
# 	$(AR) r "$@" $+

# ## What's going on here?
# ## We have a __wrap_malloc_usable_size in our preload, and normally we alias it
# ## to the main one too. Here we strip that alias, to avoid multiple definitions.
# ## WHY is malloc_usable_size special? Perhaps because it's in preload.o, whereas
# ## our other wrappers (like malloc) are in the malloc hooks... have we excluded
# ## them here?
# #preload-wrap.o: preload.o
# #	objcopy --strip-symbol malloc_usable_size "$<" "$@"
# #
# #liballocs_exe.a: $(MAIN_OBJS) preload-wrap.o $(FAKE_LIBUNWIND_OBJ) $(HOOKS_WRAP_OBJS)
# #	rm -f "$@" && ar r "$@" $+ 

# src/noop.o: CFLAGS += -fPIC 
# src/liballocs_noop.o: src/noop.o
# 	ln -s "$<" "$@"

# src/liballocs_noop.a: src/noop.o
# 	$(AR) r "$@" $+

# src/liballocs_noop.so: src/noop.o
# 	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS)

# # this version lacks preload stuff
# #liballocs.a: $(MAIN_OBJS) $(FAKE_LIBUNWIND_OBJ) $(filter-out malloc%,$(HOOKS_PRELOAD_OBJS))
# #	ar r "$@" $+


# src/libdumpsmaps.so: src/libdumpsmaps.o
# 	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out %hooks.a,$^) $(LDFLAGS) 

# src/liballocs_nomemtable_preload.so: $(MAIN_OBJS_NOMEMTABLE) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ) src/dummy_thread_locals.o
# 	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out %hooks.a,$^) $(LDFLAGS) -ldl $(LIBUNWIND_LDLIBS)

# src/liballocs_nomemtable.o: src/liballocs.c
# 	$(CC) $(CFLAGS) -DNO_MEMTABLE -c -o "$@" "$<" 

export 
# was export INSTALL INSTALL_DATA libdir

