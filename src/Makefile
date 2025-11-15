THIS_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
LIBALLOCS := $(realpath $(dir $(THIS_MAKEFILE))/..)
SRCROOT := $(dir $(THIS_MAKEFILE))..
srcdir := $(SRCROOT)/src
include $(SRCROOT)/config.mk

CFLAGS += -D_FILE_OFFSET_BITS=64
CFLAGS += -DIN_LIBRUNT_DSO
CFLAGS += -DIN_LIBALLOCS_DSO
CFLAGS += -std=gnu11 -fPIC -Wall -g -I../include -I$(SRCROOT)/include -I$(LIBMALLOCHOOKS)/include \
   -I$(LIBSYSTRAP)/include -I$(LIBRUNT)/include -I$(DONALD)/src -I$(LIBDLBIND)/include -I$(srcdir) -Wno-unused
ifeq ($(DEBUG),)
CFLAGS += -flto -ffat-lto-objects
endif
LDFLAGS += -L$(LIBDLBIND)/lib

OBJCOPY ?= objcopy

# for debugging private malloc, try these
# ... remember that dlmalloc needs -DDEBUG for assertions to be enabled
# CFLAGS += -DTRACE_PRIVATE_MALLOC
# dlmalloc.o: CFLAGS += -DDEBUG

# run-from-srcdir case:
# if the current dir is the source dir, change to the output directory
# and re-invoke this makefile from there.
# If we don't know which output directory we want, we want the production one.
ifeq ($(realpath .),$(realpath $(srcdir)))
ifeq ($(MAKECMDGOALS),)
MAKECMDGOALS := default
endif
ifneq ($(TEST),)
outdir := test
else
ifneq ($(DEBUG),)
outdir := debug
else
outdir := opt
endif
endif
.PHONY: $(MAKECMDGOALS)
$(MAKECMDGOALS):
	mkdir -p $(SRCROOT)/build/$(outdir)
	$(MAKE) -C $(SRCROOT)/build/$(outdir) -f $(srcdir)/Makefile $(MAKECMDGOALS)
else
# the rest
vpath %.c $(srcdir)
vpath %.lds $(srcdir)
vpath %.lds.cpp $(srcdir)
vpath %.c $(srcdir)/allocators
vpath dlmalloc.c $(LIBSYSTRAP)/contrib

allocators/%.d allocators/%.o:: allocators
allocators:
	mkdir -p allocators

liballocs.so: $(srcdir)/liballocs.so
	cp $< $@

# if we're building from a dir called "debug" or "test"...
ifeq ($(notdir $(realpath .)),test)
DEBUG := 1
TEST := 1
else
ifeq ($(notdir $(realpath .)),debug)
DEBUG := 1
endif
endif

.PHONY: default
default: all # autotools likes an 'all' target (I think)

# What binaries do we build?
TARGETS += liballocs_preload.so    # the main binary
TARGETS += liballocs_preload.a     # in archive form, for extending libraries to link in (libcrunch)
TARGETS += liballocs.so            # nasty linker script for clients, working around uniqueness problem
                                   # FIXME: this has little reason to exist, although could perhaps
                                   # be repurposed as futzing with ld.so->allocsld.so (etc) if sane
TARGETS += liballocs.a             # the main binary usable for statically-linked client exes -- no uniqueness problem
TARGETS += liballocs_dummyweaks.so # non-client exes, that contain instrumented code, get -l this (but ideally would eliminate)
TARGETS += liballocs_dummyweaks.o  # non-client solibs, that contain instrumented code, get this linked in (i.e. avoiding a .so dependency; this is okay for solibs because LD_PRELOAD overrides them)
                                   # (what do client solibs get? easiest is just to treat them like exes, modulo non-overrideyness)

# Keep a list of all the linked binaries we produce
SOLIB_TARGETS := $(filter-out liballocs.so,$(filter %.so,$(TARGETS)))
#$(info SOLIB_TARGETS is $(SOLIB_TARGETS))

.PHONY: all
all: $(TARGETS)

ifneq ($(TEST),)
CFLAGS += -DTEST
endif
ifeq ($(DEBUG),)
    # FIXME: check this is still true: -O3 -DNDEBUG is the fastest, faster than -O4!
    CFLAGS += -O3 -DNDEBUG
    # Why do we use -Bsymbolic-functions? I think it was just for speed
    LDFLAGS += -Bsymbolic-functions
else
    CFLAGS += -O0
endif

# Tell make how to build .i and .s files, for debugging
%.i: %.c
	$(CC) -E -o $@ $(CPPFLAGS) $(CFLAGS) $<
%.s: %.i
	$(CC) -S -o $@ $(CPPFLAGS) $(CFLAGS) $<

# Don't use allocscc to compile liballocs!
# if CC is allocscc, unset it
ifeq ($(notdir $(CC)),allocscc)
$(warning Setting CC to cc, not allocscc)
export CC := cc
endif

# regardless of fast/non-fast CFLAGS, link with -Wl,-O2 -flto
# ARGH, disabling LTO for now
# owing to GCC bug 88643 and/or binutils (gold) bug 24415 (breakage of --wrap)
#LDFLAGS += -Wl,-O2 -flto
LDFLAGS += -fno-lto
LDFLAGS += -fPIC
# Try to cut down size of the .so file, given some of the libraries we link in (xed...)
LDFLAGS += -Wl,--gc-sections
# We need to use gold for now...
LDFLAGS += -fuse-ld=gold
# ... but why?
# XXX: I think one-DSO is going to need BFD?
#LDFLAGS += -fuse-ld=bfd
# NOTE that our use of __private_malloc, a defsym'd symbol,
# used to provoke a gold bug when we were generating protected-visibility
# undefineds that were bound to it. That gold bug has been reported (#24286) and
# I've removed the protected undefineds (which came from libmallochooks
# template code) so we can use gold regardless of whether that bug is fixed.
# At one time we ran into binutils bug 13600, forcing use of gold, but no longer?
# Our use of symbols defined in linker scripts (private-malloc-{plain,wrapped}.lds)
# requires that they generate global symbols. Gold does this but BFD doesn't!
# BFD can be forced to, using a --dynamic-list option... sigh.

# FIXME: if/when LTO is fixed, we can revert to using ld -r
# to create __next_hook_* aliases when composing malloc wrappers. For now we
# use the C preprocessor.
user2hook.o: CFLAGS += \
-D__next_hook_init=hook_init \
-D__next_hook_malloc=hook_malloc \
-D__next_hook_free=hook_free \
-D__next_hook_realloc=hook_realloc \
-D__next_hook_memalign=hook_memalign
hook2event.o: CFLAGS += -D'HOOK_PREFIX(s)=__terminal_hook_\#\#s' -D'ALLOC_EVENT(s)=__liballocs_malloc_\#\#s'
terminal-indirect-dlsym.o: CFLAGS += -Ddlsym_nomalloc=fake_dlsym
vpath user2hook.c $(LIBMALLOCHOOKS)/src
vpath hook2event.c $(LIBMALLOCHOOKS)/src
vpath terminal-indirect-dlsym.c $(LIBMALLOCHOOKS)/src
# HOOK_PREFIX computes the symbol names that the wrappers call. hook2event
# always generates hook_* and calls {*} u {event hook names}
user2hook.o: CFLAGS += -D'HOOK_PREFIX(s)=hook_\#\#s'
# MALLOC_PREFIX computes the symbol names that will get looked up by the terminal hooks
# -- we had this as __wrap___real_ because of the nonshared copy, but we also need the
# preload copy. Instead of a nonshared lib, we use the toolchain side (compiler wrapper,
# or rather ldplugin/toolsub) to add the instrumentation into the built DSO.
#terminal-indirect-dlsym.o: CFLAGS += -D'MALLOC_PREFIX(s)=__wrap___real_\#\#s'
MALLOCHOOKS_OBJS := user2hook.o hook2event.o terminal-indirect-dlsym.o
# NOTE: a version of these needs to get linked in to every
# output binary that defines a malloc... but with different
# ALLOC_EVENT mangling. This will be done in our toolchain stuff
# soon-ish.

ifneq ($(TRACE_HEAP_INDEX),)
CFLAGS += -DTRACE_HEAP_INDEX
#CFLAGS += -DTRACE_MALLOC_HOOKS
#CFLAGS += -DTRACE_DEEP_HEAP_INDEX
endif
CFLAGS += -I$(srcdir)

# different outputs involve different subgroups of objects
ALLOCSLD_OBJS := meta-dso.o err.o  # in one-DSO builds, these will be in allocsld.os already
# constraints of allocsld objs: must not use TLS, ...
# constraints of allocsld: must be free of UNDs? free of via-PLT calls?
CORE_OBJS := cache.o allocsites.o pageindex.o addrlist.o uniqtype-bfs.o \
  meta-dso-util.o uniqtype-util.o counters.o rt-uniqtypes.o util.o private-libc.o query.o walk.o \
  init.o workarounds.o $(filter-out user2hook.o,$(MALLOCHOOKS_OBJS)) \
  $(patsubst $(srcdir)/allocators/%.c,allocators/%.o,$(wildcard $(srcdir)/allocators/*.c))
ifeq ($(LIBALLOCS_ONE_DSO),)
CORE_OBJS += $(ALLOCSLD_OBJS)
endif
ifneq ($(USE_REAL_LIBUNWIND),)
LDLIBS += -lunwind -lunwind-`uname -m`
CFLAGS += -DUSE_REAL_LIBUNWIND
else
CORE_OBJS += fake-libunwind.o
CFLAGS += -fno-omit-frame-pointer
endif
NOPRELOAD_OBJS := #uniqtypes.o # never link this into a preload lib! nor include in _preload.a!
 # recall that liballocs.a is only for static-linked client binaries (exe or solib).
 # What should liballocs.a include? E.g. does a client static-linked exe need this
 # if it defines its own malloc?
PRELOAD_OBJS := preload.o user2hook.o ifunc.o # <-- ifunc.o is just for testing / proof-of-concept
ifneq ($(TEST),)
# We have a noop version of the systrap object, which
# used to be linked into liballocs_test.so because
# those tests didn't depend on systrapping working, and
# starting systrapping late (on dlopening the test lib)
# didn't work.
# BUT two things happened: we want to run tests that do
# depend on that, and now (tentatively) it seems we're
# robust enough to init systrap relatively late and not
# break horribly. So use the real systrap object.
# SYSTRAP_OBJS := systrap_noop.o
SYSTRAP_OBJS := systrap.o
else
SYSTRAP_OBJS := systrap.o
endif
DLMALLOC_OBJS := nommap-dlmalloc.o dlmalloc.o dlmalloc-ext.o nommap-dlmalloc-ext.o

# Generate deps.
ALL_OBJS := $(CORE_OBJS) $(NOPRELOAD_OBJS) $(PRELOAD_OBJS) $(SYSTRAP_OBJS) $(DLMALLOC_OBJS)
# enumerate src files backwards from our .o files
DEP_OBJS := $(filter-out nommap-%,$(ALL_OBJS))
C_SRC := $(sort $(patsubst %.o,%.c,$(DEP_OBJS)))
# Because of our vpath'd rules, we can't do patsubst on the source path to get the
# obj path... $< will be something wacky. Instead, work from the object file.
# All our objs are from C files, for now
C_OBJ_DEPS := $(foreach f,$(DEP_OBJS),$(patsubst %.o,%.d,$(f)))
DEPS := $(C_OBJ_DEPS)
#$(info C_OBJ_DEPS are $(C_OBJ_DEPS))
# ARGH. If we define a rule verbatim inside $(foreach ), it doesn't actually get
# defined. So we have to use eval.
define rule-for-depfile =
$(patsubst %.o,%.d,$(1)): $(patsubst %.o,%.c,$(1))
	mkdir -p $$(dir $$@) && $$(CC) -MM -MT $(1) $$(CPPFLAGS) $$(CFLAGS) "$$<" > "$$@" || (rm -f "$$@"; false)
endef
$(foreach f,$(DEP_OBJS),$(eval $(call rule-for-depfile,$(f))))
ifneq ($(MAKECMDGOALS),clean)
include $(DEPS)
endif

# Build using our special toolsub-based wrapper checks.
# Currently this checks we don't have any cases of missing/conflicting/ignored
# constructor priorities (see GCC bug  and my blog post:
# ).
$(ALL_OBJS): CFLAGS += -no-integrated-cpp \
-wrapper $(TOOLSUB)/wrapper/example/constructor-priority-checker/wrapper

# We include our own malloc impl, for which we use dlmalloc,
# of which libsystrap already has a copy in its source tree, so borrow that (HACK).
#
# We actually include two copies of dlmalloc:
# dlmalloc...        <-- uses mmap and not morecore
# nommap_dlmalloc... <-- uses morecore emulation, not mmap
# Each of these, we wrap so that we are meta-complete and have some uniformity
# across all malloc chunks in the program (we can reflect on all of them, identify
# the underlying malloc/free functions, etc).
vpath dlmalloc.c $(LIBSYSTRAP)/../src # HACK: actually in trap-syscalls but should be in libsystrap
dlmalloc.a: dlmalloc.o nommap-dlmalloc.o
dlmalloc.o:        CFLAGS += -include $(srcdir)/dlmalloc-includes.h -DHAVE_MMAP=1 -DHAVE_MORECORE=0 -DMSPACES=0                          -DUSE_DL_PREFIX -fPIC
nommap-dlmalloc.o: CFLAGS += -include $(srcdir)/dlmalloc-includes.h -DHAVE_MMAP=0 -DHAVE_MORECORE=1 -DMSPACES=1 -DMORECORE=emulated_sbrk -DUSE_DL_PREFIX -fPIC
nommap-dlmalloc-ext.o dlmalloc-ext.o: CFLAGS += -fPIC
nommap-dlmalloc-ext.o: CFLAGS += -DNOMMAP
# do the symbol renaming with objcopy, because the dl-prefixed symbols are not the only ones
nommap-dlmalloc.o: dlmalloc.c
	tmpo="$$(mktemp --suffix=.o)"; $(CC) $(CPPFLAGS) $(CFLAGS) -c -o "$$tmpo" $< && \
	tmpsymlist="$$(mktemp)" && nm -fposix --defined-only "$$tmpo" | tee /dev/stderr | sed -n '/^\([a-zA-Z0-9_\.]\+\).*/ {s//\1 nommap_\1/;p}' > "$$tmpsymlist" && \
	$(OBJCOPY) --redefine-syms "$$tmpsymlist" -R '.gnu.*lto_.*' "$$tmpo" "$@"; status=$$?; echo rm -f "$$tmpo" "$$tmpsymlist"; exit $$status
# ... we also strip LTO sections, i.e. don't risk that LTO will regenerate the old symbol names
# from IR definitions of the stuff we just renamed
nommap-dlmalloc-ext.o: dlmalloc-ext.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<
comma := ,
PRIVATE_MALLOC_WRAPPED_LDFLAGS := $(foreach s, \
  dlmalloc dlcalloc dlfree dlrealloc dlmemalign dlposix_memalign dlmalloc_usable_size,\
-Wl$(comma)--wrap$(comma)$(s) -Wl$(comma)--wrap$(comma)nommap_$(s))
# We put dlmalloc in a library so that --exclude-libs=dlmalloc.a will hide its symbols
# in our output .so, so that they don't override anything in the rest of the program.
# NOTE: __private_strdup is defined explicitly in private-libc.c and dummyweaks.c
# NOTE: we need to defsym to the __wrap_* functions, because of the way
# --wrap and --defsym interact: references generated by --defsym are *not*
# wrapped, unlike references that were in the file already.
PRIVATE_MALLOC_LDLIBS := -Wl,--whole-archive dlmalloc.a  -Wl,--no-whole-archive
# all our .so targets embed a dlmalloc, so tell 'make' that
$(SOLIB_TARGETS): dlmalloc.a
# HACKETY HACK: ld.gold seems to require we use the colon separator, and just give the filename
# not its fully qualified pathname
$(SOLIB_TARGETS): EXCLUDE_LIBS += dlmalloc.a:libsystrap.a
#$(SOLIB_TARGETS): LDFLAGS += -Wl,-z,initfirst

LIBALLOCS_PRELOAD_A_OBJS := dlmalloc-ext.o nommap-dlmalloc-ext.o $(CORE_OBJS) $(PRELOAD_OBJS)
LIBALLOCS_A_OBJS := $(SYSTRAP_OBJS) $(CORE_OBJS) $(NOPRELOAD_OBJS) $(PRELOAD_OBJS)

LIBSYSTRAP_A := $(LIBSYSTRAP)/build/$(shell uname -m)/libsystrap.a
liballocs_preload.so: LDFLAGS += $(PRIVATE_MALLOC_WRAPPED_LDFLAGS)
liballocs_preload.so: private-malloc-wrapped.lds
# XXX: see above: for BFD linker to work, we need --dynamic-list for these lds
# vpath allocsld.os $(srcdir)/../allocsld
ifneq ($(LIBALLOCS_ONE_DSO),)
allocsld.os: $(srcdir)/../allocsld/allocsld.os
	cp -p "$<" "$@"
liballocs_preload.so: allocsld.os
# XXX: can we be sure allocsld was built before we were? Yes,
# because SUBDIRS in Makefile.am puts us in this order.
allocsld.lds: CPPFLAGS += -include $(srcdir)/../allocsld/allocsld.h
allocsld.lds: allocsld.lds.cpp
	$(CC) -E -o $@ $< $(CPPFLAGS)
liballocs_preload.so: allocsld.lds
# we need to
# - rename the relocs section(s)  -- do this in allocsld Makefile
# - define a new symbol for each  -- in a linker script? there are *lots* of sections (.rela.*)
#       -- how do we prevent use of the PLT? PLT needs bootstrap relocation.
#          can we prevent use of the PLT? should be possible but tricky
# - put a new tag in .dynamic for each
# - put the DT_DEBUG in .dynamic as well
liballocs_preload.so: LDFLAGS += -Wl,-e,_start -Wl,--defsym,_begin=0
liballocs_preload.so: LDFLAGS += -Wl,--spare-dynamic-tags=4  # one for DT_DEBUG, three for bootstrap rela
# ------ end allocsld
endif
liballocs_preload.so: LDFLAGS += -Wl,-Map,liballocs_preload.so.map

liballocs_preload.so: LDLIBS += $(LIBDLBIND)/lib/libdlbind.a $(PRIVATE_MALLOC_LDLIBS) $(LIBSYSTRAP_A)
liballocs_preload.so liballocs_dummyweaks.so: LDLIBS += -lz -Wl,--no-as-needed -ldl $(LIBUNWIND_LDLIBS)
# also set the dependencies, for make purposes
liballocs_preload.so: $(LIBDLBIND)/lib/libdlbind.a $(LIBSYSTRAP_A) # anything that goes in ldlibs should be a dependency
liballocs_preload.so: LDLIBS += -lpthread

# FIXME: this is supposed to obsolete liballocs_test.so and tests/lib-test
# ... but I'm not sure it can. Some unit tests need to run within a wider liballocs
# (i.e. they are not really unit tests per se...).
# What's the right way to do smaller-unit tests of liballocs internals?
# i.e. code that links against those internals, rather than simple
# instrumented code that is built using the toolchain? The liballocs_test approach
# simply runs test sfrom the constructor... e.g. in allocators/mmap.c there is
# test code. Perhaps we really want a 'test' build, sibling of 'debug' and 'opt'
# builds, which 
liballocs_preload.so-test-%: LDFLAGS += $(PRIVATE_MALLOC_WRAPPED_LDFLAGS)
liballocs_preload.so-test-%: LDLIBS += -ldlbind $(PRIVATE_MALLOC_LDLIBS) $(LIBSYSTRAP_A) -lz -Wl,--no-as-needed -ldl $(LIBUNWIND_LDLIBS)
liballocs_preload.so-test-%.c.test: %.c $(filter-out %.o,$(SYSTRAP_OBJS) $(LIBALLOCS_PRELOAD_A_OBJS)) dlmalloc.a
	$(CC) $(CFLAGS) $(CPPFLAGS) -DUNIT_TEST -o "$@" $(filter-out dlmalloc.a,$+) $(LDFLAGS) $(LDLIBS)
vpath %.h $(SRCROOT)/include
liballocs_preload.so-test-%.h.test: %.h $(SYSTRAP_OBJS) $(LIBALLOCS_PRELOAD_A_OBJS) dlmalloc.a
	$(CC) $(CFLAGS) $(CPPFLAGS) -DUNIT_TEST -o "$@" $(filter-out dlmalloc.a $<,$+) -x c $< -x none $(LDFLAGS) $(LDLIBS)

RUNT_LDFLAGS := -Wl,--wrap,__runt_files_notify_load \
-Wl,--wrap,__runt_files_notify_unload \
-Wl,--wrap,__runt_files_metadata_by_addr \
-Wl,--wrap,__runt_segments_notify_define_segment \
-Wl,--wrap,__runt_segments_notify_destroy_segment \
-Wl,--wrap,__runt_sections_notify_define_section # there is no 'destroy section'
# if we don't do --whole-archive, then the wrapping of __runt_* doesn't work...
# ... though with a behaviour that makes no sense: librunt still calls itself rather
# than its wrapper __static_file_allocator notify_load.
LIBRUNT_BUILD_DIR := $(LIBRUNT)/build/$(if $(DEBUG),debug,opt)-$(shell uname -m)
LIBRUNT_A := $(LIBRUNT_BUILD_DIR)/librunt_preload.a
RUNT_LDLIBS := -Wl,--whole-archive $(LIBRUNT_A) -Wl,--no-whole-archive
liballocs_preload.so: LDFLAGS += $(RUNT_LDFLAGS) -Wl,-O0
liballocs_preload.so: LDLIBS += $(RUNT_LDLIBS)
# dependency for make
liballocs_preload.so: $(LIBRUNT_A)

DYNAPPEND ?= $(ELFTIN)/dynappend/dynappend
OBJCOPY ?= objcopy
# liballocs_preload.so build rule is funky because dlmalloc.a is in LDFLAGS.
# It needs to be there because it goes inside --whole-archive (and these options
# are not files, so can't be prerequisites expanded by $+)
# It is even more funky with allocsld.os, because we need to fill in the
# custom .dynamic entries.
ifneq ($(LIBALLOCS_ONE_DSO),)
define liballocs_so_post_build_commands
$(DYNAPPEND) $@ $$( printf "%d\n" $(DT_ALLOCS_BOOTSTRAP_RELA) ) "$$( $(OBJCOPY) -Obinary \
	  -j.bootstrap_dynamic "$@" /dev/stdout | \
	  tail -c+9 | head -c8 | od -td8 | tr -s '[:blank:]' '\t' | cut -f2 | head -n1 )" && \
	$(DYNAPPEND) $@ $$( printf "%d\n" $(DT_ALLOCS_BOOTSTRAP_RELASZ) ) "$$( $(OBJCOPY) -Obinary \
	  -j.bootstrap_dynamic "$@" /dev/stdout | \
	  tail -c+25 | head -c8 | od -td8 | tr -s '[:blank:]' '\t' | cut -f2 | head -n1 )" && \
	$(DYNAPPEND) $@ $$( printf "%d\n" $(DT_ALLOCS_BOOTSTRAP_RELAENT) ) "$$( $(OBJCOPY) -Obinary \
	  -j.bootstrap_dynamic "$@" /dev/stdout | \
	  tail -c+41 | head -c8 | od -td8 | tr -s '[:blank:]' '\t' | cut -f2 | head -n1 )" && \
	$(DYNAPPEND) "$@" 21 0 `echo this is DT_DEBUG >/dev/null` \
	  || (rm -f "$@"; false)
endef
else
define liballocs_so_post_build_commands
true
endef
endif
liballocs_preload.so: $(SYSTRAP_OBJS) $(LIBALLOCS_PRELOAD_A_OBJS) dlmalloc.a
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out $(LDLIBS) dlmalloc.a,$+) \
                $(LDFLAGS) $(LDLIBS) -Wl,--exclude-libs="$(EXCLUDE_LIBS)" && \
        $(liballocs_so_post_build_commands)
%.a:
	$(AR) r "$@" $+
liballocs_preload.a: $(LIBALLOCS_PRELOAD_A_OBJS)
liballocs.a: $(LIBALLOCS_A_OBJS)

ifeq ($(USE_FAKE_LIBUNWIND),)
FAKE_LIBUNWIND_OBJ :=
LIBUNWIND_LDLIBS := -lunwind -lunwind-$(shell uname -m)
else
FAKE_LIBUNWIND_OBJ := fake-libunwind.o
CFLAGS += -fno-omit-frame-pointer
LIBUNWIND_LDLIBS :=
endif

ifeq ($(LIFETIME_POLICIES),)
LIFETIME_EXT_OBJ :=
else
LIFETIME_EXT_OBJ := lifetime_policies.o
endif

ifneq ($(TRACE_HEAP_INDEX),)
CFLAGS += -DTRACE_HEAP_INDEX
endif

# HACK: would ideally eliminate "dummyweaks" shared object if ld provided a "--dt-useful" option
# or if we could statically link-in our stubs without making them non-overridable.
# Perhaps the custom ld.so will make this feasible.
liballocs_dummyweaks.o: dummyweaks.o
	$(LD) -r -o "$@" $+
# Because our dummyweaks also includes private_strdup, it brings in a whole private malloc.
# FIXME: it shouldn't. But unclear how else to satisfy the dependency on __private_strdup
# in libcrunch's _stubs.so.
vpath librunt_%.o $(LIBRUNT_BUILD_DIR)
liballocs_dummyweaks.so: private-malloc-plain.lds
# XXX: see above: for BFD linker to work, we need --dynamic-list for these lds
liballocs_dummyweaks.so: LDLIBS += $(PRIVATE_MALLOC_LDLIBS)
liballocs_dummyweaks.so: dummyweaks.o librunt_dummyweaks.o
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out dlmalloc.a,$+) $(LDFLAGS) $(LDLIBS)  -Wl,--exclude-libs="$(EXCLUDE_LIBS)"

# Instead of a nomemtable build (for Valgrinding)
# can we just arrange that on a nomemtable *execution*,
# pageindex points to a large non-canonical address range
# and we handle the fault in our fault handler (Valgrind
# does honour user-supplied segfault handlers, apparently)

# liballocs.so is a linker script, so don't remove it
.PHONY: clean
clean: 
	rm -f *.o */*.o $(filter-out liballocs.so,$(wildcard *.so)) *.d */*.d *.a *_fast.c
	rm -r allocators

.PHONY: install
install: all
	${INSTALL} liballocs_preload.so $(srcdir)/liballocs.so liballocs_dummyweaks.so ${libdir}
	${INSTALL_DATA} liballocs_preload.a liballocs.a liballocs_dummyweaks.o ${libdir}

vpath %.h $(srcdir)/%.h

# unit test pattern for C:
# 1. Any source file (.c or .h) may contain a unit-test main(), #ifdef-guarded by UNIT_TEST
# 2. It may link with "the rest of the binary". What does that mean?
#     -- for %.c, we do a normal build of liballocs_preload.so, but filter-out %.o and
#liballocs_preload.so-test-%.c: %.c $(filter-out $(patsubst %.o,%.c,$*.c),$(ALL_OBJS))
# HM. We used to say "put the tests in constructors, and run by dlopening the _test.so or just firing up a debug build"
# What's good or bad about this?
# Good: we don't do a separate build of each .o file, so the tests remain in any non-NDEBUG build.
# Bad: we don't test optimised code, unless we do a non-NDEBUG-but-optimised build.
# Bad-ish: we don't currently run this very frequently, but we have to adjust habits either way.
# Bad-ish: we can't supply arguments to a test case... but do we want to? No, probably.
# Bad-ish: Any debug build will run the tests before doing anything else, so tests can't be long-running (that would be annoying).
# What about our new way of building one executable per test?
# Bad: If a failing test should be signposted by an assertion failure in another module,
#   we won't see that because they were probably -DNDEBUG.
# Bad: running tests means extra compilation, but
# Unclear: we can have debug builds that execute without running tests (good or bad?), and
# Good-ish: we can have long-running tests (desirable?), and
# Good: we can have tests even for .h files  (there is exactly one test entry point per linked executable; called main()) and
# Good: tests can themselves have "debug builds" i.e. the rest of the linked in stuff is the debug build
# Bad: complicates this makefile (see how it turns out...)
# Good/bad: our tests are not true unit tests, because they integrate with the wider library
# (i.e. they use no stubs/mocks)

endif # test for run-from-srcdir
