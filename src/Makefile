THIS_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
LIBALLOCS := $(realpath $(dir $(THIS_MAKEFILE))/..)
SRCROOT := $(dir $(THIS_MAKEFILE))../
srcdir := $(SRCROOT)/src
include $(SRCROOT)/config.mk

CFLAGS += -DIN_LIBRUNT_DSO
CFLAGS += -std=gnu11 -fPIC -Wall -g -I../include -I$(SRCROOT)/include -I$(LIBMALLOCHOOKS) \
   -I$(LIBSYSTRAP)/include -I$(LIBRUNT)/include -I$(LIBDLBIND)/include -I$(srcdir) -Wno-unused \
   $(LIBALLOCSTOOL_CFLAGS)
ifeq ($(DEBUG),)
CFLAGS += -flto -ffat-lto-objects
endif
LDFLAGS += -L$(LIBDLBIND)/lib

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
TARGETS += liballocs_nonshared.a   # uniqtypes and (own-malloc) allocator stubs; linker script points to this, s.t. client exes (-lallocs) get this linked in statically
TARGETS += liballocs.a             # the main binary usable for statically-linked client exes -- no uniqueness problem
TARGETS += liballocs_dummyweaks.so # non-client exes, that contain instrumented code, get -l this (but ideally would eliminate)
TARGETS += liballocs_dummyweaks.o  # non-client solibs, that contain instrumented code, get this linked in (i.e. avoiding a .so dependency; this is okay for solibs because LD_PRELOAD overrides them)
                                   # (what do client solibs get? easiest is just to treat them like exes, *except* I *think* they don't get nonshared_hooks.o)

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
export CC := cc
endif

# regardless of fast/non-fast CFLAGS, link with -Wl,-O2 -flto
# ARGH, disabling LTO for now
# owing to GCC bug 88643 and/or binutils (gold) bug 24415 (breakage of --wrap)
#LDFLAGS += -Wl,-O2 -flto
LDFLAGS += -fno-lto
LDFLAGS += -fPIC 
# until binutils bug 13600 is fixed, gold is the linker we need
# (FIXME: why? where was the bogus relocation causing problems?)
LDFLAGS += -fuse-ld=gold
# NOTE that our use of __private_malloc, a defsym'd symbol,
# used to provoke a gold bug when we were generating protected-visibility
# undefineds that were bound to it. That bug has been reported (#24286) and
# I've removed the protected undefineds (which came from libmallochooks
# template code). So we are still committed to using gold to link liballocs
# owing to binutils issue 13600 is fixed.

export BUILD_MALLOC_HOOKS := event
# FIXME: if/when LTO is fixed, we can revert to using ld -r
# to create __next_hook_* aliases when composing malloc wrappers. For now we
# use the C preprocessor.
event_hooks.o event_hooks_nonshared.o: CFLAGS += \
-D__next_hook_init=__terminal_hook_init \
-D__next_hook_malloc=__terminal_hook_malloc \
-D__next_hook_free=__terminal_hook_free \
-D__next_hook_realloc=__terminal_hook_realloc \
-D__next_hook_memalign=__terminal_hook_memalign 
# GRR. We can't include the Makerules now that we need to build the hooks by 
# two different methods. Also, we can't get dependency information about these
# files from the makefiles. So we always want to run these rules. HMM.
vpath malloc_hook_stubs_wrap.c $(LIBMALLOCHOOKS)
vpath malloc_hook_stubs_preload.c $(LIBMALLOCHOOKS)
vpath event_hooks.c $(LIBMALLOCHOOKS)

ifneq ($(TRACE_HEAP_INDEX),)
CFLAGS += -DTRACE_HEAP_INDEX
#CFLAGS += -DTRACE_MALLOC_HOOKS
#CFLAGS += -DTRACE_DEEP_HEAP_INDEX
endif
CFLAGS += -I$(srcdir)

# different outputs involve different subgroups of objects
UTIL_OBJS := cache.o allocsites.o pageindex.o addrlist.o uniqtype-bfs.o
ifneq ($(USE_REAL_LIBUNWIND),)
LDLIBS += -lunwind -lunwind-`uname -m`
CFLAGS += -DUSE_REAL_LIBUNWIND
else
UTIL_OBJS += fake-libunwind.o
CFLAGS += -fno-omit-frame-pointer
endif
ALLOCATOR_OBJS := $(patsubst $(srcdir)/allocators/%.c,allocators/%.o,$(wildcard $(srcdir)/allocators/*.c))
#$(info ALLOCATORS_OBJS is $(ALLOCATOR_OBJS))
MAIN_OBJS := liballocs.o event_hooks.o $(UTIL_OBJS) $(ALLOCATOR_OBJS)
HOOKS_WRAP_OBJS := malloc_hook_stubs_wrap.o
NOPRELOAD_OBJS := #uniqtypes.o # never link this into a preload lib! nor include in _preload.a!
NONSHARED_OBJS := nonshared_hooks.o # does *not* go in liballocs.a -- FIXME: why not? recall that liballocs.a is only for static-linked client binaries (exe or solib). Otherwise we get _nonshared.a, from the liballocs.so linker script. Probably, liballocs.a should include this, e.g. a client static-linked exe needs this if it defines its own malloc.
PRELOAD_OBJS := preload.o malloc_hook_stubs_preload.o
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

# Generate deps.
ALL_OBJS := $(MAIN_OBJS) $(NOPRELOAD_OBJS) $(NONSHARED_OBJS) $(PRELOAD_OBJS) $(HOOKS_WRAP_OBJS) $(SYSTRAP_OBJS)
# enumerate src files backwards from our .o files
# -- HACK: nonshared_hooks.o is not built from .c source
DEP_OBJS := $(filter-out $(NONSHARED_OBJS),$(ALL_OBJS))
C_SRC := $(sort $(patsubst %.o,%.c,$(DEP_OBJS)))
# Becuase of our vpath'd rules, we can't do patsubst on the source path to get the
# obj path... $< will be something wacky. Instead, work from the object file.
# All our objs are from C files, for now
C_OBJ_DEPS := $(foreach f,$(DEP_OBJS),$(patsubst %.o,%.d,$(f)))
DEPS := $(C_OBJ_DEPS)
#$(info C_OBJ_DEPS are $(C_OBJ_DEPS))
# ARGH. If we define a rule verbatim inside $(foreach ), it doesn't actually get
# defined. So we have to use eval.
define rule-for-depfile =
$(patsubst %.o,%.d,$(1)): $(patsubst %.o,%.c,$(1))
	mkdir -p $$(dir $$@) && $$(CC) -MM -MT $(1) $$(CFLAGS) "$$<" > "$$@" || (rm -f "$$@"; false)
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

# event_hooks.c is macroised so that we can create special versions of it.
# This version is used when we link an executable including its own malloc impl.
# FIXME: this should be made more uniform, as part of the allocator/stub-generation refactoring.
event_hooks_nonshared.o: CFLAGS += -D'ALLOC_EVENT(s)=__liballocs_malloc_\#\#s' -DALLOC_EVENT_ATTRIBUTES=
event_hooks_nonshared.o: event_hooks.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o "$@" $+
nonshared_hooks.o: event_hooks_nonshared.o nonshared_hook_wrappers.o
	$(LD) -r -o "$@" $+

# we include our own malloc impl, for which we use dlmalloc
# of which libsystrap already has a copy, so borrow that (HACK)
vpath dlmalloc.c $(LIBSYSTRAP)/../src # HACK: actually in trap-syscalls but should be in libsystrap
dlmalloc.a: dlmalloc.o
dlmalloc.o: CFLAGS += -DHAVE_MORECORE=0 -DUSE_DL_PREFIX -fPIC
dlmalloc-ext.o: CFLAGS += -fPIC
# FIXME: instead of these ldflags,
# write a ldscript and include it on the command line.
# This should let us make the defined symbols .hidden or .internal, whereas
# currently these 'private' symbols have public visibility
PRIVATE_MALLOC_WRAPPED_LDFLAGS := -Wl,--wrap,dlmalloc -Wl,--wrap,dlcalloc \
 -Wl,--wrap,dlfree -Wl,--wrap,dlrealloc -Wl,--wrap,dlmemalign -Wl,--wrap,dlposix_memalign \
 -Wl,--defsym,__private_malloc=__wrap_dlmalloc \
 -Wl,--defsym,__private_calloc=__wrap_dlcalloc \
 -Wl,--defsym,__private_free=__wrap_dlfree \
 -Wl,--defsym,__private_realloc=__wrap_dlrealloc \
 -Wl,--defsym,__private_memalign=__wrap_dlmemalign \
 -Wl,--defsym,__private_posix_memalign=__wrap_dlposix_memalign \
 -Wl,--defsym,__real_dlmalloc_usable_size=dlmalloc_usable_size
# FIXME: document this ^^^ hack for malloc_usable_size... can't remember why it's needed.
# Is it simply because we don't wrap it? in libmallochooks?
PRIVATE_MALLOC_PLAIN_LDFLAGS := -Wl,--defsym,__private_malloc=dlmalloc \
 -Wl,--defsym,__private_calloc=dlcalloc \
 -Wl,--defsym,__private_free=dlfree \
 -Wl,--defsym,__private_realloc=dlrealloc \
 -Wl,--defsym,__private_memalign=dlmemalign \
 -Wl,--defsym,__private_posix_memalign=dlposix_memalign
# We put dlmalloc in a library so that --exclude-libs=dlmalloc.a will hide its symbols
# in our output .so, so that they don't override anything in the rest of the program.
# NOTE: __private_strdup is defined explicitly in liballocs.c and dummyweaks.c
# NOTE: we need to defsym to the __wrap_* functions, because of the way
# --wrap and --defsym interact: references generated by --defsym are *not*
# wrapped, unlike references that were in the file already.
PRIVATE_MALLOC_LDLIBS := -Wl,--whole-archive dlmalloc.a  -Wl,--no-whole-archive
# all our .so targets embed a dlmalloc, so tell 'make' that
$(SOLIB_TARGETS): dlmalloc.a
# HACKETY HACK: ld.gold seems to require we use the colon separator, and just give the filename
# not its fully qualified pathname
$(SOLIB_TARGETS): EXCLUDE_LIBS += dlmalloc.a:libsystrap.a

LIBALLOCS_PRELOAD_A_OBJS := dlmalloc-ext.o $(MAIN_OBJS) $(PRELOAD_OBJS)
LIBALLOCS_NONSHARED_A_OBJS := $(NOPRELOAD_OBJS) $(NONSHARED_OBJS)
LIBALLOCS_A_OBJS := $(SYSTRAP_OBJS) $(MAIN_OBJS) $(NOPRELOAD_OBJS) $(PRELOAD_OBJS) $(HOOKS_WRAP_OBJS)

liballocs_preload.so: LDFLAGS += -Wl,--wrap,malloc_usable_size $(PRIVATE_MALLOC_WRAPPED_LDFLAGS)
liballocs_preload.so: LDFLAGS += -Wl,-Map,liballocs_preload.so.map
liballocs_preload.so: LDLIBS += $(LIBDLBIND)/lib/libdlbind.a $(PRIVATE_MALLOC_LDLIBS) $(LIBSYSTRAP)/lib/libsystrap.a
liballocs_preload.so liballocs_dummyweaks.so: LDLIBS += -lz -Wl,--no-as-needed -ldl $(LIBUNWIND_LDLIBS)
# also set the dependencies, for make purposes
liballocs_preload.so: $(LIBDLBIND)/lib/libdlbind.a $(LIBSYSTRAP)/lib/libsystrap.a # anything that goes in ldlibs should be a dependency

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
liballocs_preload.so-test-%: LDLIBS += -ldlbind $(PRIVATE_MALLOC_LDLIBS) $(LIBSYSTRAP)/lib/libsystrap.a -lz -Wl,--no-as-needed -ldl $(LIBUNWIND_LDLIBS)
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
RUNT_LDLIBS := -Wl,--whole-archive $(LIBRUNT)/lib/librunt_preload.a -Wl,--no-whole-archive
liballocs_preload.so: LDFLAGS += $(RUNT_LDFLAGS) -Wl,-O0
liballocs_preload.so: LDLIBS += $(RUNT_LDLIBS)
# dependency for make
liballocs_preload.so: $(LIBRUNT)/lib/librunt_preload.a

# liballocs_preload.so build rule is funky because dlmalloc.a is in LDFLAGS.
# It needs to be there because it goes inside --whole-archive (and these options
# are not files, so can't be prerequisites expanded by $+)
liballocs_preload.so: $(SYSTRAP_OBJS) $(LIBALLOCS_PRELOAD_A_OBJS) dlmalloc.a
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out $(LDLIBS) dlmalloc.a,$+) $(LDFLAGS) $(LDLIBS) -Wl,--exclude-libs="$(EXCLUDE_LIBS)"

%.a:
	$(AR) r "$@" $+
liballocs_preload.a: $(LIBALLOCS_PRELOAD_A_OBJS)
liballocs_nonshared.a: $(LIBALLOCS_NONSHARED_A_OBJS)
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
vpath %.o $(LIBRUNT)/lib
liballocs_dummyweaks.so: LDFLAGS += $(PRIVATE_MALLOC_PLAIN_LDFLAGS)
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
	${INSTALL_DATA} liballocs_preload.a liballocs_nonshared.a liballocs.a liballocs_dummyweaks.o ${libdir}

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
