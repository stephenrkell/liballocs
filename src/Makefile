THIS_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
LIBALLOCS := $(realpath $(dir $(THIS_MAKEFILE))/..)
SRCROOT := $(dir $(THIS_MAKEFILE))../
srcdir := $(SRCROOT)/src
include $(SRCROOT)/config.mk

CFLAGS += -std=gnu11 -fPIC -Wall -g -I../include -I$(SRCROOT)/include -I$(LIBMALLOCHOOKS) \
   -I$(LIBSYSTRAP) -I$(LIBRUNT)/include -I$(LIBDLBIND)/include -I$(srcdir) -Wno-unused \
   -flto -ffat-lto-objects
LDFLAGS += -L$(LIBDLBIND)/lib

# run-from-srcdir case:
# if the current dir is the source dir, change to the output directory
# and re-invoke this makefile from there.
# If we don't know which output directory we want, we want the production one.
ifeq ($(realpath .),$(realpath $(srcdir)))
ifeq ($(MAKECMDGOALS),)
MAKECMDGOALS := default
endif
ifneq ($(DEBUG),)
outdir := debug
else
outdir := opt
endif
.PHONY: $(MAKECMDGOALS)
$(MAKECMDGOALS):
	mkdir -p $(SRCROOT)/build/$(outdir)
	$(MAKE) -C $(SRCROOT)/build/$(outdir) -f $(srcdir)/Makefile $(MAKECMDGOALS)
else
# the rest
vpath %.c $(srcdir)
vpath %.c $(srcdir)/allocators

allocators/.%.d allocators/%.o:: allocators
allocators:
	mkdir -p allocators

#%.o:: %.c
#	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

liballocs.so: $(srcdir)/liballocs.so
	cp $< $@

# if we're building from a dir called "debug"
ifeq ($(notdir $(realpath .)),debug)
DEBUG := 1
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
TARGETS += liballocs_test.so       # version only usable for doing dlopen() -- runs unit tests in its constructor (see tests/lib-test)

.PHONY: all
all: $(TARGETS)

ifeq ($(DEBUG),)
    # FIXME: check this is still true: -O3 -DNDEBUG is the fastest, faster than -O4!
    CFLAGS += -O3 -DNDEBUG
endif

# Don't use allocscc to compile liballocs!
# if CC is allocscc, unset it
ifeq ($(notdir $(CC)),allocscc)
export CC := cc
endif

# regardless of fast/non-fast CFLAGS, link with -Wl,-O2 -flto
LDFLAGS += -Wl,-O2 -flto -Bsymbolic-functions -fPIC 
# until binutils bug 13600 is fixed, gold is the linker we need
LDFLAGS += -Wl,-fuse-ld=gold
# NOTE that our use of __private_malloc, a defsym'd symbol,
# used to provoke a gold bug when we were generating protected-visibility
# undefineds that were bound to it. That bug has been reported (#24286) and
# I've removed the protected undefineds (which came from libmallochooks
# template code). So we are still committed to using gold to link liballocs
# owing to binutils issue 13600 is fixed.

# HACK: -flto doesn't seem to work with our ld -r -generated malloc_hooks_preload_fast
# object. It complains about __next_malloc_hook et al being undefined, even though
# we --defsym'd them and they are clearly defined in the .o file. LTO doesn't grok --defsym.
# So we use the preprocessor (above) to define __next_hook_*.
export BUILD_MALLOC_HOOKS := event
event_hooks.o event_hooks_nonshared.o: CFLAGS += \
-D__next_hook_init=__terminal_hook_init \
-D__next_hook_malloc=__terminal_hook_malloc \
-D__next_hook_free=__terminal_hook_free \
-D__next_hook_realloc=__terminal_hook_realloc \
-D__next_hook_memalign=__terminal_hook_memalign 
CFLAGS += -DTRACE_MALLOC_HOOKS -DTRACE_HEAP_INDEX #-DTRACE_DEEP_HEAP_INDEX
event_hooks.c:

# GRR. We can't include the Makerules now that we need to build the hooks by 
# two different methods. Also, we can't get dependency information about these
# files from the makefiles. So we always want to run these rules. HMM.
vpath malloc_hook_stubs_wrap.c $(LIBMALLOCHOOKS)
vpath malloc_hook_stubs_preload.c $(LIBMALLOCHOOKS)
vpath event_hooks.c $(LIBMALLOCHOOKS)

ifneq ($(TRACE_HEAP_INDEX),)
CFLAGS += -DTRACE_HEAP_INDEX
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
$(info ALLOCATORS_OBJS is $(ALLOCATOR_OBJS))
MAIN_OBJS := liballocs.o event_hooks.o $(UTIL_OBJS) $(ALLOCATOR_OBJS)
HOOKS_WRAP_OBJS := malloc_hook_stubs_wrap.o
NOPRELOAD_OBJS := uniqtypes.o # never link this into a preload lib! nor include in _preload.a!
NONSHARED_OBJS := nonshared_hooks.o # does *not* go in liballocs.a -- FIXME: why not? recall that liballocs.a is only for static-linked client binaries (exe or solib). Otherwise we get _nonshared.a, from the liballocs.so linker script. Probably, liballocs.a should include this, e.g. a client static-linked exe needs this if it defines its own malloc.
PRELOAD_OBJS := preload.o malloc_hook_stubs_preload.o
SYSTRAP_OBJS := systrap.o

# Generate deps.
ALL_OBJS := $(MAIN_OBJS) $(NOPRELOAD_OBJS) $(NONSHARED_OBJS) $(PRELOAD_OBJS) $(HOOKS_WRAP_OBJS) $(SYSTRAP_OBJS)
# enumerate src files backwards from our .o files
C_SRC := $(sort $(patsubst %.o,%.c,$(ALL_OBJS)))
dep_fname = $(dir $1)$(patsubst %.c,.%.d,$(notdir $1))
C_DEPS := $(foreach f,$(C_SRC),$(call dep_fname,$(f)))
DEPS := $(C_DEPS)
$(call dep_fname,%.c): %.c
	mkdir -p $(dir $@) && $(CC) -MM $(CFLAGS) "$<" > "$@" || (rm -f "$@"; false)
-include $(DEPS)

# event_hooks.c is macroised so that we can create special versions of it.
# This version is used when we link an executable including its own malloc impl.
# FIXME: this should be made more uniform, as part of the allocator/stub-generation refactoring.
event_hooks_nonshared.o: CFLAGS += -D'ALLOC_EVENT(s)=__liballocs_malloc_\#\#s' -DALLOC_EVENT_ATTRIBUTES=
event_hooks_nonshared.o: event_hooks.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o "$@" $+
nonshared_hooks.o: event_hooks_nonshared.o nonshared_hook_wrappers.o
	$(LD) -r -o "$@" $+

# FIXME: remove the need for this
uniqtypes.o: uniqtypes.c
	$(CC) -o "$@" $(filter-out -flto,$(CFLAGS)) -c "$<" && \
	$(SRCROOT)/tools/lang/c/bin/link-used-types "$@" || (rm -f "$@"; false)

# we include our own malloc impl, for which we use dlmalloc
# of which libsystrap already has a copy, so borrow that (HACK)
vpath dlmalloc.c $(LIBSYSTRAP)/../src # HACK: actually in trap-syscalls but should be in libsystrap
# We put dlmalloc in a library so that --exclude-libs=dlmalloc.a will hide its symbols
# in our output .so, so that they don't override anything in the rest of the program.
dlmalloc.a: dlmalloc.o
dlmalloc.o: CFLAGS += -DHAVE_MORECORE=0 -DUSE_DL_PREFIX -fPIC
dlmalloc-ext.o: CFLAGS += -fPIC
PRIVATE_MALLOC_LDFLAGS := -Wl,--wrap,dlmalloc -Wl,--wrap,dlcalloc \
 -Wl,--wrap,dlfree -Wl,--wrap,dlrealloc -Wl,--wrap,dlmemalign -Wl,-wrap,dlposix_memalign \
 -Wl,--defsym,__private_malloc=__wrap_dlmalloc \
 -Wl,--defsym,__private_calloc=__wrap_dlcalloc \
 -Wl,--defsym,__private_free=__wrap_dlfree \
 -Wl,--defsym,__private_realloc=__wrap_dlrealloc \
 -Wl,--defsym,__private_memalign=__wrap_dlmemalign \
 -Wl,--defsym,__private_posix_memalign=__wrap_dlposix_memalign \
 -Wl,--defsym,__real_dlmalloc_usable_size=dlmalloc_usable_size \
 -Wl,--exclude-libs=dlmalloc.a \
 -Bsymbolic # important for _etext in preload hooks
# NOTE: we need to defsym to the __wrap_* functions, because of the way
# --wrap and --defsym interact: references generated by --defsym are *not*
# wrapped, unlike references that were in the file already.
PRIVATE_MALLOC_LDLIBS := -Wl,--whole-archive dlmalloc.a  -Wl,--no-whole-archive

LIBALLOCS_PRELOAD_A_OBJS := dlmalloc-ext.o $(MAIN_OBJS) $(PRELOAD_OBJS)
LIBALLOCS_NONSHARED_A_OBJS := $(NOPRELOAD_OBJS) $(NONSHARED_OBJS)
LIBALLOCS_A_OBJS := $(SYSTRAP_OBJS) $(MAIN_OBJS) $(NOPRELOAD_OBJS) $(PRELOAD_OBJS) $(HOOKS_WRAP_OBJS)

# liballocs_preload.so build rule is funky becuase dlmalloc.a is in LDFLAGS.
# It needs to be there because it goes inside --whole-archive (and these options
# are not files, so can't be prerequisites)
liballocs_preload.so: LDFLAGS += -Wl,--wrap,malloc_usable_size $(PRIVATE_MALLOC_LDFLAGS)
liballocs_preload.so: LDLIBS += -ldlbind $(PRIVATE_MALLOC_LDLIBS) $(LIBSYSTRAP)/libsystrap.a -lz -Wl,--no-as-needed -ldl $(LIBUNWIND_LDLIBS)
liballocs_preload.so: $(SYSTRAP_OBJS) $(LIBALLOCS_PRELOAD_A_OBJS) dlmalloc.a
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out dlmalloc.a,$+) $(LDFLAGS) $(LDLIBS)

# FIXME: this is supposed to obsolete liballocs_test.so and tests/lib-test
# ... but I'm not sure it can. Some unit tests need to run within a wider liballocs
liballocs_preload.so-test-%: LDFLAGS += $(PRIVATE_MALLOC_LDFLAGS)
liballocs_preload.so-test-%: LDLIBS += -ldlbind $(PRIVATE_MALLOC_LDLIBS) $(LIBSYSTRAP)/libsystrap.a -lz -Wl,--no-as-needed -ldl $(LIBUNWIND_LDLIBS)
liballocs_preload.so-test-%.c.test: %.c $(filter-out %.o,$(SYSTRAP_OBJS) $(LIBALLOCS_PRELOAD_A_OBJS)) dlmalloc.a
	$(CC) $(CFLAGS) $(CPPFLAGS) -DUNIT_TEST -o "$@" $(filter-out dlmalloc.a,$+) $(LDFLAGS) $(LDLIBS)
vpath %.h $(SRCROOT)/include
liballocs_preload.so-test-%.h.test: %.h $(SYSTRAP_OBJS) $(LIBALLOCS_PRELOAD_A_OBJS) dlmalloc.a
	$(CC) $(CFLAGS) $(CPPFLAGS) -DUNIT_TEST -o "$@" $(filter-out dlmalloc.a $<,$+) -x c $< -x none $(LDFLAGS) $(LDLIBS)

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
liballocs_dummyweaks.so: dummyweaks.o
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS)

# FIXME: this should probably go away, if our .test stuff above starts working
liballocs_test.so: LDLIBS += -lz -Wl,--no-as-needed -ldl $(LIBUNWIND_LDLIBS)
liballocs_test.so: systrap_noop.o liballocs_pic.a dlmalloc.a
	$(CC) $(CFLAGS) -shared -o "$@" \
	-Wl,--whole-archive $(filter-out dlmalloc.a,$+) -Wl,--no-whole-archive \
	$(LIBSYSTRAP)/libsystrap.a $(LDFLAGS) $(LDLIBS)

# Instead of a nomemtable build (for Valgrinding)
# can we just arrange that on a nomemtable *execution*,
# pageindex points to a large non-canonical address range
# and we handle the fault in our fault handler (Valgrind
# does honour user-supplied segfault handlers, apparently)

# liballocs.so is a linker script, so don't remove it
.PHONY: clean
clean: 
	rm -f *.o */*.o $(filter-out liballocs.so,$(wildcard *.so)) .*.d */.*.d *.a *_fast.c
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
