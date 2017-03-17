THIS_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
LIBALLOCS_BASE := $(realpath $(dir $(THIS_MAKEFILE))/..)
SRCROOT := $(dir $(THIS_MAKEFILE))../
MALLOC_HOOKS ?= $(SRCROOT)contrib/libmallochooks #./../libmallochooks.hg
TRAP_SYSCALLS ?= $(SRCROOT)contrib/trap-syscalls
LIBDLBIND ?= $(SRCROOT)contrib/libdlbind

# HACK: -flto doesn't seem to work with our ld -r -generated malloc_hooks_preload_fast
# object. It complains about __next_malloc_hook et al being undefined, even though
# we --defsym'd them and they are clearly defined in the .o file.
# So don't use that rule. We use the preprocessor (above) to define __next_hook_*.

HOOKS_PRELOAD_OBJS := malloc_hook_stubs_preload_fast.o event_hooks_fast.o
HOOKS_WRAP_OBJS := malloc_hook_stubs_wrap_fast.o event_hooks_fast.o

CFLAGS += -std=gnu11 -Wall -g -I../include -I$(SRCROOT)/include -I$(MALLOC_HOOKS) \
   -I$(TRAP_SYSCALLS)/libsystrap -I$(LIBDLBIND)/include -I$(SRCROOT)/src -Wno-unused

ifeq ($(DEBUG),1)
    DEFAULT_EXTRA_CFLAGS := -g
else
    # STRANGE: this
    #DEFAULT_EXTRA_CFLAGS := -flto -O4 # note! no -DNDEBUG
    # is slower than the following (4.61, 4.54, 4.60)
    #DEFAULT_EXTRA_CFLAGS := -O0 -finline-functions
    # ; what about this? it's the same or slightly slower
    #DEFAULT_EXTRA_CFLAGS := -O4 -flto -finline-functions -DNDEBUG
    # what about this one? makes little difference
    #DEFAULT_EXTRA_CFLAGS := -O4 -flto -DNDEBUG
    # what about this one? same or slightly slower
    #DEFAULT_EXTRA_CFLAGS := -Os -flto -DNDEBUG
    # what about this one? slightly faster
    #DEFAULT_EXTRA_CFLAGS := -O0 -DNDEBUG
    # what about this one?  among the fastest (4.52, 4.50, 4.51)
    #DEFAULT_EXTRA_CFLAGS := -O3 -DNDEBUG
    # really double-check that the following isn't faster? nope (4.64, 4.64, 4.59)
    #DEFAULT_EXTRA_CFLAGS := -O4 -flto -DNDEBUG

    # Summary of the above: -O3 -DNDEBUG is the fastest
    FAST_EXTRA_CFLAGS := -O3 -DNDEBUG -flto -ffat-lto-objects
    DEBUG_EXTRA_CFLAGS := -O0
endif

default: liballocs_preload.so liballocs_test.so liballocs_nonshared.a liballocs_dummyweaks.so liballocs_dummyweaks.o liballocs.a
all: default

HOOKS_NON_FAST_CFLAGS += -fPIC -DTRACE_MALLOC_HOOKS -DTRACE_HEAP_INDEX #-DTRACE_DEEP_HEAP_INDEX
HOOKS_FAST_CFLAGS += -fpic -flto -ffat-lto-objects
ifneq ($(DEBUG),1)
    HOOKS_FAST_CFLAGS += -O4 -DNDEBUG
endif

# regardless of fast/non-fast CFLAGS, link with -Wl,-O2 -flto
LDFLAGS += -Wl,-O2 -flto -Bsymbolic-functions -fPIC 

# until binutils bug 13600 is fixed, gold is the linker we need
LDFLAGS += -Wl,-fuse-ld=gold

LDFLAGS += -L$(LIBDLBIND)/lib
LDLIBS += -ldlbind

# We define our own malloc_usable_size to catch the alloca case.
liballocs_preload.so: LDFLAGS += -Wl,--wrap,malloc_usable_size

export BUILD_MALLOC_HOOKS := event
event_hooks.o event_hooks_fast.o event_hooks_nonshared.o: CFLAGS += -D__next_hook_init=__terminal_hook_init \
-D__next_hook_malloc=__terminal_hook_malloc \
-D__next_hook_free=__terminal_hook_free \
-D__next_hook_realloc=__terminal_hook_realloc \
-D__next_hook_memalign=__terminal_hook_memalign 

# $(warning CFLAGS is $(CFLAGS))

CXXFLAGS := $(filter-out -std=%,$(CFLAGS)) -std=c++11
C_SRC := $(wildcard *.c)

# Don't use allocscc to compile liballocs!
# if CC is allocscc, unset it
ifeq ($(notdir $(CC)),allocscc)
export CC := cc
endif

# GRR. We can't include the Makerules now that we need to build the hooks by 
# two different methods. Also, we can't get dependency information about these
# files from the makefiles. So we always want to run these rules. HMM.
malloc_hook_stubs_preload.o malloc_hook_stubs_preload_fast.o: $(MALLOC_HOOKS)/malloc_hook_stubs_wrap.c
	CFLAGS="$(CFLAGS) -fPIC" $(MAKE) MALLOC_HOOKS_METHOD=preload -f $(MALLOC_HOOKS)/Makerules malloc_hook_stubs_preload.o malloc_hook_stubs_preload_fast.o
malloc_hook_stubs_wrap.o malloc_hook_stubs_wrap_fast.o: $(MALLOC_HOOKS)/malloc_hook_stubs_wrap.c
	$(MAKE) MALLOC_HOOKS_METHOD=wrap -f $(MALLOC_HOOKS)/Makerules malloc_hook_stubs_wrap.o malloc_hook_stubs_wrap_fast.o

vpath %.c $(MALLOC_HOOKS)

vpath dlmalloc.c $(TRAP_SYSCALLS)/src
# We put dlmalloc in a library so that --exclude-libs=dlmalloc.a will hide its symbols
# in our output .so, so that they don't override anything in the rest of the program.
dlmalloc.a: dlmalloc.o
	$(AR) r "$@" $^
dlmalloc.o: CFLAGS += -DHAVE_MORECORE=0 -DUSE_DL_PREFIX -fPIC
dlmalloc-ext.o: CFLAGS += -fPIC
liballocs_preload.so liballocs_test.so: LDFLAGS += -Wl,--wrap,dlmalloc -Wl,--wrap,dlcalloc \
 -Wl,--wrap,dlfree -Wl,--wrap,dlrealloc -Wl,--wrap,dlmemalign -Wl,-wrap,dlposix_memalign \
 -Wl,--whole-archive dlmalloc.a  -Wl,--no-whole-archive \
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

ifeq ($(USE_REAL_LIBUNWIND),)
FAKE_LIBUNWIND_OBJ := fake-libunwind.o
CFLAGS += -fno-omit-frame-pointer
LIBUNWIND_LDLIBS :=
else
FAKE_UNWIND_OBJ :=
LIBUNWIND_LDLIBS := -lunwind -lunwind-`uname -m` 
CFLAGS += -DUSE_REAL_LIBUNWIND
endif

ifneq ($(TRACE_HEAP_INDEX),)
CFLAGS += -DTRACE_HEAP_INDEX
endif

uniqtypes.o: uniqtypes.c
	$(CC) -o "$@" $(filter-out -flto,$(CFLAGS)) -c "$<" && \
	$(LIBALLOCS_BASE)/tools/lang/c/bin/link-used-types "$@" || (rm -f "$@"; false)

ALLOCATOR_OBJS := $(patsubst %.c,%.o,$(wildcard allocators/*.c))
UTIL_OBJS := pageindex.o addrlist.o uniqtype-bfs.o
NOPRELOAD_OBJS := uniqtypes.o # never link this into a preload lib! nor include in _preload.a!
NONSHARED_OBJS := nonshared_hooks.o
MAIN_OBJS := liballocs.o $(UTIL_OBJS) $(FAKE_UNWIND_OBJ) $(ALLOCATOR_OBJS)
MAIN_OBJS_NOMEMTABLE := liballocs_nomemtable.o $(UTIL_OBJS) $(ALLOCATOR_OBJS)
PRELOAD_OBJS := preload.o
# HOOKS_*_OBJS are defined at the top

# build src backwards 
C_SRC := $(sort $(patsubst %.o,%.c,$(MAIN_OBJS) $(NOPRELOAD_OBJS) $(PRELOAD_OBJS) $(HOOKS_PRELOAD_OBJS) $(HOOKS_WRAP_OBJS) liballocs_nomemtable.o systrap.o))
dep_fname = $(dir $1)$(patsubst %.c,.%.d,$(notdir $1))
C_DEPS := $(foreach f,$(C_SRC),$(call dep_fname,$(f)))
# patsubst %.c,$(dir %.c).$(patsubst %.c,%.d$(notdir %.c).d,$(C_SRC))

DEPS := $(C_DEPS)
# $(warning DEPS are $(DEPS))

CFLAGS += -I$(SRCROOT)/src

# FIXME: make complains "target `allocators/.alloca.d' doesn't match the target pattern"
# if we prefix with C_DEPS here. 
# Actually it's a bit weird (but nice) that it's happy to expand "$(call dep_fname,%.c)".
#$(C_DEPS): 
$(call dep_fname,%.c) : %.c
	$(CC) -MM $(CFLAGS) "$<" > "$@"
$(CC_DEPS): $(dir %.cc)$(patsubst %.cc,.%.d,$(notdir %.cc)) : %.cc
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"

-include $(DEPS)

%_fast.o: %.c
	$(CC) $(CFLAGS) -c -o "$@" "$<"

ifeq ($(DEBUG),1)
systrap.o $(MAIN_OBJS) $(NOPRELOAD_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ): CFLAGS += -fPIC $(DEBUG_EXTRA_CFLAGS) # hooks have either fpic or fPIC
else
systrap.o $(MAIN_OBJS) $(NOPRELOAD_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ): CFLAGS += -fPIC $(FAST_EXTRA_CFLAGS) # hooks have either fpic or fPIC
endif 
.SECONDARY: heap_index_hooks_fast.c
heap_index_hooks_fast.o: CFLAGS += $(HOOKS_FAST_CFLAGS)
heap_index_hooks.o: CFLAGS += $(HOOKS_NON_FAST_CFLAGS)
event_hooks_fast.o: CFLAGS += $(HOOKS_FAST_CFLAGS)
event_hooks.o: CFLAGS += $(HOOKS_NON_FAST_CFLAGS)

event_hooks_nonshared.o: CFLAGS += -D'ALLOC_EVENT(s)=__liballocs_malloc_\#\#s' -DALLOC_EVENT_ATTRIBUTES=
event_hooks_nonshared.o: event_hooks.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o "$@" $+

nonshared_hooks.o: event_hooks_nonshared.o nonshared_hook_wrappers.o
	$(LD) -r -o "$@" $+

# HACK override the rule for *.c -> *.o as a possible fix for debug info non-findy (does it work?)
%.o: %.c
	$(CC) -o "$@" $(CFLAGS) -c $(realpath $<)

# FIXME: in preload case, can be clever with stubs? 
# HMM. We still have to --wrap the allocation funcs, but we could put the wrappers in the preload lib...
# BUT since they're generated per-build from the LIBALLOCS_ALLOC_FNS content, this doesn't work --
# stick with stubs!

# What libraries do we build?
# 
# liballocs_preload.so -- the main binary
# liballocs_preload.a  -- in archive form, for extending libraries to link in (libcrunch)
# liballocs.so         -- nasty linker script for clients, working around uniqueness problem
# liballocs_nonshared.a -- just uniqtypes; linker script points to this, s.t. client exes (-lallocs) get this linked in statically (uniqtypes)
# liballocs.a          -- the main binary usable for statically-linked exes -- no uniqueness problem
# liballocs_pic.a         -- PIC non-preload archive, used for testing (_test.so)
# liballocs_test.so       -- designed to be dlopen()able, to run self-tests in constructors
# liballocs_dummyweaks.so -- non-client exes, that contain instrumented code, get -l this (but ideally would eliminate)
# liballocs_dummyweaks.o  -- non-client solibs, that contain instrumented code, get this linked in (i.e. avoiding a .so dependency; this is okay for solibs because LD_PRELOAD overrides them)
#
# What do client solibs get?
# Easiest is just to treat them like exes. They will get their own copy 
# of the basic uniqtypes, but this will get uniqued as appropriate.

liballocs_preload.so: LDLIBS += -lz -Wl,--no-as-needed -ldl $(LIBUNWIND_LDLIBS)
liballocs_preload.so: systrap.o liballocs_preload.a dlmalloc.a
	$(CC) $(CFLAGS) -shared -o "$@" \
	-Wl,--whole-archive $(filter-out dlmalloc.a,$+) -Wl,--no-whole-archive \
	$(TRAP_SYSCALLS)/libsystrap/libsystrap.a $(LDFLAGS) $(LDLIBS)

liballocs_test.so: LDLIBS += -lz -Wl,--no-as-needed -ldl $(LIBUNWIND_LDLIBS)
liballocs_test.so: systrap_noop.o liballocs_pic.a dlmalloc.a
	$(CC) $(CFLAGS) -shared -o "$@" \
	-Wl,--whole-archive $(filter-out dlmalloc.a,$+) -Wl,--no-whole-archive \
	$(TRAP_SYSCALLS)/libsystrap/libsystrap.a $(LDFLAGS) $(LDLIBS)

liballocs_preload.a: dlmalloc-ext.o $(MAIN_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ) $(HOOKS_PRELOAD_OBJS)
	$(AR) r "$@" $+

liballocs_pic.a: dlmalloc-ext.o $(MAIN_OBJS) $(FAKE_LIBUNWIND_OBJ) $(HOOKS_PRELOAD_OBJS)
	$(AR) r "$@" $+

liballocs_nonshared.a: $(NOPRELOAD_OBJS) $(NONSHARED_OBJS)
	$(AR) r "$@" $+

liballocs.a: systrap.o $(MAIN_OBJS) $(NOPRELOAD_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ) $(HOOKS_WRAP_OBJS)
	$(AR) r "$@" $+

# HACK: would ideally eliminate "dummyweaks" shared object if ld provided a "--dt-useful" option.
dummyweaks.o: CFLAGS += -fPIC 
liballocs_dummyweaks.o: dummyweaks.o
	$(LD) -r -o "$@" $+

liballocs_dummyweaks.so: dummyweaks.o
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS)

libdumpsmaps.so: libdumpsmaps.o
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out %hooks.a,$^) $(LDFLAGS) 

liballocs_nomemtable_preload.so: $(MAIN_OBJS_NOMEMTABLE) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ) dummy_thread_locals.o
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out %hooks.a,$^) $(LDFLAGS) -ldl $(LIBUNWIND_LDLIBS)

liballocs_nomemtable.o: liballocs.c
	$(CC) $(CFLAGS) -DNO_MEMTABLE -c -o "$@" "$<" 

# have to preload the hooks yourself if you want them to hook!

# liballocs.so is a linker script, so don't remove it
clean: 
	rm -f *.o */*.o $(filter-out liballocs.so,$(wildcard *.so)) .*.d */.*.d *.a *_fast.c

install: all
	${INSTALL} liballocs_preload.so liballocs.so liballocs_dummyweaks.so ${libdir}
	${INSTALL_DATA} liballocs_preload.a liballocs_nonshared.a liballocs.a liballocs_dummyweaks.o ${libdir}
