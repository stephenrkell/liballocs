THIS_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
LIBALLOCS_BASE := $(realpath $(dir $(THIS_MAKEFILE))/..)
SRCROOT := $(dir $(THIS_MAKEFILE))/..
MALLOC_HOOKS ?= ../../libmallochooks.hg

# HACK: -flto doesn't seem to work with our ld -r -generated malloc_hooks_preload_fast
# object. It complains about __next_malloc_hook et al being undefined, even though
# we --defsym'd them and they are clearly defined in the .o file.
# So don't use that rule. We use the preprocessor (above) to define __next_hook_*.

HOOKS_PRELOAD_OBJS := heap_index_hooks_fast.o malloc_hook_stubs_preload_fast.o event_hooks_fast.o
HOOKS_WRAP_OBJS := heap_index_hooks_fast.o malloc_hook_stubs_wrap_fast.o event_hooks_fast.o

CFLAGS += -std=gnu99 -g -I../include -I$(SRCROOT)/include -I$(MALLOC_HOOKS)

# STRANGE: this
#DEFAULT_EXTRA_CFLAGS := -fPIC -flto -O4 # note! no -DNDEBUG
# is slower than the following (4.61, 4.54, 4.60)
#DEFAULT_EXTRA_CFLAGS := -fPIC -O0 -finline-functions
# ; what about this? it's the same or slightly slower
#DEFAULT_EXTRA_CFLAGS := -fPIC -O4 -flto -finline-functions -DNDEBUG
# what about this one? makes little difference
#DEFAULT_EXTRA_CFLAGS := -fPIC -O4 -flto -DNDEBUG
# what about this one? same or slightly slower
#DEFAULT_EXTRA_CFLAGS := -fPIC -Os -flto -DNDEBUG
# what about this one? slightly faster
#DEFAULT_EXTRA_CFLAGS := -fPIC -O0 -DNDEBUG
# what about this one?  among the fastest (4.52, 4.50, 4.51)
#DEFAULT_EXTRA_CFLAGS := -fPIC -O3 -DNDEBUG
# really double-check that the following isn't faster? nope (4.64, 4.64, 4.59)
#DEFAULT_EXTRA_CFLAGS := -fPIC -O4 -flto -DNDEBUG

# Summary of the above: -fPIC -O3 -DNDEBUG is the fastest
DEFAULT_EXTRA_CFLAGS := -fPIC -O3 -DNDEBUG

default: liballocs_preload.so liballocs_nonshared.a liballocs_noop.so liballocs_noop.a liballocs_noop.o liballocs.a

NON_FAST_CFLAGS += -fPIC -DTRACE_MALLOC_HOOKS -DTRACE_HEAP_INDEX #-DTRACE_DEEP_HEAP_INDEX
FAST_CFLAGS += -fpic -flto -ffat-lto-objects -O4 -DNDEBUG
#FAST_CFLAGS += -fpic -O3 -DNDEBUG

# regardless of fast/non-fast CFLAGS, link with -Wl,-O2 -flto
LDFLAGS += -Wl,-O2 -flto -Bsymbolic-functions -fPIC 

# We define our own malloc_usable_size to catch the alloca case.
liballocs_preload.so: LDFLAGS += -Wl,--wrap,malloc_usable_size

export BUILD_MALLOC_HOOKS := event
event_hooks.o event_hooks_fast.o: CFLAGS += -D__next_hook_init=__terminal_hook_init \
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

ifeq ($(USE_REAL_LIBUNWIND),)
FAKE_LIBUNWIND_OBJ := fake-libunwind.o
CFLAGS += -fno-omit-frame-pointer
LIBUNWIND_LDLIBS :=
else
FAKE_UNWIND_OBJ :=
LIBUNWIND_LDLIBS := -lunwind -lunwind-`uname -m` 
CFLAGS += -DUSE_REAL_LIBUNWIND
endif

uniqtypes.o: uniqtypes.c
	$(CC) -o "$@" $(filter-out -flto,$(CFLAGS)) -c "$<" && \
	$(LIBALLOCS_BASE)/tools/lang/c/bin/link-used-types "$@" || (rm -f "$@"; false)

UTIL_OBJS := l0index.o maps.o addrmap.o addrlist.o uniqtypes.o uniqtype-bfs.o
MAIN_OBJS := liballocs.o $(UTIL_OBJS) $(FAKE_UNWIND_OBJ)
MAIN_OBJS_NOMEMTABLE := liballocs_nomemtable.o $(UTIL_OBJS)
PRELOAD_OBJS := preload.o
# HOOKS_*_OBJS are defined at the top

# build src backwards 
C_SRC := $(sort $(patsubst %.o,%.c,$(MAIN_OBJS) $(PRELOAD_OBJS) $(HOOKS_PRELOAD_OBJS) $(HOOKS_WRAP_OBJS) liballocs_nomemtable.o))
C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))

DEPS := $(C_DEPS)

$(C_DEPS): .%.d : %.c
	$(CC) -MM $(CFLAGS) "$<"  > "$@"
$(CC_DEPS): .%.d : %.cc
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"

-include $(DEPS)

%_fast.o: %.c
	$(CC) $(CFLAGS) -c -o "$@" "$<"

$(MAIN_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ): CFLAGS += $(DEFAULT_EXTRA_CFLAGS) # hooks have either fpic or fPIC
.SECONDARY: heap_index_hooks_fast.c
heap_index_hooks_fast.o: CFLAGS += $(FAST_CFLAGS)
heap_index_hooks.o: CFLAGS += $(NON_FAST_CFLAGS)
event_hooks_fast.o: CFLAGS += $(FAST_CFLAGS)
event_hooks.o: CFLAGS += $(NON_FAST_CFLAGS)

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
# liballocs_noop.so     -- non-client exes, that contain instrumented code, get -l this (but ideally would eliminate)
# liballocs_noop.a      -- in archive form, for extending noop libraries to link in (libcrunch_noop)
# liballocs_noop.o      -- non-client solibs, that contain instrumented code, get this linked in (i.e. avoiding a .so dependency; this is okay for solibs because LD_PRELOAD overrides them)
#
# What do client solibs get?
# Easiest is just to treat them like exes. They will get their own copy 
# of the basic uniqtypes, but this will get uniqued as appropriate.

liballocs_preload.so: liballocs_preload.a
	$(CC) $(CFLAGS) -shared -o "$@" -Wl,--whole-archive "$<" -Wl,--no-whole-archive $(LDFLAGS) -ldl $(LIBUNWIND_LDLIBS)
	
liballocs_preload.a: $(MAIN_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ) $(HOOKS_PRELOAD_OBJS)
	$(AR) r "$@" $+

liballocs_nonshared.a: uniqtypes.o
	$(AR) r "$@" $+

liballocs.a: $(MAIN_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ) $(HOOKS_WRAP_OBJS)
	$(AR) r "$@" $+

## What's going on here?
## We have a __wrap_malloc_usable_size in our preload, and normally we alias it
## to the main one too. Here we strip that alias, to avoid multiple definitions.
## WHY is malloc_usable_size special? Perhaps because it's in preload.o, whereas
## our other wrappers (like malloc) are in the malloc hooks... have we excluded
## them here?
#preload-wrap.o: preload.o
#	objcopy --strip-symbol malloc_usable_size "$<" "$@"
#
#liballocs_exe.a: $(MAIN_OBJS) preload-wrap.o $(FAKE_LIBUNWIND_OBJ) $(HOOKS_WRAP_OBJS)
#	rm -f "$@" && ar r "$@" $+ 

noop.o: CFLAGS += -fPIC 
liballocs_noop.o: noop.o
	ln -s "$<" "$@"

liballocs_noop.a: noop.o
	$(AR) r "$@" $+

liballocs_noop.so: noop.o
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS)

# this version lacks preload stuff
#liballocs.a: $(MAIN_OBJS) $(FAKE_LIBUNWIND_OBJ) $(filter-out malloc%,$(HOOKS_PRELOAD_OBJS))
#	ar r "$@" $+


libdumpsmaps.so: libdumpsmaps.o
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out %hooks.a,$^) $(LDFLAGS) 

liballocs_nomemtable_preload.so: $(MAIN_OBJS_NOMEMTABLE) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ) dummy_thread_locals.o
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out %hooks.a,$^) $(LDFLAGS) -ldl $(LIBUNWIND_LDLIBS)

liballocs_nomemtable.o: liballocs.c
	$(CC) $(CFLAGS) -DNO_MEMTABLE -c -o "$@" "$<" 

# have to preload the hooks yourself if you want them to hook!

# liballocs.so is a linker script, so don't remove it
clean: 
	rm -f *.o $(filter-out liballocs.so,$(wildcard *.so)) .*.d *.a *_fast.c
