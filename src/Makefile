THIS_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
SRCROOT := $(dir $(THIS_MAKEFILE))/..
MALLOC_HOOKS ?= ../../libmallochooks.hg

#HOOKS_OBJS :=  malloc_hooks_preload.o heap_index_hooks.o
#HOOKS_OBJS :=  malloc_hooks_preload_fast.o heap_index_hooks_fast.o
# HACK: -flto doesn't seem to work with our ld -r -generated malloc_hooks_preload_fast
# object. It complains about __next_malloc_hook et al being undefined, even though
# we --defsym'd them and they are clearly defined in the .o file.
# So don't use that rule. We use the preprocessor (above) to define __next_hook_*.

HOOKS_OBJS := heap_index_hooks_fast.o malloc_hook_stubs_preload_fast.o event_hooks_fast.o
#HOOKS_OBJS := heap_index_hooks.o malloc_hook_stubs_preload.o event_hooks.o

CFLAGS += -std=gnu99 -g -I../include -I$(SRCROOT)/include
#DEFAULT_EXTRA_CFLAGS := -fPIC -flto -O4 #-DNDEBUG
DEFAULT_EXTRA_CFLAGS := -fPIC -O0 -finline-functions

default: liballocs_preload.so liballocs_preload.a liballocs_noop.so liballocs_noop.o liballocs.a

NON_FAST_CFLAGS += -fPIC #-DTRACE_DEEP_HEAP_INDEX -DTRACE_MALLOC_HOOKS -DTRACE_HEAP_INDEX
FAST_CFLAGS += -fpic -flto -O4 #-DNDEBUG

# regardless of fast/non-fast CFLAGS, link with -Wl,-O2 -flto
LDFLAGS += -Wl,-O2 -flto -fPIC

BUILD_MALLOC_HOOKS := event
MALLOC_HOOKS_METHOD := preload
event_hooks.o event_hooks_fast.o: CFLAGS += -D__next_hook_init=__terminal_hook_init \
-D__next_hook_malloc=__terminal_hook_malloc \
-D__next_hook_free=__terminal_hook_free \
-D__next_hook_realloc=__terminal_hook_realloc \
-D__next_hook_memalign=__terminal_hook_memalign 
$(warning CFLAGS is $(CFLAGS))
include $(MALLOC_HOOKS)/Makerules

CXXFLAGS := $(filter-out -std=%,$(CFLAGS)) -std=c++11

C_SRC := $(wildcard *.c)

# Don't use allocscc to compile liballocs!
# if CC is allocscc, unset it
ifeq ($(notdir $(CC)),allocscc)
export CC := cc
endif

ifneq ($(USE_FAKE_LIBUNWIND),)
FAKE_LIBUNWIND_OBJ := fake-libunwind.o
CFLAGS += -DUSE_FAKE_LIBUNWIND -fno-omit-frame-pointer
LIBUNWIND_LDLIBS :=
else
FAKE_UNWIND_OBJ :=
LIBUNWIND_LDLIBS := -lunwind -lunwind-`uname -m` 
endif

UTIL_OBJS := l0index.o maps.o addrmap.o
MAIN_OBJS := liballocs.o $(UTIL_OBJS) $(FAKE_UNWIND_OBJ)
MAIN_OBJS_NOMEMTABLE := liballocs_nomemtable.o $(UTIL_OBJS)
PRELOAD_OBJS := preload.o
# HOOKS_OBJS is defined at the top

# build src backwards 
C_SRC := $(patsubst %.o,%.c,$(MAIN_OBJS) $(PRELOAD_OBJS) $(HOOKS_OBJS) liballocs_nomemtable.o)
C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))

DEPS := $(C_DEPS)

$(C_DEPS): .%.d : %.c
	$(CC) -MM $(CFLAGS) "$<"  > "$@"
$(CC_DEPS): .%.d : %.cc
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"

-include $(DEPS)

%_fast.c: %.c
	cp "$<" "$@"

$(MAIN_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ): CFLAGS += $(DEFAULT_EXTRA_CFLAGS) # hooks have either fpic or fPIC
.SECONDARY: heap_index_hooks_fast.c
heap_index_hooks_fast.o: CFLAGS += $(FAST_CFLAGS)
heap_index_hooks.o: CFLAGS += $(NON_FAST_CFLAGS)

# HACK override the rule for *.c -> *.o as a possible fix for debug info non-findy (does it work?)
%.o: %.c
	$(CC) -o "$@" $(CFLAGS) -c $(realpath $<)

# FIXME: in preload case, can be clever with stubs? 
# HMM. We still have to --wrap the allocation funcs, but we could put the wrappers in the preload lib...
# BUT since they're generated per-build from the LIBALLOCS_ALLOC_FNS content, this doesn't work --
# stick with stubs!
liballocs_preload.so: liballocs_preload.a
	$(CC) $(CFLAGS) -shared -o "$@" -Wl,--whole-archive -Wl,-Bstatic -L. "$<" -Wl,--no-whole-archive -Wl,-Bdynamic $(LDFLAGS) -ldl $(LIBUNWIND_LDLIBS)

liballocs_preload.a: $(MAIN_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ) $(HOOKS_OBJS)
	ar r "$@" $+ 

libdumpsmaps.so: libdumpsmaps.o
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out %hooks.a,$^) $(LDFLAGS) 

liballocs_nomemtable_preload.so: $(MAIN_OBJS_NOMEMTABLE) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ) dummy_thread_locals.o
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out %hooks.a,$^) $(LDFLAGS) -ldl $(LIBUNWIND_LDLIBS)

# this version lacks preload stuff
liballocs.a: $(MAIN_OBJS) $(FAKE_LIBUNWIND_OBJ)
	ar r "$@" $+

liballocs.so: liballocs.a
	$(CC) $(CFLAGS) -shared -o "$@" -Wl,--whole-archive "$<" -Wl,--no-whole-archive $(LDFLAGS) -ldl $(LIBUNWIND_LDLIBS) #-lheap_index_hooks

noop.o: CFLAGS += -fPIC 

liballocs_nomemtable.o: liballocs.c
	$(CC) $(CFLAGS) -DNO_MEMTABLE -c -o "$@" "$<" 

liballocs_noop.so: noop.o
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS)

liballocs_noop.o: noop.o
	ln -s "$<" "$@"

# have to preload the hooks yourself if you want them to hook!

clean: 
	rm -f *.o *.so .*.d *.a
