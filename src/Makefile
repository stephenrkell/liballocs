THIS_MAKEFILE := $(realpath $(lastword $(MAKEFILE_LIST)))
SRCROOT := $(dir $(THIS_MAKEFILE))/..
MALLOC_HOOKS ?= ../../libmallochooks.hg

CFLAGS += -std=gnu99 -g -I../include
CFLAGS += -I$(SRCROOT)/include

default: liballocs_preload.so liballocs_preload.a liballocs_noop.so liballocs_noop.o liballocs.a

NON_FAST_CFLAGS += -DTRACE_DEEP_HEAP_INDEX -DTRACE_MALLOC_HOOKS -DTRACE_HEAP_INDEX -fPIC
FAST_CFLAGS += -DNDEBUG -fpic -flto -O4

BUILD_MALLOC_HOOKS := event
MALLOC_HOOKS_METHOD := preload
$(warning CFLAGS is $(CFLAGS))
include $(MALLOC_HOOKS)/Makerules

CXXFLAGS := $(filter-out -std=%,$(CFLAGS)) -std=c++11

C_SRC := $(wildcard *.c)
CC_SRC := $(wildcard *.cc)

# Don't use allocscc to compile liballocs!
# if CC is allocscc, unset it
ifeq ($(notdir $(CC)),allocscc)
export CC := cc
endif

ifneq ($(USE_FAKE_LIBUNWIND),)
C_SRC += fake-libunwind.c
FAKE_LIBUNWIND_OBJ := fake-libunwind.o
CFLAGS += -DUSE_FAKE_LIBUNWIND -fno-omit-frame-pointer
LIBUNWIND_LDLIBS :=
else
LIBUNWIND_LDLIBS := -lunwind -lunwind-`uname -m` 
endif

C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))
CC_DEPS := $(patsubst %.cc,.%.d,$(CC_SRC))

DEPS := $(C_DEPS) $(CC_DEPS)

$(C_DEPS): .%.d : %.c
	$(CC) -MM $(CFLAGS) "$<"  > "$@"
$(CC_DEPS): .%.d : %.cc
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"

-include $(DEPS)

UTIL_OBJS := l0index.o maps.o addrmap.o
MAIN_OBJS := liballocs.o $(UTIL_OBJS)
MAIN_OBJS_NOMEMTABLE := liballocs_nomemtable.o $(UTIL_OBJS)
PRELOAD_OBJS := preload.o
#MALLOC_HOOKS_OBJ := malloc_hooks_preload_fast.o 
MALLOC_HOOKS_OBJ := malloc_hooks_preload.o 
HOOKS_OBJS := $(MALLOC_HOOKS_OBJ) heap_index_hooks.o

$(MAIN_OBJS) $(PRELOAD_OBJS) $(FAKE_LIBUNWIND_OBJ): CFLAGS += -fPIC # hooks have either fpic or fPIC
ifeq ($(MALLOC_HOOKS_OBJ),malloc_hooks_preload_fast.o)
heap_index_hooks.o: CFLAGS += $(FAST_CFLAGS)
else
heap_index_hooks.o: CFLAGS += $(NON_FAST_CFLAGS)
endif

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
