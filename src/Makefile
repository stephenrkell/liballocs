CFLAGS += -std=gnu99 -g -O3 -fPIC -DNDEBUG -I../include
HEAP_INDEX_HOOKS := heap_index_fast_hooks
#HEAP_INDEX_HOOKS := heap_index_hooks

CXXFLAGS := $(filter-out -std=%,$(CFLAGS)) -std=c++11

C_SRC := $(wildcard *.c)
CC_SRC := $(wildcard *.cc)

# Don't use crunchcc to compile libcrunch!
# if CC is crunchcc, unset it
ifeq ($(notdir $(CC)),crunchcc)
export CC := cc
endif

default: libcrunch_preload.so libcrunch_noop.so libcrunch_noop.o

# for addrmap.c and fake-libunwind.c
vpath %.c $(PMIRROR)/src

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

# FIXME: in preload case, can be clever with stubs? 
# HMM. We still have to --wrap the allocation funcs, but we could put the wrappers in the preload lib...
# BUT since they're generated per-build from the LIBCRUNCH_ALLOC_FNS content, this doesn't work --
# stick with stubs!
libcrunch_preload.so: libcrunch.o preload.o l0index.o maps.o addrmap.o $(FAKE_LIBUNWIND_OBJ) $(PMIRROR)/lib/lib$(HEAP_INDEX_HOOKS).a
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out %hooks.a,$^) $(LDFLAGS) -ldl $(LIBUNWIND_LDLIBS) -Wl,--whole-archive -Wl,-Bstatic -l$(HEAP_INDEX_HOOKS) -Wl,--no-whole-archive -Wl,-Bdynamic 

libdumpsmaps.so: libdumpsmaps.o
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out %hooks.a,$^) $(LDFLAGS) 

libcrunch_nomemtable_preload.so: libcrunch_nomemtable.o preload.o l0index.o maps.o addrmap.o $(FAKE_LIBUNWIND_OBJ) dummy_thread_locals.o
	$(CC) $(CFLAGS) -shared -o "$@" $(filter-out %hooks.a,$^) $(LDFLAGS) -ldl $(LIBUNWIND_LDLIBS)

# this version lacks preload stuff
libcrunch.so: libcrunch.o l0index.o maps.o addrmap.o $(FAKE_LIBUNWIND_OBJ)
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS) -ldl $(LIBUNWIND_LDLIBS) #-lheap_index_hooks

noop.o: CFLAGS += -fPIC 

libcrunch_nomemtable.o: libcrunch.c
	$(CC) $(CFLAGS) -DNO_MEMTABLE -c -o "$@" "$<" 

libcrunch_noop.so: noop.o
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS)

libcrunch_noop.o: noop.o
	ln -s "$<" "$@"

# have to preload the hooks yourself if you want them to hook!

clean: 
	rm -f *.o *.so .*.d
