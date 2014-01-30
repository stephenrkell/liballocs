#CFLAGS += -std=gnu99 -g -O2 -fPIC
CFLAGS += -std=gnu99 -g -O0 -fPIC -I../include
#CFLAGS += -DUSE_STARTUP_BRK

C_SRC := $(wildcard *.c)

# Don't use crunchcc to compile libcrunch!
# if CC is crunchcc, unset it
ifeq ($(notdir $(CC)),crunchcc)
export CC := cc
endif

default: libcrunch_preload.so libcrunch_noop.so stubs.o

C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))

DEPS :=$(C_DEPS)

$(C_DEPS): .%.d : %.c
	$(CC) -MM $(CFLAGS) "$<"  > "$@"

-include $(DEPS)

# FIXME: in preload case, can be clever with stubs?

libcrunch_preload.so: libcrunch.o preload.o prefix_tree.o
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS) ${HOME}/work/devel/libpmirror.hg/src/addrmap.c -ldl -lunwind -lunwind-`uname -m` -Wl,--whole-archive -Wl,-Bstatic -lheap_index_fast_hooks -Wl,--no-whole-archive -Wl,-Bdynamic 

libcrunch.so: libcrunch.o
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS) ${HOME}/work/devel/libpmirror.hg/src/addrmap.c -ldl -lunwind -lunwind-`uname -m` #-lheap_index_hooks

noop.o: CFLAGS += -fPIC 

libcrunch_noop.so: noop.o
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS)

libcrunch_noop.o: noop.o
	ln -s "$<" "$@"

# have to preload the hooks yourself if you want them to hook!

clean: 
	rm -f *.o *.so .*.d
