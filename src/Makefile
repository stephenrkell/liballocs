#CFLAGS += -std=gnu99 -g -O3 -fPIC
CFLAGS += -std=gnu99 -g -O0 -fPIC

C_SRC := $(wildcard *.c)

default: libcrunch.so

C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))

DEPS :=$(C_DEPS)

$(C_DEPS): .%.d : %.c
	$(CC) -MM $(CFLAGS) "$<"  > "$@"

-include $(DEPS)

libcrunch.so: libcrunch.o
	$(CC) $(CFLAGS) -shared -o "$@" "$<" $(LDFLAGS) -lheap_index_fast_hooks
