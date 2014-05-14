LDLIBS += -l1 -l2
LDFLAGS += -L$(shell pwd) -Wl,-R$(shell pwd)
CFLAGS += -fPIC -I$(realpath ../../include)

section-group: lib1.so lib2.so

%.so: %.c %a.c
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS)
