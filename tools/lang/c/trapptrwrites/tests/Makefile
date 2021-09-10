CIL_INSTALL ?= $(LIBALLOCS)/contrib/cil/lib
CC := $(CIL_INSTALL)/../bin/cilly
CFLAGS := --load=../trapptrwrites.cmxs --dotrap-ptr-writes --save-temps -g
TESTS := writer arrays closure

build: $(TESTS)

%.o: %.c ../trapptrwrites.cmxs
	$(CC) $(CFLAGS) -c $< -o $@

%: %.o log_ptr_writes.o ../trapptrwrites.cmxs
	$(CC) $(CFLAGS) $< log_ptr_writes.o -o $@

# Disable default rules (why do they exist ?!)
%: %.c
%: %.o
%.o: %.c

clean:
	rm $(TESTS) *.i *.cil.c

.PHONY: build clean
