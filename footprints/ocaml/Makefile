LIBDIR ?= /home/jf451/prefix/lib

-include config.mk

ocaml_test_syscalls.native:
	corebuild ocaml_test_syscalls.native -package ctypes -package ctypes.foreign -lflags -cclib,-L${LIBDIR} -lflags -cclib,-lallocs_syscalls
