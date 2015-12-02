CFLAGS += -DRELF_DEFINE_STRUCTURES

LDFLAGS += -static

# FIXME: don't demand pthreads in l0index; use weak symbol test
LDFLAGS += -pthread 

# HACK: as of gcc 4.9 and binutils 2.25, BFD ld chokes on the 
# IFUNC relocations in libc.a.
# /usr/bin/ld.bfd.real: dynamic STT_GNU_IFUNC symbol `strcmp' with pointer equality in `/usr/lib/gcc/x86_64-linux-gnu/4.9/../../../x86_64-linux-gnu/libc.a(strcmp.o)' cannot be used when making an executable; recompile with -fPIE and relink with -pie
CFLAGS += -fuse-ld=gold
