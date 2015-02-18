LDFLAGS += -static

# FIXME: don't demand pthreads in l0index; use weak symbol test
LDFLAGS += -pthread 
