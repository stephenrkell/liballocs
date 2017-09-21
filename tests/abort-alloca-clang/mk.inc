CC := $(LIBALLOCS_BASE)/contrib/llvm/build/bin/clang -fsanitize=allocs
LDLIBS += -lallocs -ldl
