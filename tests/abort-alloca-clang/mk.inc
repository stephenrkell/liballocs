CC := $(LIBALLOCS_LIB)/contrib/llvm/build/bin/clang -fsanitize=allocs
LDLIBS += -lallocs -ldl
