CXX = g++

LLVM_CXXFLAGS = $(shell llvm-config-20 --cxxflags)
LLVM_LDFLAGS  = $(shell llvm-config-20 --ldflags)
LLVM_LIBS     = $(shell llvm-config-20 --libs --system-libs --link-static)


# 1. Get the full paths
# 2. Use 'basename' to get just the filename (e.g., libclangBasic.a)
# 3. Use 'sed' to strip the 'lib' prefix and '.a' suffix
CLANG_LIBS = $(shell ls /usr/lib/llvm-20/lib/libclang*.a | xargs -n1 basename | sed 's/^lib\(.*\)\.a/-l\1/')

CXXFLAGS = -std=c++17 -g $(LLVM_CXXFLAGS) -Iinclude

BIN = ../bin
SRC = src
BUILD = build
TARGET = $(BIN)/clang-ast-parser

SRCS = $(shell find $(SRC) -name *.cpp)
OBJS = $(subst $(SRC)/,$(BUILD)/,$(addsuffix .o,$(basename $(SRCS))))

default: ../bin/clang-ast-parser

$(BUILD)/%.o: $(SRC)/%.cpp
	mkdir -p $(dir $@)
	${CXX} ${CXXFLAGS} -c $< -o $@

$(TARGET): $(OBJS)
	mkdir -p $(dir $@)
	${CXX} ${CXXFLAGS} $(OBJS) -o $@ ${LLVM_LDFLAGS} \
	-Wl,--start-group ${CLANG_LIBS} ${LLVM_LIBS} -Wl,--end-group

clang-ast-parser.o: clang-ast-parser.cpp
	${CXX} ${CXXFLAGS} -c clang-ast-parser.cpp -o clang-ast-parser.o

# Group is used to tell linker to search repeatedly within the group
clang-ast-parser: clang-ast-parser.o
	${CXX} ${CXXFLAGS} clang-ast-parser.o -o clang-ast-parser ${LLVM_LDFLAGS} \
	-Wl,--start-group ${CLANG_LIBS} ${LLVM_LIBS} -Wl,--end-group

clean:
	rm -rf build
	rm -f $(TARGET)

dep:
	wget https://apt.llvm.org/llvm.sh
	chmod +x llvm.sh
	sudo ./llvm.sh 20
	rm llvm.sh
	sudo apt update
	sudo apt install libclang-20-dev llvm-20-dev libpolly-20-dev libisl-dev libzstd-dev

