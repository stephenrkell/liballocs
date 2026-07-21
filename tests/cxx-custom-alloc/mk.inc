CXX := $(LIBALLOCS)/tools/lang/c++/bin/allocsc++
export CXX

CXXFLAGS := $(filter-out -std=c99,$(CFLAGS)) -std=c++17
export CXXFLAGS

# Tell the liballocs instrumentation about our custom allocator.
# Same env-var format as the C tool (dumpallocs.ml) and clang-ast-parser.
export LIBALLOCS_ALLOC_FNS := _Z9my_mallocm(Z)p _Z9my_callocmm(zZ)p

LDLIBS += -lallocs

cxx-custom-alloc: cxx-custom-alloc.cpp my-alloc.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)
