CXX := $(LIBALLOCS)/tools/lang/c++/bin/allocsc++
export CXX

CXXFLAGS := $(filter-out -std=c99,$(CFLAGS)) -std=c++17
export CXXFLAGS

LDLIBS += -lallocs

cxx-sizeof-subtract: sizeof-subtract.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)
