DEPS := 

CXXFLAGS += -std=c++0x -g -O2
CXXFLAGS += -Wno-deprecated-declarations # while we're using old libdwarfpp -- FIXME
LDFLAGS += -L`pwd` -Wl,-R`pwd`
LDLIBS += -lallocstool -ldwarfidl -lantlr3c -lcxxgen -ldwarfpp -ldwarf -lboost_regex -lboost_filesystem -lboost_system -lboost_serialization -lc++fileno -lsrk31c++ -lelf

CPP_SRC := $(wildcard *.cpp)

default: liballocstool.a dumptypes allocsites usedtypes ifacetypes find-allocated-type-size lang

.PHONY: lang
lang:
	for dir in $(wildcard lang/*); do if [ -e $$dir/Makefile ]; then $(MAKE) -C $$dir; fi; done

.PHONY: clean
clean:
	rm -f *.o .*.d dumptypes allocsites usedtypes ifacetypes liballocstool.a
	for dir in $(wildcard lang/*); do if [ -e $$dir/Makefile ]; then $(MAKE) -C $$dir clean; fi; done

CPP_DEPS := $(patsubst %.cpp,.%.d,$(CPP_SRC))
DEPS := $(CPP_DEPS)

$(CPP_DEPS): .%.d : %.cpp
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

# GAH... for some reason GNU Make needs this rule to avoid trying 
# to link the .o using $(CC) instead of $(CXX). 
%: %.cpp
	$(CXX) $(LDFLAGS) $(CXXFLAGS) -o "$@" "$<" $(LDLIBS)

liballocstool.a: helpers.o uniqtypes.o
	ar r "$@" $^

dumptypes: dumptypes.cpp liballocstool.a
allocsites: allocsites.cpp liballocstool.a
usedtypes: usedtypes.cpp liballocstool.a
ifacetypes: ifacetypes.cpp liballocstool.a
