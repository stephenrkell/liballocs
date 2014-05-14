DEPS := 

CXXFLAGS += -std=c++0x -g -O0
CXXFLAGS += -Wno-deprecated-declarations # while we're using old libdwarfpp -- FIXME
LDFLAGS += -L`pwd` -Wl,-R`pwd`
LDLIBS += -lallocstool -lcxxgen -ldwarfpp -ldwarf -lboost_regex -lboost_filesystem -lboost_system -lboost_serialization -lc++fileno -lsrk31c++ -lelf

CPP_SRC := $(wildcard *.cpp)

default: liballocstool.a dumptypes allocsites usedtypes

.PHONY: clean
clean:
	rm -f *.o .*.d dumptypes allocsites usedtypes liballocstool.a

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
