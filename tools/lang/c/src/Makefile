DEPS := 

ALLOCSITES ?= ../../../allocsites

CXXFLAGS += -std=c++0x -g -O0 -I$(ALLOCSITES)
CXXFLAGS += -Wno-deprecated-declarations # while we're using old libdwarfpp -- FIXME
LDFLAGS += -L`pwd` -Wl,-R`pwd` -L$(ALLOCSITES) -Wl,-R$(realpath $(ALLOCSITES))
LDLIBS += -lallocs -lcxxgen -ldwarfpp -ldwarf -lboost_regex -lboost_filesystem -lboost_system -lboost_serialization -lc++fileno -lsrk31c++ -lelf

CPP_SRC := $(wildcard *.cpp)

default: lower-typenames base-types-translation

.PHONY: clean
clean:
	rm -f *.o .*.d lower-typenames base-types-translation

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

lower-typenames: lower-typenames.cpp $(ALLOCSITES)/liballocs.a
base-types-translation: base-types-translation.cpp $(ALLOCSITES)/liballocs.a
