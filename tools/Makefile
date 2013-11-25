DEPS := 

CXXFLAGS += -std=c++0x -g -O0
CXXFLAGS += -Wno-deprecated-declarations # while we're using old libdwarfpp -- FIXME
LDFLAGS += -L`pwd` -Wl,-R`pwd`
LDLIBS += -lallocs -ldwarfpp -ldwarf -lboost_regex -lboost_filesystem -lboost_system -lboost_serialization -lc++fileno -lsrk31c++ -lelf

CPP_SRC := uniqtypes.cpp

default: liballocs.a dumptypes allocsites

.PHONY: clean
clean:
	rm -f *.o .*.d

CPP_DEPS := $(patsubst %.cpp,.%.d,$(CPP_SRC))

DEPS :=$(CPP_DEPS)

$(CPP_DEPS): .%.d : %.cpp
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"

-include $(DEPS)

default: uniqtypes
%: %.cpp
	$(CXX) $(LDFLAGS) $(CXXFLAGS) -o "$@" "$<" $(LDLIBS)

liballocs.a: helpers.o
	ar r "$@" $^

dumptypes: liballocs.a
allocsites: liballocs.a
