DEPS := 

CXXFLAGS += -std=c++0x -g -O0
CXXFLAGS += -Wno-deprecated-declarations # while we're using old libdwarfpp -- FIXME
LDLIBS += -ldwarfpp -ldwarf -lboost_regex -lboost_filesystem -lboost_system -lboost_serialization -lc++fileno -lsrk31c++ -lelf

CPP_SRC := uniqtypes.cpp

OCAMLOPT ?= ocamlopt
CIL ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST))))/../cil

default: uniqtypes

.PHONY: clean
clean:
	rm -f *.o .*.d

CPP_DEPS := $(patsubst %.cpp,.%.d,$(CPP_SRC))

DEPS :=$(CPP_DEPS)

$(CPP_DEPS): .%.d : %.cpp
	$(CXX) -MM $(CXXFLAGS) "$<"  > "$@"

-include $(DEPS)

default: uniqtypes #dumpallocs

#dumpallocs: dumpallocs.ml dumpallocsMain.ml
#	$(OCAMLOPT) -o dumpallocsMain.cmx -c -I $(CIL)/obj/x86_LINUX $+
#	$(OCAMLOPT) -ccopt -L$(CIL)/obj/x86_LINUX -o dumpallocs \
#		unix.cmxa str.cmxa \
#		int_misc.cmx nat.cmx big_int.cmx \
#		$(CIL)/obj/x86_LINUX/cil.cmxa dumpallocsMain.cmx

%: %.cpp
	$(CXX) $(LDFLAGS) $(CXXFLAGS) -o "$@" "$<" $(LDLIBS)
