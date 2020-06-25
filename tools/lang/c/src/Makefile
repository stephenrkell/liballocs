$(warning antlr environment is $(shell printenv | grep -i antlr))

DEPS := 

srcroot ?= ../../../..

CXXFLAGS += -Wno-deprecated-declarations # while we're using old libdwarfpp -- FIXME

# use the pkg-config vars
CXXFLAGS += $(LIBCXXFILENO_CXXFLAGS) \
  $(LIBSRK31CXX_CXXFLAGS) \
  $(LIBDWARFPP_CXXFLAGS) \
  $(LIBCXXGEN_CXXFLAGS) \
  $(DWARFIDL_CXXFLAGS) \
  $(LIBANTLR3C_CXXFLAGS) \
  $(LIBALLOCSTOOL_CXXFLAGS)
LDFLAGS += $(LIBCXXFILENO_LIBS) \
  $(LIBSRK31CXX_LIBS) \
  $(LIBDWARFPP_LIBS) \
  $(LIBCXXGEN_LIBS) \
  $(DWARFIDL_LIBS) \
  $(LIBANTLR3C_LIBS) \
  $(LIBALLOCSTOOL_DIR)

CXXFLAGS += -I$(srcroot) # for config.h

LDFLAGS += -L`pwd` -Wl,-R`pwd`
LDLIBS += -lantlr3c -ldwarfidl -lcxxgen -ldwarfpp \
-lboost_regex -lboost_filesystem -lboost_system -lboost_serialization  \
-lc++fileno -lsrk31c++ -lelf -lstdc++ -lz

CPP_SRC := $(wildcard *.cpp)

default: base-types-translation #lower-typenames

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

lower-typenames: lower-typenames.cpp
base-types-translation: base-types-translation.cpp
