THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE))/../../..)
include $(srcroot)/config.mk
OCAMLFIND ?= ocamlfind

ifeq ($(CIL_INSTALL),)
$(error "Expected CIL_INSTALL to be set")
endif
CILLY ?= $(CIL_INSTALL)/../bin/cilly
CIL_TOOLS ?= cilallocs dumpallocs monalloca dumpmemacc trapptrwrites
OCAMLFLAGS +=  -package findlib
OCAMLFLAGS += -I $(CIL_INSTALL)/cil -I $(dir $(THIS_MAKEFILE))/cilallocs

CIL_TOOLS_SRC := $(shell find $(CIL_TOOLS) $(realpath $(dir $(THIS_MAKEFILE)))/lib -name '*.ml') 

default: cil src bin $(foreach t,$(CIL_TOOLS),$(t)/$(t).cmxs $(t)/$(t).cma)

OCAML_DEPS := $(patsubst %.ml,%.d,$(CIL_TOOLS_SRC))

$(OCAML_DEPS): %.d: %.ml
	$(OCAMLFIND) ocamldep $(filter-out -g,$(OCAMLOPTFLAGS)) $(OCAMLFLAGS) "$<" > "$@"

DEPS += $(OCAML_DEPS)
-include $(DEPS)

%.cmxs: %.cmx 
	$(OCAMLFIND) ocamlopt -shared -o "$@" $(OCAMLOPTFLAGS) $(OCAMLFLAGS) $+
%.cmx %.cmi: %.ml cil.stamp
	$(OCAMLFIND) ocamlopt -o "$@" $(OCAMLOPTFLAGS) $(OCAMLFLAGS) -c "$<"
%.cmo %.cmi: %.ml cil.stamp
	$(OCAMLFIND) ocamlc -o "$@" $(OCAMLFLAGS) -c "$<"
%.cma: %.cmo
	$(OCAMLFIND) ocamlc -o "$@" $(OCAMLFLAGS) -a $+

# build cilallocs first
dumpallocs/dumpallocs.cmx: cilallocs/cilallocs.cmx
dumpmemacc/dumpmemacc.cmx: cilallocs/cilallocs.cmx
monalloca/monalloca.cmx: cilallocs/cilallocs.cmx
dumpallocs/dumpallocs.cmo: cilallocs/cilallocs.cmo
dumpmemacc/dumpmemacc.cmo: cilallocs/cilallocs.cmo
monalloca/monalloca.cmo: cilallocs/cilallocs.cmo

# for testing
%.cil.o: %.c
	cd "$(dir $<)" && $(CILLY) --do$$( echo $(dir $<) | tr -d '/' ) --save-temps -c -o "$(notdir $@)" "$(notdir $<)"

.PHONY: clean
clean:
	for dir in $(CIL_TOOLS); do (cd $$dir && rm -f *.o *.cmo *.cma *.cmi *.cmx *.cmxa *.cmxs *.cil.c *.i ); done
	$(MAKE) -C src clean

.PHONY: src
src: 
	$(MAKE) -C src

.PHONY: bin
bin: src
	cd bin && ln -sf ../src/base-types-translation .
