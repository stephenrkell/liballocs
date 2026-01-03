THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE))/../../..)
include $(srcroot)/config.mk
OCAMLFIND ?= ocamlfind

ifeq ($(CIL_INSTALL),)
$(error "Expected CIL_INSTALL to be set")
endif
ifeq ($(LIBALLOCS_OCAML_PREFIX),)
$(error "Expected LIBALLOCS_OCAML_PREFIX to be set")
endif

export OCAMLPATH := $(LIBALLOCS_OCAML_PREFIX)/lib:$(OCAMLPATH)

CILLY ?= $(CIL_INSTALL)/../bin/cilly
CIL_TOOLS ?= cilallocs dumpallocs monalloca dumpmemacc trapptrwrites
OCAMLFLAGS += -package findlib -package goblint-cil
OCAMLFLAGS += -I $(dir $(THIS_MAKEFILE))/cilallocs
OCAMLFLAGS += -open GoblintCil -open GoblintCil.Cilint

CIL_TOOLS_SRC := $(shell find $(CIL_TOOLS) $(realpath $(dir $(THIS_MAKEFILE)))/lib -name '*.ml')

default: $(foreach t,$(CIL_TOOLS),$(t)/$(t).cmxs $(t)/$(t).cma)

OCAML_DEPS := $(patsubst %.ml,%.d,$(CIL_TOOLS_SRC))

$(OCAML_DEPS): %.d: %.ml
	$(OCAMLFIND) ocamldep $(filter-out -g,$(OCAMLOPTFLAGS)) $(OCAMLFLAGS) "$<" > "$@"

DEPS += $(OCAML_DEPS)
-include $(DEPS)

%.cmxs: %.cmx
	$(OCAMLFIND) ocamlopt -shared -o "$@" $(OCAMLOPTFLAGS) $(OCAMLFLAGS) $+
%.cmx %.cmi: %.ml
	$(OCAMLFIND) ocamlopt -o "$@" $(OCAMLOPTFLAGS) $(OCAMLFLAGS) -c "$<"
goblintCil.cmo: goblintCil.ml ;
%.cmo %.cmi: %.ml
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
	for dir in $(CIL_TOOLS); do (cd $$dir && rm -f *.o *.cmo *.cma *.cmi *.cmx *.cmxa *.cmxs *.cil.c *.i *.d ); done
