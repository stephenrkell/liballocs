#!/bin/bash

obj="$1"
shift

# We want to do an in-place update of the .o file,
# such that all the defined symbols 'sym' are unbound
# into __def_ and __ref_ symbols.
#
# The basic idea is:
# 
# 1. add a fresh name for SYM,  using ld -r --defsym __def_SYM=SYM
# (on which files? on the .o file defining SYM)
#
# 2. turn references into ABS symbols

#2. create your wrapper as a new definition for SYM, using NEWSYM if it wants
#
#   $ cc -c -o wrapper.o wrapper.c
#
#3. include your wrapper object before the original definition on the command line
#
#   $ ld wrapper.o otherstuff... OPTIONS -z muldefs

curobj="$obj"
LD="${LD:-ld}"
AS="${AS:-as}"
STRIP="${STRIP:-strip}"
OBJCOPY="${OBJCOPY:-objcopy}"
ourdir="$( mktemp -d )"
mktempobj () {
   mktemp -p "$ourdir" --suffix .o "$@"
}
ABS2UND="${ABS2UND:-abs2und}"

if false; then
# strip out the debug info
dbgabsobj="$(mktempobj dbgabstmp.XXX )"
# ${STRIP} --only-keep-debug -o "$dbgobj" "$curobj"
# This doesn't work. It decides '.text' et al are still needed.
# So instead we need to abs2und them!
allsymobj="$(mktempobj dbgallsym.XXX)"
# cp "$curobj" "$allsymobj"
objcopy --globalize-symbol .text "$curobj" "$allsymobj"
${LD} -z muldefs -r -o "$dbgabsobj" -R "$allsymobj" "$curobj"
objdump -t "$dbgabsobj"
dbgundobj="$(mktempobj dbgundtmp.XXX )"
cp "$dbgabsobj" "$dbgundobj"
${ABS2UND} "$dbgundobj"
dbgstripobj="$(mktempobj dbgstriptmp.XXX )"
# ${STRIP} --only-keep-debug -o "$dbgstripobj" "$dbgundobj"
#echo ${OBJCOPY} $(for sect in .debug_{info,abbrev,aranges,line,str} .eh_frame; do echo "-j $sect"; done) "$dbgundobj" "$dbgstripobj"
#     ${OBJCOPY} $(for sect in .debug_{info,abbrev,aranges,line,str} .eh_frame; do echo "-j $sect"; done) "$dbgundobj" "$dbgstripobj"
${OBJCOPY} --only-keep-debug "$dbgundobj" "$dbgstripobj"
# problem with the above: debug sections have relocs pointing at '.text' etc.
# We need to make *those* symbols undefined -- the section syms. Because they're local,
# the ld -r -R doesn't ABSify them. Hence --globalize attempt above. This *seems* to
# work, though from dbgabs we get a fresh SECTION symbol pointing at .text. Which do the
# relocs use?
#
# Remember that instead of all this, it may be possible to divert self-references some
# other way. The issue with --prefer-non-section-relocs was presumably that
# some text-to-text references go via the .text symbol even though they needn't.
# I think currently we don't have a story on that either... they will not get wrapped.
# I could write a separate tool, like abs2und but rewrite_section_relocs, that does this.
# Maybe it could also do the transform that I'm trying and failing to get objcopy to
# do above? i.e. replace section symbols with something possibly undefined.
#
# ACTUALLY... surely the rule is that we rebind references to non-section symbols, but
# not ones to section symbols? So --prefer-non-section-relocs should not be needed.
# My guess is that the real problem is self-calls or function-addrtakes on static symbols,
# i.e. the interaction
# with --globalize-sym. Check this with our bzip2-style address-taken-allocator test.
# Indeed:
#
#0000000000000000 <get_allocator>:
#   0:   48 8d 05 00 00 00 00    lea    0x0(%rip),%rax        # 7 <get_allocator+0x7>
#                        3: R_X86_64_PC32        .text.myalloc-0x4
#   7:   c3                      retq   
#
# So we want a 'normalize relocs' tool that will turn this into a 'myalloc' reference.
# In short it will see that the reference is to the start of 'malloc' and use that
# instead. (Some addend-futzing will be needed. The -0x4 is a consequence of the PLT32,
# so we can pair those off to nullify the -0x4.)
# We can avoid second-guessing about local vs global symbols, if we do this *after*
# globalization. Probably we should turn them into .hidden globals.
#
# If we do all that, then we probably don't have to strip out the debug info.

nodbgobj="$(mktempobj nodbgtmp.XXX )"
${STRIP} -g -o "$nodbgobj" "$curobj"
curobj="$nodbgobj"
fi

bail () {
   local sym="$1"
   local status="$2"
   printenv | grep "obj=" 1>&2
   echo "processing $sym, subcommand returned $status" 1>&2
   exit $status
}

for sym in "$@"; do
    newobj="$(mktempobj newtmp.XXX )"
    # create a 'def' alias
    ${LD} -r -o "$newobj" --defsym __def_$sym=$sym "$curobj" || bail $sym $?
    objdump -t "$newobj" 1>&2
    # make a scratch object defining the wrapped symbol
    symobj="$(mktempobj symtmp.XXX )"
    (printf ".globl $sym\n${sym}:\n" | as -o "$symobj") || bail $sym $?
    absobj="$(mktempobj abstmp.XXX )"
    # link in the scratch object with -R, so it leaves only an ABS symbol for $sym
    # (__def_ is still there, but relocs are pointing at $sym)
    ${LD} -z muldefs -r -o "$absobj" -R "$symobj" "$newobj" || bail $sym $?
    objdump -t "$absobj" 1>&2
    # turn the ABS into UND
    undobj="$(mktempobj undtmp.XXX )"
    cp "$absobj" "$undobj" || bail $sym $?
    ${ABS2UND} "$undobj" "$sym" || bail $sym $?
    objdump -t "$undobj" 1>&2
    # rename the 'sym' into '__ref_'
    refobj="$(mktempobj reftmp.XXX )"
    cp "$undobj" "$refobj" || bail $sym $?
    ${OBJCOPY} --redefine-sym "$sym"=__ref_"$sym" "$refobj" || bail $sym $?
    objdump -t "$refobj" 1>&2
    curobj="$refobj"
done
# now relink the debug info, renaming all the symbols to __def_
if false; then
dbgdefobj="$(mktempobj)"
${OBJCOPY} $( for sym in "$@"; do echo --redefine-sym "$sym"=__def_"$sym"; done ) "$dbgstripobj" "$dbgdefobj"
dbgnewobj="$(mktempobj)"
${LD} -r -o "$dbgnewobj" "$curobj" "$dbgdefobj"
else
dbgnewobj="$curobj"
fi
mv "$dbgnewobj" "$obj"
rm -rf "$ourdir"
