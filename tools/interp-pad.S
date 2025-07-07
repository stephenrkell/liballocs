# In some circumstances, the dynamic linker uses the executable's
# .interp string to infer its own name. When we are using a chain
# loader (allocsld), and the binary is pointing to that loader as
# its dynamic linker, the "real" (chained-to) system dynamic
# linker will pick up that string and use it as its own name,
# creating a very confused link map entry.
#
# We avoid this by overwriting the executable's in-memory interp
# string at run time, just before the chain loader invocation, so
# that the system dynamic linker will get its own name correct.
# For this to work, .interp needs to be writable!
#
# So the purpose of this file is to:
# 1. ensure a writable .interp section in the final link;
# 2. equalise the behaviour of BFD and gold linkers w.r.t. the
#    interaction between explicit .interp sections and -dynamic-linker.
#    With gold, .interp will clobber -dynamic-linker, whereas
#    with bfd, -dynamic-linker works like an implicit .interp that is prepended
#    to the output .interp section.
#    To equalise these, we make our section string-mergeable. BFD will merge
#    its prepended string.
# See Makefile.am for where we set INTERP_STRING

#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
.section .interp, "awMS"
.ascii INTERP_STRING

