/* This is like a generalised version of objdumpallocs. 
 *
 * It walks all call sites in the binary, optionally outputting metadata.
 * We can also merge with allocsites info at this point.
 * We also identify syscalls.
 *
 * FIXME: where does the symbolic execution begin? The idea here is to
 * do some simple static analysis on the binary to propagate certain
 * information between instructions. There are two known use cases
 * at present:
 *
 * - for Linux's type-erased system call entry points, we want to
 *     execute forwards just far enough that we connect with the
 *     DWARF info describing the static / inlined body of the call.
 *
 * - for system calls, we want to identify cases where the syscall
 *     being made is statically knowable (this is usually the case).
 *     We do this by executing forwards from an entry point and, if
 *     we reach a syscall, 
 *
  *** See thing thing I mailed to Guillaume
 *
 *  Might this also help with stuff like allocation calls whose size
 * argument is statically knowable but not described with sizeofness?
 *
 * In general, what we're doing is static analysis around entry points and
 * call sites, deriving a bunch of "facts". Of what form are facts?
 * We start with an entry point in symbolic form.
 * Then facts are symbolic statements about 
 * registers (machine-level)
 * or call positions (ABI-level)
 * at a given site or location.
 * Correlating that with the static DWARF info, in the kernel case,
 * requires an extra step: back-propagating from the first "location"
 * reached inside the static function's DIE range,
 * to the entry point itself.
 *
 * So we sym-execute forwards from entry points, and care about reaching
 * - call sites
 * - syscall sites
 * - addresses within other DIEs
 *  */
