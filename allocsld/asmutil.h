#ifndef ASMUTIL_H_
#define ASMUTIL_H_

#include <link.h> /* for ElfW and link map structures */
#include <relf.h> /* for ELFW_* */

#ifndef stringify
#define stringifx(x) #x
#define stringify(x) stringifx(x)
#endif
/* To embed a relocation type in our assembly strings,
 * we break out of the string but immediately stringify
 * the relocation type's preprocessor token, after expansion.
 * e.g. "..."R_(X86_64_PC32)"..." */
#define R_(x) stringify(R_ ## x)

/* A cpp-macro for a stretch of inline assembly that
 * assembles into a .rodata section. In parallel, it assembles
 * a relocation table... the assembly invokes an assembly-macro when it
 * wants to emit a relocation, done using pushsection/popsection.
 *
 * FIXME: the following bakes in Elf64_Rela in the .8byte sequence.
 * Better to cpp-macro-abstract this, and ideally also share these
 * cpp macro helpers with the code generated by tools/* (e.g. see extrasym). */
#define INSTRS_FROM_ASM(symname, asmstr) \
	extern ElfW(Rela) symname ## _relocs[]; /*__attribute__((section(".rodata_" #symname "_relocs" ))); */ \
	extern char symname []; /* __attribute__((section(".rodata_" #symname))); */ \
	__asm__( \
".pushsection .rodata_" #symname "_relocs, \"a\", @progbits \n\
"#symname "_relocs: \n\
 .popsection \n\
 .pushsection .rodata_" #symname ", \"a\", @progbits \n\
"#symname ": \n\
 .popsection \n\
 .set nrelocs, 0 \n\
 .macro reloc offs kind symidx addend=0 \n\
 .set offsval, \\offs - " #symname " \n\
 .pushsection .rodata_" #symname "_relocs, \"a\", @progbits \n\
 .8byte offsval \n\
 .8byte \\kind | (\\symidx << 32) \n\
 .8byte \\addend \n\
 .popsection \n\
 .set nrelocs, nrelocs + 1 \n\
 .endm \n\
 .pushsection .rodata_" #symname ", \"a\", @progbits \n\
 " asmstr " \n\
 .size " #symname ", . - " #symname "\n\
"#symname "_size:\n\
 .8byte . - " #symname "\n\
"#symname "_nrelocs:\n\
 .8byte nrelocs\n\
 .popsection \n\
 .pushsection " ".rodata_" #symname "_relocs, \"a\", @progbits\n\
 .size " #symname "_relocs,  . - " #symname "_relocs \n\
 .popsection \n\
 .purgem reloc\n" \
	)

// Use it like the following:
// 	INSTRS_FROM_ASM (bytes, /* FIXME: sysdep */ " \
// 1: movabs 0x123456789abcdef0,%rax             # 48 b8 f0 de bc 9a 78 56 34 12 \n\
// 		 RELOC 1b + 2, "STR(R_X86_64_64)", 0 "/* symidx */", 0 "/* addend */" \n\
//    jmpq *%rax \n\
// ");
// 
// ... now we have "bytes" as a char[] and "bytes_relocs" as a ElfW(Rela)[]

/* What about applying relocs?
 * We could define memcpy_and_relocate(dest, src, n, relocs, symaddr...)
 * ... how do we terminate symaddr?
                   memcpy_and_relocate(dest, src, n, relocs, nsyms, symaddr...)
 * Another problem with our helper is that now 'sizeof bytes' does not give us
 * the memcpying, as distinct from 
 */

static inline void apply_one_reloc(void *buf, ElfW(Rela) rel, uintptr_t *symaddrs)
{
	char *tgt = buf + rel.r_offset;
	unsigned symidx = ELFW_R_SYM(rel.r_info);
	unsigned long s = symaddrs[symidx];
	unsigned long a = rel.r_addend;
	unsigned long long utmp;
	long stmp;
	switch (ELFW_R_TYPE(rel.r_info))
	{
		case R_X86_64_PC32:   utmp = s - (uintptr_t) tgt     + a; memcpy(tgt, &utmp, 4); break;
		case R_X86_64_64:     utmp = s                       + a; memcpy(tgt, &utmp, 8); break;
		case R_X86_64_32:     utmp = s                       + a; memcpy(tgt, &utmp, 4); break;
		case R_X86_64_32S:    stmp = (int32_t) s + (int32_t) a; memcpy(tgt, &stmp, 4); break;
		case R_X86_64_TPOFF32:utmp = s                       + a; memcpy(tgt, &utmp, 4); break;

		default: abort();
	}
}
static inline unsigned long read_one_relocated_field(void *buf, ElfW(Rela) rel)
{
	char *tgt = buf + rel.r_offset;
	unsigned long long utmp = 0;
	unsigned utmp32 = 0;
	long long stmp = 0;
	unsigned stmp32 = 0;
	switch (ELFW_R_TYPE(rel.r_info))
	{
		case R_X86_64_PC32:   memcpy(&stmp, tgt, 4); return (uintptr_t) tgt + stmp;
		case R_X86_64_64:     memcpy(&utmp, tgt, 8); return utmp;
		case R_X86_64_32:     memcpy(&utmp32, tgt, 4); return utmp32;
		case R_X86_64_32S:    memcpy(&stmp32, tgt, 4); return stmp32;
		case R_X86_64_TPOFF32:memcpy(&utmp32, tgt, 4); return utmp32;
		default: abort();
	}
}
#define memcpy_and_relocate(dest, srcident, ...) do { \
	uintptr_t addrlist[] = { __VA_ARGS__ }; \
	extern size_t srcident ## _size; \
	extern size_t srcident ## _nrelocs; \
	extern ElfW(Rela) srcident ## _relocs[]; \
	memcpy(dest, srcident, srcident ## _size); \
	for (unsigned i = 0; i < srcident ## _nrelocs; ++i) { \
		apply_one_reloc(dest, srcident ## _relocs[i], addrlist); \
	} \
} while (0)

#endif
