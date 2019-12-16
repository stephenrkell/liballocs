
#include <string>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <fileno.hpp>
#include <srk31/algorithm.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
#include <libgen.h>
#include <cstdio>
#include <cstring> // for memset
#include <memory>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <boost/icl/interval_map.hpp>

extern "C" {
#include <sys/mman.h>
#include <link.h>
#include "relf.h"
}

#include "stickyroot.hpp"

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

using std::cerr;
using std::endl;
using std::ostringstream;
using std::string;
using std::deque;
using namespace dwarf::core;
using dwarf::tool::abstract_c_compiler;

std::ostream& operator<<(std::ostream& s, const enum sym_or_reloc_kind& k)
{
#define _sym_or_reloc_kind_v(tok, n)  case tok: s << #tok; break;
	switch (k)
	{
_sym_or_reloc_kind(_sym_or_reloc_kind_v, _sym_or_reloc_kind_v)
		default: break;
	}
	return s;
}

namespace allocs
{
namespace tool
{

ElfW(Half) find_shndx(Elf *e,
	std::function<bool(unsigned, GElf_Shdr *)> pred,
	GElf_Shdr *out_shdr)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	unsigned shndx = 0;
	// iterate through sections looking for symtab
	while (NULL != (scn = elf_nextscn(e, scn)))
	{
		++shndx;
		if (gelf_getshdr(scn, &shdr) != &shdr)
		{
			cerr << "Unexpected ELF error" << std::endl;
			throw lib::No_entry(); 
		}
		if (pred(shndx, &shdr))
		{
			if (out_shdr) *out_shdr = shdr;
			break;
		}
	}
	if (!scn) return (ElfW(Half)) -1;
	return shndx;
}
ElfW(Half) find_shndx_by_sh_type(Elf * e, ElfW(Half) sh_type)
{
	return find_shndx(e, [sh_type](unsigned idx, GElf_Shdr *shdr) -> bool {
		return shdr->sh_type == sh_type;
	});
}
ElfW(Half) find_shndx_by_sh_name(Elf * e, const char *name)
{
	Elf_Scn *shstrtab_scn = elf_getscn(e, gelf_getehdr(e, NULL)->e_shstrndx);
	GElf_Shdr the_shdr;
	GElf_Shdr *shstrtab_hdr = gelf_getshdr(shstrtab_scn, &the_shdr);
	Elf_Data *shstrtab_elf_data = elf_rawdata(shstrtab_scn, NULL);
	char *shstrtab_data = reinterpret_cast<char*>(shstrtab_elf_data->d_buf);
	return find_shndx(e, [name, shstrtab_hdr, shstrtab_data](unsigned idx, GElf_Shdr *shdr) -> bool {
		return shdr->sh_name <= shstrtab_hdr->sh_size &&
			0 == strncmp(shstrtab_data + shdr->sh_name, name,
			std::min<size_t>(shstrtab_hdr->sh_size - shdr->sh_name, strlen(name)));
	});
}
Elf_Data *raw_data_by_shndx(Elf *e, ElfW(Half) shndx)
{
	assert(shndx != -1);
	Elf_Scn *scn = elf_getscn(e, shndx);
	if (!scn) throw lib::No_entry();
	GElf_Shdr the_shdr = (GElf_Shdr) { 0 };
	GElf_Shdr *shdr = gelf_getshdr(scn, &the_shdr);
	if (!shdr) throw lib::No_entry();
	Elf_Data *p_rawdata = elf_rawdata(scn, NULL);
	assert(p_rawdata);
	assert(p_rawdata->d_size >= shdr->sh_size);
	return p_rawdata;
}

pair<pair<ElfW(Sym) *, char*>, pair<Elf*, unsigned> > sticky_root_die::find_symbols(bool use_dynsym)
{
	/* We try the Elf that underlies our DWARF info first.
	 * If that doesn't work, */
	Elf *e = get_elf();
	ElfW(Half) shndx = find_shndx_by_sh_type(e, use_dynsym ? SHT_DYNSYM : SHT_SYMTAB);
	if (shndx == -1) throw lib::No_entry();
	Elf_Scn *scn = elf_getscn(e, shndx);
	if (!scn && base_elf_if_different != nullptr)
	{
		// try the other file
		e = base_elf_if_different;
		shndx = find_shndx_by_sh_type(e, use_dynsym ? SHT_DYNSYM : SHT_SYMTAB);
		if (shndx == -1) throw lib::No_entry();
		scn = elf_getscn(e, shndx);
	}
	if (!scn) throw lib::No_entry();
	GElf_Shdr the_shdr = (GElf_Shdr) { 0 };
	GElf_Shdr *shdr = gelf_getshdr(scn, &the_shdr);
	// FIXME: NOBITS check still necessary?
	if (!shdr) throw lib::No_entry();
	Elf_Data *symtab_rawdata = elf_rawdata(scn, NULL);
	assert(symtab_rawdata);
	assert(symtab_rawdata->d_size >= shdr->sh_size);
	ElfW(Sym) *the_symtab = reinterpret_cast<ElfW(Sym) *>(symtab_rawdata->d_buf);
	unsigned n = shdr->sh_size / shdr->sh_entsize;
	int strtab_ndx = shdr->sh_link;
	if (strtab_ndx == 0) throw lib::No_entry();
	Elf_Scn *strtab_scn = NULL;
	strtab_scn = elf_getscn(e, strtab_ndx);
	GElf_Shdr strtab_shdr;
	if (gelf_getshdr(strtab_scn, &strtab_shdr) != &strtab_shdr) throw lib::No_entry();
	Elf_Data *strtab_rawdata = elf_rawdata(strtab_scn, NULL);
	assert(strtab_rawdata);
	assert(strtab_rawdata->d_size >= strtab_shdr.sh_size);
	char *the_strtab = reinterpret_cast<char *>(strtab_rawdata->d_buf);
	assert(the_strtab);
	assert(the_symtab);
	// FIXME: cleanup
	return make_pair(make_pair(the_symtab, the_strtab), make_pair(e, n));
}
pair<pair<ElfW(Sym) *, char*>, pair<Elf *, unsigned> > sticky_root_die::get_symtab()
{
	if (!opt_symtab)
	{
		auto pair = find_symbols(false);
		opt_symtab = pair.first.first;
		strtab = pair.first.second;
		symtab_e = pair.second.first;
		symtab_n = pair.second.second;
	}	
	return make_pair(make_pair(*opt_symtab, strtab), make_pair(symtab_e, symtab_n));
}
pair<pair<ElfW(Sym) *, char*>, pair<Elf *, unsigned> > sticky_root_die::get_dynsym()
{
	if (!opt_dynsym)
	{
		auto pair = find_symbols(true);
		opt_dynsym = pair.first.first;
		dynstr = pair.first.second;
		dynsym_e = pair.second.first;
		dynsym_n = pair.second.second;
	}	
	return make_pair(make_pair(*opt_dynsym, dynstr), make_pair(dynsym_e, dynsym_n));
}

bool sticky_root_die::is_base_object(int user_fd)
{
	bool retval = true;
	/* This test distinguishes "base" objects, i.e. those
	 * we might reasonably load and run,
	 * from "meta" objects containing only debug info
	 * i.e. those produced by dh_strip or other methods.
	 * It is quite hard to identify these files because
	 * they may have all of the usual sections and headers.
	 * Most of the PROGBITS sections have become NOBITS,
	 * but ELF allows NOBITS where PROGBITS would do.
	 * We use an ad-hoc test: whether it has either an
	 * entry point that points into nobits,
	 * or a DYNAMIC phdr that point into nobits.
	 * This covers static and dynamic executables
	 * and dynamic shared libraries. */
	struct stat s;
	int ret = fstat(user_fd, &s);
	if (ret != 0) throw No_entry();
	long page_size = sysconf(_SC_PAGESIZE);
	void *mapping = mmap(NULL, ROUND_UP(s.st_size, page_size),
		PROT_READ, MAP_PRIVATE, user_fd, 0);
	if (mapping == MAP_FAILED) throw No_entry();
	const char magic[] = { '\177', 'E', 'L', 'F' };
	if (0 != memcmp(magic, mapping, sizeof magic)) throw No_entry();
	ElfW(Ehdr) *ehdr = reinterpret_cast<ElfW(Ehdr) *>(mapping);
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64
		|| ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
	{
		std::cerr << "ELF file is of unsupported class or endianness" << std::endl;
		throw No_entry();
	}
	if (!ehdr->e_shoff) throw No_entry();
	ElfW(Shdr) *shdr = reinterpret_cast<ElfW(Shdr) *>((char*) mapping + ehdr->e_shoff);
	/* Walk the section headers remembering their base addresses. */
	boost::icl::interval_map<ElfW(Addr), std::set<ElfW(Shdr)*> > m;
	auto& right_open = boost::icl::interval<ElfW(Addr)>::right_open;
	for (unsigned i = 1; i < ehdr->e_shnum; ++i)
	{
		if (!(shdr[i].sh_flags & SHF_ALLOC)) continue; // skip non-allocated sections
		std::set<ElfW(Shdr)*> singleton_set;
		singleton_set.insert(&shdr[i]);
		m += make_pair(
				right_open(shdr[i].sh_addr, shdr[i].sh_addr + shdr[i].sh_size),
				singleton_set
			);
	}
	auto is_nobits = [m, &right_open, shdr](ElfW(Addr) addr, unsigned span_len) -> bool {
		/* Find the section spanning this address range. */
		auto found = m.find(right_open(addr, addr + span_len));
		if (found == m.end()) return false;
		if (found->second.size() == 0) return false;
		if (found->second.size() > 1)
		{
			std::cerr << "Address 0x" << std::hex << addr << " spanned by more than"
				" one non-empty section; indices: {";
				
			for (auto i_found = found->second.begin();
				i_found != found->second.end();
				++i_found)
			{
				if (i_found != found->second.begin()) std::cerr << ", ";
				std::cerr << (*i_found - shdr);
			}
			std::cerr << "}" << std::endl;
		}
		auto &it = *found->second.begin();
		if (it->sh_type == SHT_NOBITS) return true;
		return false;
	};
	/* Which section contains the entry point? Is it nobits? */
	ElfW(Addr) dyn_vaddr = 0;
	if (ehdr->e_entry && is_nobits(ehdr->e_entry, 1))
	{
		retval = false; goto out;
	}
	for (unsigned i = 1; i < ehdr->e_shnum; ++i)
	{
		if (shdr[i].sh_type == SHT_DYNAMIC) { dyn_vaddr = shdr[i].sh_addr; break; }
	}
	if (dyn_vaddr && is_nobits(dyn_vaddr, 1))
	{
		retval = false; goto out;
	}
out:
	munmap(mapping, ROUND_UP(s.st_size, page_size));
	return retval;
}

bool sticky_root_die::has_dwarf(int user_fd)
{
	dwarf::lib::Dwarf_Debug d;
	dwarf::lib::Dwarf_Error e;
	bool retval;
	int ret = dwarf::lib::dwarf_init(user_fd, DW_DLC_READ, nullptr, nullptr, &d, &e);
	if (ret == 0)
	{
		Dwarf_Unsigned seen_cu_header_length;
		Dwarf_Half seen_version_stamp;
		Dwarf_Unsigned seen_abbrev_offset;
		Dwarf_Half seen_address_size;
		Dwarf_Half seen_offset_size;
		Dwarf_Half seen_extension_size;
		Dwarf_Unsigned seen_next_cu_header;

		ret = dwarf_next_cu_header_b(d,
			&seen_cu_header_length, &seen_version_stamp,
			&seen_abbrev_offset, &seen_address_size,
			&seen_offset_size, &seen_extension_size,
			&seen_next_cu_header, &e);
		if (ret == DW_DLV_OK)
		{
			retval = true;
		} else retval = false;
		ret = dwarf_finish(d, &e);
	} else retval = false;
	return retval;
}

static string get_liballocs_base()
{
	/* HACK HACK HACK: assume we're run in place, and use auxv to get our $0's dirname.
	 * PROBLEM: if we're libtool'd, our program is built in .libs.
	 * FIXME: what's the right way to do this? Envvars are normal, but we don't
	 * really like that either. Reimplementing the logic in C/C++ would also work. */
	static opt<string> liballocs_base;
	if (!liballocs_base)
	{
		int dummy_local = 0;
		struct auxv_limits limits = get_auxv_limits(get_auxv(environ, &dummy_local));
		string argv0 = limits.argv_vector_start[0];
		char *argv0_dup = strdup(argv0.c_str());
		if (!argv0_dup) abort();
		char *argv0_dir = dirname(argv0_dup);
		char *argv0_dir_realname = realpath(argv0_dir, NULL);
		string argv0_dir_realstr = argv0_dir_realname;
		liballocs_base = string(argv0_dir) + "/.." + ((
			/* HACK for libtool: if the realpath ends with ".libs", go one further level down. */
				argv0_dir_realstr.length() >= string("/.libs").length()
				&& 0 == argv0_dir_realstr.compare(
				    /* pos */ argv0_dir_realstr.length() - string("/.libs").length() /* for '/' */,
				    /* len */ string("/.libs").length(),
				    string("/.libs"))) ? "/.." : ""
			);
		free(argv0_dir_realname);
		free(argv0_dup);
	}
	return (*liballocs_base).c_str();
}

int sticky_root_die::open_debuglink(int user_fd)
{
	/* FIXME: linux-specific big hacks here. */
	char *cmdstr = NULL;
	char *fdstr = NULL;
	int ret = asprintf(&fdstr, "/dev/fd/%d", user_fd);
	if (ret <= 0) throw No_entry();
	/* HACK HACK HACK */
	ret = asprintf(&cmdstr, "bash -c \". '%s'/tools/debug-funcs.sh && read_debuglink '%s' | tr -d '\\n'\"",
		get_liballocs_base().c_str(), fdstr);
	if (ret <= 0) throw No_entry();
	assert(cmdstr != NULL);
	FILE *p = popen(cmdstr, "r");
	char debuglink_buf[4096];
	size_t nread = fread(debuglink_buf, 1, sizeof debuglink_buf, p);
	int ret_fd;
	if (nread == sizeof debuglink_buf)
	{
		// basically we overflowed
		std::cerr << "Debuglink contained too many characters" << std::endl;
		ret_fd = -1;
	}
	else if (nread > 0)
	{
		/* We've successfully slurped a debuglink */
		std::cerr << "Slurped debuglink: " << debuglink_buf << std::endl;
		/* How to build the path from the debuglink? GDB docs say we
		 * have to try:
		 * the directory of the executable file, then
		 * in a subdirectory of that directory named .debug, and finally
		 * under each one of the global debug directories,
		 *      in a subdirectory whose name is identical to
		 *      the leading directories of the executable's absolute file name. */
		std::vector<std::string> paths_to_try;
		char *fd_realpath = realpath(fdstr, NULL);
		if (fd_realpath)
		{
			// to save us from strdup'ing, construct a string
			// only do the first one if debuglink it doesn't match basename
			if (string(debuglink_buf) !=
				string(basename((char*) string(fd_realpath).c_str())))
			{
				/* Try the debuglink basename on the fd realpath */
				paths_to_try.push_back(
					string(dirname((char*) string(fd_realpath).c_str()))
					+ "/" + debuglink_buf
				);
			}
			// try .debug/
			paths_to_try.push_back(
				string(dirname((char*) string(fd_realpath).c_str()))
				+ "/.debug/" + debuglink_buf
			);
			// HACK: try /usr/lib/debug + fd dirname + debuglink
			paths_to_try.push_back(
				string("/usr/lib/debug/")
				+ string(dirname((char*) string(fd_realpath).c_str()))
				+ "/"
				+ debuglink_buf
			);

			free(fd_realpath);
		}
		for (auto i_path = paths_to_try.begin(); i_path != paths_to_try.end();
			++i_path)
		{
			ret_fd = open(i_path->c_str(), O_RDONLY);
			if (ret_fd != -1) break;
		}
	}
	free(cmdstr);
	return ret_fd;
}
int sticky_root_die::open_debug_via_build_id(int user_fd)
{
	/* FIXME: linux-specific big hacks here. */
	char *cmdstr = NULL;
	char *fdstr = NULL;
	int ret = asprintf(&fdstr, "/dev/fd/%d", user_fd);
	if (ret <= 0) throw No_entry();
	/* HACK HACK HACK */
	ret = asprintf(&cmdstr, "bash -c \". '%s'/tools/debug-funcs.sh && read_build_id '%s' | tr -d '\\n'\"",
		get_liballocs_base().c_str(), fdstr);
	if (ret <= 0) throw No_entry();
	assert(cmdstr != NULL);
	FILE *p = popen(cmdstr, "r");
	char build_id_buf[41];
	size_t nread = fread(build_id_buf, 1, sizeof build_id_buf - 1, p);
	build_id_buf[40] = '\0';
	int ret_fd;
	if (nread > 0)
	{
		/* We've successfully slurped a build_id */
		std::cerr << "Slurped build ID: " << build_id_buf << std::endl;
		/* How to build the path from the build ID? GDB docs say we
		 * have to try:
		 * the directory of the executable file, then
		 * in a subdirectory of that directory named .debug, and finally
		 * under each one of the global debug directories,
		 *      in a subdirectory whose name is identical to
		 *      the leading directories of the executable’s absolute file name. */
		std::vector<std::string> paths_to_try;
		paths_to_try.push_back(
				string("/usr/lib/debug/.build-id/")
				+ build_id_buf[0]
				+ build_id_buf[1]
				+ "/"
				+ (build_id_buf + 2)
				+ ".debug"
			);
		std::cerr << "Trying: " << *paths_to_try.begin() << std::endl;
		for (auto i_path = paths_to_try.begin(); i_path != paths_to_try.end();
			++i_path)
		{
			ret_fd = open(i_path->c_str(), O_RDONLY);
			if (ret_fd != -1) break;
		}
	} else ret_fd = -1;
	free(cmdstr);
	return ret_fd;
}

shared_ptr<sticky_root_die> sticky_root_die::create(int user_fd)
{
	/* This is a helper not a constructor, because we have to
	 * inspect user_fd before we know what constructor to call. */
	bool is_base = is_base_object(user_fd);
	/* Easy case: a base object containing DWARF. */
	if (is_base && has_dwarf(user_fd))
	{ return std::make_shared<sticky_root_die>(user_fd, user_fd); }
	int dbg_fd;
	if (is_base)
	{
		dbg_fd = open_debuglink(user_fd);
		if (dbg_fd == -1) dbg_fd = open_debug_via_build_id(user_fd);
	}
	else dbg_fd = user_fd;
	if (dbg_fd != -1) return std::make_shared<sticky_root_die>(dbg_fd, user_fd);
	return std::shared_ptr<sticky_root_die>();
}

boost::icl::discrete_interval<Dwarf_Addr>
sticky_root_die::static_descr::address_range() const
{
	switch (k)
	{
		case DYNSYM:
		case SYMTAB:
			return boost::icl::interval<Dwarf_Addr>::right_open(
				static_cast<Dwarf_Addr>(get_sym().first.second->st_value),
				static_cast<Dwarf_Addr>(get_sym().first.second->st_value + get_sym().first.second->st_size)
			);
		case DWARF: {
			boost::icl::interval_map<Dwarf_Addr, Dwarf_Unsigned> intervals;
			if (get_d().tag_here() == DW_TAG_variable
				&& get_d().has_attribute_here(DW_AT_location))
			{
				iterator_df<variable_die> i_var = get_d().as_a<variable_die>();
				if (!i_var->has_static_storage())
				{
					// cerr << "Skipping non-static var " << i.summary() << std::endl;
					goto return_empty;
				}
				/* Just because we have a location doesn't mean we have a complete
				 * type. In general it's buggy DWARF that lacks a complete type in
				 * such cases, but I've seen it. So guard against it. */
				auto maybe_t = i_var->find_type();
				if (!maybe_t)
				{
					std::cerr << "Warning: DIE at " << i_var.offset_here() << " has location "
						<< "but no type" << std::endl;
					goto return_empty;
				}
				if (!maybe_t->calculate_byte_size())
				{
					std::cerr << "Warning: DIE at " << i_var.offset_here() << " has location "
						<< "but incomplete or unbounded-size type: " << maybe_t << std::endl;
					// HMM. We don't want to return empty. We want to return "whatever the symbol
					// says". That's currently how we handle an empty interval, in effect, but
					// this is a bit fragile.
					goto return_empty;
				}
				try
				{
					intervals = 
						i_var->file_relative_intervals(
							i_var.root(),
							0 /* sym_binding_t (*sym_resolve)(const std::string& sym, void *arg) */, 
							0 /* arg */);
				}
				catch (dwarf::lib::No_entry)
				{
					// this happens if we don't have a real location -- continue
					goto return_empty;
				}
			}
			else if (get_d().is_a<subprogram_die>())
			{
				try
				{
					intervals = 
						get_d().as_a<subprogram_die>()->file_relative_intervals(
							get_d().root(),
							0 /* sym_binding_t (*sym_resolve)(const std::string& sym, void *arg) */, 
							0 /* arg */);
				}
				catch (dwarf::lib::No_entry)
				{
					// this happens if we don't have a real location -- continue
					goto return_empty;
				}
			}
			if (intervals.size() == 0)
			{
				// this happens if we don't have a real location -- continue
				goto return_empty;
			}

			// calculate its file-relative addr
			Dwarf_Off addr = intervals.begin()->first.lower();
			// unsigned n_intervals = srk31::count(intervals.begin(), intervals.end());
			// if it has more than one interval, we've got something weird
			auto end_minus_one = intervals.end(); --end_minus_one;
			Dwarf_Off end_addr = end_minus_one->first.upper();
			ElfW(Sym) *maybe_sym = nullptr;
			const char *maybe_sym_name = nullptr;
			if (end_minus_one != intervals.begin())
			{
				cerr << "Warning: ignoring the following static having >1 address-range interval: " << d.summary() << std::endl;
				goto return_empty;
			}
			return intervals.begin()->first;
		} // end case DWARF
		case REL:
		case DYNREL:
			// it's from the address of the rel, up to the address of any other stuff
			return boost::icl::interval<Dwarf_Addr>::right_open(
				get_reltgt().first,
				get_reltgt().first + get_reltgt().second
			);
		case UNKNOWN:
		default:
			assert(false);
		return_empty: {
			Dwarf_Addr zero = 0;
			return boost::icl::interval<Dwarf_Addr>::right_open(zero, zero);
		}
	}
}

boost::icl::interval_map< Dwarf_Addr, sticky_root_die::static_descr_set >
sticky_root_die::get_statics()
{
	/* A static address can be described by DWARF info, a dynsym entry
	 * and/or a symtab entry. We want to merge this information, somehow.
	 * We merge it in a particular way: we always want to know the DWARF
	 * info for a location, and we also want *a* symbol for any location
	 * that is described by *either* DWARF *or* an existing symbol.
	 * We make up a fake "extrasym" for anything that is on DWARF but
	 * not in a symbol.
	 *
	 * How to do all this?
	 * We build one big interval map of *sets* of descriptions.
	 * Then we walk the (now split) intervals.
	 * If we have no symbol for some interval, we generate one.
	 * Otherwise we pick the highest-preference one (dynsym first).
	 * We always generate a DWARF type for the interval.
	 * FIXME: what about relocs? tempted to say they have "starts" but
	 * no symbol/type info. That complicates our metavec, which expects
	 * that bitmap entries correspond one-to-one with metadata records.
	 * So maybe we should give them a null metadata record -- still no
	 * type or symbol.
	 */
	boost::icl::interval_map< Dwarf_Addr, static_descr_set > statics;
	auto process_a_symtab = [&statics](ElfW(Sym) *syms, char *strtab, unsigned n,
		static_descr::kind k) {
		for (unsigned i = 0; i < n; ++i)
		{
			/* Is this a symbol with non-zero size?
			 * FIXME: what about overlaps? */
			if ((ELFW_ST_TYPE(syms[i].st_info) == STT_OBJECT
				||  ELFW_ST_TYPE(syms[i].st_info) == STT_FUNC)
				&& syms[i].st_size > 0
				&& syms[i].st_shndx != SHN_ABS
				&& syms[i].st_shndx != SHN_UNDEF)
			{
				//out.insert(make_pair((Dwarf_Addr) syms[i].st_value,
				//	make_pair(&syms[i], syms[i].st_name == 0 ? nullptr : &strtab[syms[i].st_name])));
				static_descr_set singleton_set;
				singleton_set.insert(static_descr(k, make_pair(
					make_pair(i, &syms[i]),
					syms[i].st_name == 0 ? nullptr : &strtab[syms[i].st_name]
				)));
				statics += make_pair(
					boost::icl::interval<Dwarf_Addr>::right_open(
						syms[i].st_value,
						syms[i].st_value + syms[i].st_size
					),
					singleton_set
				);
			}
		}
	};
	auto symtab_etc = get_symtab();
	auto dynsym_etc = get_dynsym();
	process_a_symtab(symtab_etc.first.first, symtab_etc.first.second, symtab_etc.second.second,
		static_descr::SYMTAB);
	process_a_symtab(dynsym_etc.first.first, dynsym_etc.first.second, dynsym_etc.second.second,
		static_descr::DYNSYM);
	for (auto i = this->begin(); i != this->end(); ++i)
	{
		cerr << i.summary() << std::endl;
		if ((i.tag_here() == DW_TAG_variable
				&& i.has_attribute_here(DW_AT_location)
				&& i.as_a<variable_die>()->has_static_storage())
			|| i.tag_here() == DW_TAG_subprogram)
		{
			static_descr elem(i.as_a<program_element_die>());
			auto interval = elem.address_range();
			if (interval.upper() - interval.lower() == 0) continue;
			static_descr_set singleton_set;
			singleton_set.insert(elem);
			statics += make_pair(
				interval,
				singleton_set
			);
		}
	}
	return statics;
}

iterator_df<program_element_die> sticky_root_die::static_descr_set::get_die() const
{
	for (auto i_descr = begin(); i_descr != end(); ++i_descr)
	{
		if (i_descr->k == sticky_root_die::static_descr::DWARF)
		{
			return i_descr->get_d();
		}
	}
	return iterator_base::END;
}

sticky_root_die::static_descr_set::summary
sticky_root_die::static_descr_set::get_summary(
	bool symtab_is_external, opt<unsigned> maybe_expected_size) const
{
	assert(size() > 0);
	iterator seen_non_external_sym = end();
	ElfW(Sym) *saw_sym = nullptr;
	opt<string> opt_name;
	opt<string> maybe_sym_name;
	opt<string> maybe_dwarf_name;
	opt<unsigned> maybe_sym_idx;
	iterator_df<program_element_die> maybe_die;
	// first to a pass that looks for DWARF
	for (auto i_descr = begin(); i_descr != end(); ++i_descr)
	{
		if (i_descr->k == sticky_root_die::static_descr::DWARF)
		{
			cerr << "Covered by DWARF: "
				<< *i_descr << std::endl;
			opt_name = i_descr->get_d()->get_name();
			maybe_dwarf_name = opt_name;
			maybe_die = i_descr->get_d();
		}
	}
	// now do a pass that looks for a symbol
	for (auto i_descr = begin(); i_descr != end(); ++i_descr)
	{
		if (i_descr->k == sticky_root_die::static_descr::DYNSYM
		|| (i_descr->k == sticky_root_die::static_descr::SYMTAB
			&& !symtab_is_external))
		{
			cerr << "Covered by a non-external symbol: "
				<< *i_descr << std::endl;
			seen_non_external_sym = i_descr;
			saw_sym = i_descr->get_sym().first.second;
			if (!opt_name) opt_name = string(i_descr->get_sym().second);
			if (!maybe_sym_name)
			{
				maybe_sym_name = string(i_descr->get_sym().second);
				maybe_sym_idx = opt<unsigned>(i_descr->get_sym().first.first);
			}
			break;
		}
		else if (i_descr->k == sticky_root_die::static_descr::SYMTAB
			&& symtab_is_external)
		{
			cerr << "Covered by an external symbol: "
				<< *i_descr << std::endl;
			saw_sym = i_descr->get_sym().first.second;
			if (!opt_name)
			{
				opt_name = string(i_descr->get_sym().second);
				maybe_sym_name = opt_name;
				maybe_sym_idx = opt<unsigned>(i_descr->get_sym().first.first);
			}
			break;
		}
	}
	if (seen_non_external_sym != end())
	{
		assert(maybe_sym_idx);
		assert(saw_sym);
		assert(maybe_sym_name);
		// return the summary
		summary s = {
			opt_name,
			maybe_die,
			type_from_die(maybe_die),
			(seen_non_external_sym->k == static_descr::DYNSYM) ? REC_DYNSYM
			 : (seen_non_external_sym->k == static_descr::SYMTAB) ? REC_SYMTAB
			 : (assert(false), REC_EXTRASYM),
			begin()->k,
			maybe_sym_idx,
			*saw_sym
		};
		return s;
	}
	/* Else we only saw external syms, if any syms at all.
	 * Dynsyms are never external, so this means we didn't see one. */
	assert(this->begin()->k != static_descr::DYNSYM);
	/* FIXME: use information from the external sym if we have one.
	 * If we have both DWARF and a symbol, we need to choose/merge.
	 * We resolved the size differences above, so assert that they
	 * are the same. */
	if (maybe_sym_name && maybe_dwarf_name && *maybe_sym_name != *maybe_dwarf_name)
	{
		/* HMM. Do we want to emit both? */
		cerr << "Warning: saw differing names in symbol and DWARF: "
			<< *maybe_sym_name << ", " << *maybe_dwarf_name << std::endl;
	}
	if (saw_sym && maybe_expected_size) assert(saw_sym->st_size == *maybe_expected_size);
	summary s = {
		opt_name,
		maybe_die,
		type_from_die(maybe_die),
		REC_EXTRASYM,
		begin()->k,
		maybe_sym_idx,
		saw_sym ? *saw_sym : opt<ElfW(Sym)>()
	};
	return s;
}
vector<pair< sticky_root_die::sym_with_ctxt, opt<string> > > sticky_root_die::get_extrasyms()
{
	vector<pair<sym_with_ctxt, opt<string> > > extrasyms;
	// add the null initial entry
	extrasyms.push_back(make_pair(sym_with_ctxt(), opt<string>()));
	auto statics = get_sanely_described_statics();
	/* For each range we have a *set* of metadata descriptions.
	 * Here we just want the "extrasyms", i.e. things that have DWARF info
	 * but no symbol (or have an external/stripped symbol but no in-binary symbol). */
	for (auto i_int = statics.begin(); i_int != statics.end(); ++i_int)
	{
		auto& interval = i_int->first;
		auto& descr_set = i_int->second;
		assert(sticky_root_die::static_interval_is_sanely_described(*i_int));
		//auto maybe_extrasym = statics.generate_extrasym_if_necessary(
		//	this->symtab_is_external(), i_int->first, i_int->second);
		auto summary = i_int->second.get_summary(this->symtab_is_external(),
		/* expected size */ opt<unsigned>(i_int->first.upper() - i_int->first.lower()));
		if (summary.k == REC_EXTRASYM)
		{
			sym_with_ctxt s(i_int->first, summary);
			extrasyms.push_back(make_pair(s, summary.name));
		}
	}
	return extrasyms;
}

} // end namespace tool
} // end namespace allocs
