#ifndef DUMPALLOCS_HELPERS_HPP_
#define DUMPALLOCS_HELPERS_HPP_

#include <sstream>
#include <fstream>
#include <memory>
#include <cstdint>
#include <dwarfpp/lib.hpp>
#include <srk31/rotate.hpp>
#include <cxxgen/cxx_compiler.hpp>
#include <cstdint>
#include <iomanip>
#include <deque>
#include <map>
#include <locale.h>
#include <elf.h>
#include <srk31/selective_iterator.hpp>

#include "config.h"
#if defined(HAVE_GELF_H)
#include <gelf.h>
#elif defined(HAVE_LIBELF_GELF_H)
#include <libelf/gelf.h>
#else
#error "Could not find a gelf.h"
#endif

#include <strings.h> // for bzero()

extern "C" {
#include <link.h>
}

#include "allocmeta-defs.h"
/* HACK: our C enum sym_or_reloc_kind goes in the toplevel namespace, but
 * we define a C++ operator<< for it. */
std::ostream& operator<<(std::ostream& s, const enum sym_or_reloc_kind& k);

/* Like ElfW() in link.h, but for the ELF{32,64}_ST_TYPE macros and similar. */
#define ELFW_ST_TYPE_y(p, enc) \
	ELF ## enc ## _ST_TYPE(p)
// pass-through dummy to actually substitute the "64" or "32", not paste tokens as given
#define ELFW_ST_TYPE_x(info, enc) \
	ELFW_ST_TYPE_y(info, enc)
// the actual macro we wanted to define
#define ELFW_ST_TYPE(info) \
	ELFW_ST_TYPE_x(info, __ELF_NATIVE_CLASS)

// same idea again
#define ELFW_ST_BIND_y(p, enc) \
	ELF ## enc ## _ST_BIND(p)
// pass-through dummy to actually substitute the "64" or "32", not paste tokens as given
#define ELFW_ST_BIND_x(info, enc) \
	ELFW_ST_BIND_y(info, enc)
// the actual macro we wanted to define
#define ELFW_ST_BIND(info) \
	ELFW_ST_BIND_x(info, __ELF_NATIVE_CLASS)

// same idea again
#define ELFW_ST_INFO_y(b, t, enc) \
	ELF ## enc ## _ST_INFO(b, t)
#define ELFW_ST_INFO_x(b, t, enc) \
	ELFW_ST_INFO_y(b, t, enc)
#define ELFW_ST_INFO(b, t) \
	ELFW_ST_INFO_x(b, t, __ELF_NATIVE_CLASS)

// and again
#define ELFW_R_TYPE_y(i, enc) \
	ELF ## enc ## _R_TYPE(i)
#define ELFW_R_TYPE_x(i, enc) \
	ELFW_R_TYPE_y(i, enc)
#define ELFW_R_TYPE(i) \
	ELFW_R_TYPE_x(i, __ELF_NATIVE_CLASS)
#define ELFW_R_SYM_y(i, enc) \
	ELF ## enc ## _R_SYM(i)
#define ELFW_R_SYM_x(i, enc) \
	ELFW_R_SYM_y(i, enc)
#define ELFW_R_SYM(i) \
	ELFW_R_SYM_x(i, __ELF_NATIVE_CLASS)

namespace allocs
{
namespace tool
{

using std::string;
using std::endl;
using std::cerr;
using std::map;
using std::set;
using std::deque;
using std::pair;
using std::make_pair;
using std::multimap;
using std::istringstream;
using namespace dwarf;
using spec::opt;
using lib::Dwarf_Unsigned;
using lib::Dwarf_Addr;
using dwarf::core::iterator_df;
using dwarf::core::type_die;
using dwarf::core::variable_die;
using dwarf::core::subprogram_die;
using dwarf::core::program_element_die;
using dwarf::core::root_die;
using dwarf::core::iterator_base;
using dwarf::lib::No_entry;

ElfW(Half) find_shndx_by_sht(Elf *e, ElfW(Half) sht);
ElfW(Half) find_shndx(Elf *e, std::function<bool(unsigned, GElf_Shdr *)> pred,
	GElf_Shdr *out_shdr = nullptr);
inline GElf_Shdr get_shdr(Elf *e, unsigned ndx)
{ GElf_Shdr shdr; bzero(&shdr, sizeof shdr);
  find_shndx(e, [ndx](unsigned u, GElf_Shdr *) { return u == ndx; }, &shdr);
  return shdr; }
Elf_Data *raw_data_by_shndx(Elf *e, ElfW(Half) ndx);

/* This is the root_die subclass we use for most type-gathering
 * metadata processing. Originally it was designed to make type DIEs
 * sticky, but this seems to hurt rather than help performance.
 * It provides access to the symtab of the ELF file -- but note
 * that this might be a separate debuginfo file, not the target
 * ELF binary proper.*/
struct sticky_root_die : public root_die
{
	using root_die::root_die;
	
	const int dwarf_fd;
	const int base_elf_fd;
	Elf *base_elf_if_different;
private:
	static bool is_base_object(int user_fd);
	static bool has_dwarf(int user_fd);
	static int open_debuglink(int user_fd);
	static int open_debug_via_build_id(int user_fd);

public:
	static shared_ptr<sticky_root_die> create(int user_fd);
	sticky_root_die(int dwarf_fd, int base_elf_fd) : root_die(dwarf_fd),
		dwarf_fd(dwarf_fd), base_elf_fd(base_elf_fd),
		base_elf_if_different(dwarf_fd == base_elf_fd ? nullptr :
			elf_begin(base_elf_fd, ELF_C_READ, nullptr)) {}

	virtual bool is_sticky(const core::abstract_die& d) 
	{
		return this->root_die::is_sticky(d)
			// || dwarf::spec::DEFAULT_DWARF_SPEC.tag_is_type(d.get_tag())
			;
	}

	// FIXME: support non-host-native size
private:
	opt<ElfW(Sym) *> opt_symtab;
	char *strtab;
	unsigned symtab_n;
	Elf *symtab_e;
	opt<ElfW(Sym) *> opt_dynsym;
	char *dynstr;
	unsigned dynsym_n;
	Elf *dynsym_e;
public:
	/* FIXME: can we have multiple .symtabs? For the moment we assume no,
	 * i.e. we look first in the base obj, then in the separate DWARF obj. */
	pair<pair<ElfW(Sym) *, char*>, pair<Elf *, unsigned> > get_symtab();
	bool symtab_is_external()
	{ auto symtab = get_symtab();
	  return symtab_e != dynsym_e && symtab.second.first == symtab_e; }
	Elf *get_base_elf() { return base_elf_if_different ? base_elf_if_different : get_elf(); }
	pair<pair<ElfW(Sym) *, char*>, pair<Elf *, unsigned> > get_dynsym();
	pair<pair<ElfW(Sym) *, char*>, pair<Elf *, unsigned> > find_symbols(bool use_dynsym);
	~sticky_root_die()
	{
		if (opt_symtab)
		{
			// FIXME: free the stuff
		}
		if (opt_dynsym)
		{
			// FIXME: free the stuff
		}

		// this->root_die::~root_die(); // uncomment this when ~root_die is virtual. OH. it is.
	}
	/* There are many kinds of record in ELF binaries that effectively describe
	 * statically allocated chunk of memory. This is a common abstraction to
	 * all of them, allowing access to the underlying record. */
	struct static_descr
	{
		/* The ordering here reflects our "priority" for where the info comes from:
		 * kinds appearing sooner have more priority. This shows up in a few places:
		 * - which name "wins";
		 * - the debugging output in -extrasyms.c files, describing where the info comes from;
		 * - . */
		enum kind { DWARF, DYNSYM, SYMTAB, REL, DYNREL, UNKNOWN } k;
	protected:
		//union
		//{
			pair< pair<unsigned, ElfW(Sym) *>, const char *> sym;
			iterator_df<program_element_die> d;
			// for relocations, we compute the important stuff on addition and then ignore the rest
			pair<Dwarf_Addr, unsigned> reltgt;
		//};
	public:
		      pair< pair<unsigned, ElfW(Sym) *>, const char *>& get_sym()       { assert(k == DYNSYM || k == SYMTAB); return sym; }
		const pair< pair<unsigned, ElfW(Sym) *>, const char *>& get_sym() const { assert(k == DYNSYM || k == SYMTAB); return sym; }
		iterator_df<program_element_die>&       get_d()         { assert(k == DWARF); return d; }
		const iterator_df<program_element_die>& get_d()   const { assert(k == DWARF); return d; }
		      pair<Dwarf_Addr, unsigned >& get_reltgt()            { assert(k == REL || k == DYNREL); return reltgt; }
		const pair<Dwarf_Addr, unsigned >& get_reltgt() const      { assert(k == REL || k == DYNREL); return reltgt; }
		static_descr() : k(UNKNOWN) {}
		static_descr(iterator_df<program_element_die> d) : k(DWARF), d(d) {}
		static_descr(kind k, const pair< pair<unsigned, ElfW(Sym) *>, const char *>& p) : k(k), sym(p)
		{ assert(k == SYMTAB || k == DYNSYM); }
		static_descr(const static_descr& arg)
		 : k(arg.k)
		{
			switch (arg.k)
			{
				case DYNSYM:
				case SYMTAB:
					this->get_sym() = arg.get_sym();
					break;
				case DWARF:
					this->get_d() = arg.get_d();
					break;
				case REL:
				case DYNREL:
					this->get_reltgt() = arg.get_reltgt();
					break;
				case UNKNOWN:
				default:
					assert(false);
			}
		}
		bool operator==(const static_descr& arg) const
		{ return (arg.k == this->k) &&
			((k == DWARF) ? (arg.get_d() == this->get_d())
			 : (k == SYMTAB || k == DYNSYM) ? (arg.get_sym() == this->get_sym())
			 : arg.get_reltgt() == this->get_reltgt());
		}
		bool operator<(const static_descr& arg) const
		{
			if (arg.k != this->k) return this->k < arg.k;
			switch (k)
			{
				case DYNSYM:
				case SYMTAB:
					return this->get_sym() < arg.get_sym();
				case DWARF:
					return this->get_d() < arg.get_d();
				case REL:
				case DYNREL:
					return this->get_reltgt() < arg.get_reltgt();
				case UNKNOWN:
				default:
					assert(false);
			}
		}
		boost::icl::discrete_interval<Dwarf_Addr> address_range() const;
		~static_descr() {}
		friend std::ostream& operator<<(std::ostream& s, const static_descr& descr);
		friend std::ostream& operator<<(std::ostream& s, const kind& descr);
	};
	/* Since a given static may have many descriptions -- e.g. a dynsym entry,
	 * a symtab entry and also a DWARF record -- we collect sets of them
	 * and define aggregate operations that merge the available information. */
	struct static_descr_set : public set<static_descr>
	{
		using set::set;
		sym_or_reloc_kind get_symbol_kind() const;
		struct summary
		{
			opt<string> name;
			iterator_df<program_element_die> pe;
			iterator_df<type_die> t;
			sym_or_reloc_kind k;
			static_descr::kind descr_priority_k;
			opt<unsigned> maybe_idx;
			opt<ElfW(Sym)> maybe_sym;
			//summary() : k(REC_UNKNOWN), descr_priority_k(static_descr::UNKNOWN) {}
			static inline summary default_value()
			{
				struct summary s;
				bzero(&s, sizeof s);
				s.descr_priority_k = static_descr::UNKNOWN;
				return s;
			}
		};
		summary
		get_summary(bool symtab_is_external, opt<unsigned> maybe_expected_size = opt<unsigned>()) const;
		iterator_df<program_element_die> get_die() const;
		iterator_df<type_die> type_from_die(iterator_df<program_element_die> maybe_die) const
		{ return (maybe_die && maybe_die.is_a<variable_die>()) ? maybe_die.as_a<variable_die>()->find_type()
			 : (maybe_die && maybe_die.is_a<subprogram_die>()) ? maybe_die.as_a<type_die>()
			 :  iterator_df<type_die>(iterator_base::END);
		}
		iterator_df<type_die> get_type() const
		{ return get_die() ? type_from_die(get_die()) : iterator_df<type_die>(); }
	};
	// FIXME: we need a way to relax the no-overlap in certain conditions.
	// I'm not sure how to handle this.
	// Two conditions spring to mind: the use of symbol versioning to create
	// overlapping arrays, and the use of string merging to create overlapping
	// character arrays. With character arrays we probably want to "take the
	// biggest" of the overlap. With symbol versioning, we could do the same,
	// assuming the overlap is only at one end. Then how do we record the
	// fact provided by the symbol version i.e. that an alternative definition
	// exists which is shorter?
	static bool static_interval_is_sanely_described(
		const pair<
			const boost::icl::discrete_interval<Dwarf_Addr>,
			std::set<sticky_root_die::static_descr>
		>& p
	)
	{
		/* Our description's address range should match our interval's.
		 * FIXME: sometimes different versions of the same symbol are overlapping,
		 * so trigger the "insane" case. What should we do about those?
		 */
		boost::icl::discrete_interval<Dwarf_Addr> interval = p.first;
		for (auto i_descr = p.second.begin(); i_descr != p.second.end(); ++i_descr)
		{
			if (i_descr->address_range() != interval)
			{
				std::cerr << "Warning: saw static descr (";
				std::cerr << *i_descr;
				std::cerr << ") whose address range ";
				std::cerr << i_descr->address_range();
				std::cerr << " does not match interval ";
				std::cerr << interval;
				std::cerr << std::endl;
				return false;
			}
		}
		return true;
	}
	boost::icl::interval_map< Dwarf_Addr, static_descr_set >
	get_statics();
	struct is_sane_t
	{
		inline bool operator()(
			const boost::icl::interval_map< Dwarf_Addr, static_descr_set >::iterator& it) const
		{
			return static_interval_is_sanely_described(*it);
		}
	};
	typedef srk31::selective_iterator<
		is_sane_t,
		boost::icl::interval_map< Dwarf_Addr, static_descr_set >::iterator
	> sane_interval_iterator;
	struct sym_with_ctxt : ElfW(Sym), static_descr_set::summary
	{
		sym_with_ctxt(const boost::icl::discrete_interval<Dwarf_Addr>& interval,
			const static_descr_set::summary& summary) :
			static_descr_set::summary(summary)
		{
			this->st_value = interval.lower();
			this->st_size = interval.upper() - interval.lower(),
			this->st_info = summary.maybe_sym ? summary.maybe_sym->st_info : ELFW_ST_INFO(STB_LOCAL, STT_OBJECT),
			this->st_other = summary.maybe_sym ? summary.maybe_sym->st_other : STV_HIDDEN;
		}
		// need a default for the summy initial symbol
		sym_with_ctxt() : summary(summary::default_value())//: die_offset(0), sym_index(0), k(REC_UNKNOWN)
		{}
	};
	struct sane_interval_map : boost::icl::interval_map< Dwarf_Addr, static_descr_set >
	{
		typedef typename std::set<sticky_root_die::static_descr> descr_set;
		typedef typename boost::icl::interval_map< Dwarf_Addr, static_descr_set > super;
		using super::interval_map;
		sane_interval_iterator begin()
		{ return sane_interval_iterator(this->super::begin(),
			this->super::end()); }
		sane_interval_iterator end()
		{ return sane_interval_iterator(this->super::end(),
			this->super::end()); }
#if 0
		opt<pair<sym_with_ctxt, opt<string> > > generate_extrasym_if_necessary(
			bool symtab_is_external,
			const boost::icl::discrete_interval<Dwarf_Addr>& interval,
			const static_descr_set& descrs
		);
		opt<uniqued_name> get_type(
			bool symtab_is_external,
			const boost::icl::discrete_interval<Dwarf_Addr>& interval,
			const static_descr_set& descrs
		);
#endif
	};
	sane_interval_map
	get_sanely_described_statics()
	{
		return sane_interval_map(get_statics());
	}
	vector<pair< sym_with_ctxt, opt<string> > > get_extrasyms();
};
inline std::ostream& operator<<(std::ostream& s, const sticky_root_die::static_descr::kind& k)
{
	switch (k)
	{
		case sticky_root_die::static_descr::DYNSYM: s << "DYNSYM"; break;
		case sticky_root_die::static_descr::SYMTAB: s << "SYMTAB"; break;
		case sticky_root_die::static_descr::DWARF: s << "DWARF"; break;
		case sticky_root_die::static_descr::REL: s << "REL"; break;
		case sticky_root_die::static_descr::DYNREL: s << "DYNREL"; break;
		case sticky_root_die::static_descr::UNKNOWN:
		default:
			s << "UNKNOWN"; break;
	}
	return s;
}
inline std::ostream& operator<<(std::ostream& s, const sticky_root_die::static_descr& descr)
{
	switch (descr.k)
	{
		case sticky_root_die::static_descr::DYNSYM:
		case sticky_root_die::static_descr::SYMTAB:
		// print_sym:
			s << descr.k << ", name: " << descr.get_sym().second;
			break;
		case sticky_root_die::static_descr::DWARF:
			s << descr.k << " " << descr.get_d().summary();
			break;
		case sticky_root_die::static_descr::REL:
		case sticky_root_die::static_descr::DYNREL:
			s << "target addr 0x" << std::hex << descr.get_reltgt().first
				<< std::dec << ", length " << descr.get_reltgt().second;
			break;
		case sticky_root_die::static_descr::UNKNOWN:
		default:
			assert(false);
	}
	return s;
}
} // end namespace tool
} // end namespace allocs
#endif
