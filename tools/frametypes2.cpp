/* This is a simple dwarfpp program which generates a C file
 * recording the "stack frame layout" as revealed by DWARF
 * information on local variables (.debug_info)
 * and also unwind information (.eh_frame).
 * For us "stack frame layout" is generalised to include the
 * register file too.
 *
 * We emit in a compact format in which
 * (1) <name, type> pairs are commoned across the whole DSO
 * (2) layouts are pre-elaborated as an ordered list of < pair-id, location >
 *       and are also commoned across the whole DSO
 *       -- locations can be negative offsets again, without bringing back
 *          the woe of having these in uniqtypes
 * (3) the vaddr space is described by a compact list of <vaddr, layout> pairs
 *       -- to enable binary search I think we do want vaddr
 *       -- we could save space by using shortcut vectors and storing less than the whole vaddr
 * (alt) or instead of (2) and (3), do we want a BDD-style/compiler-optimised
 *      decision tree that elaborates the layout on demand?
 *      If we represent the table (3) instead as a giant switch statement,
 *      potentially with millions of cases, how does a compiler optimise it?
 *      Then try an eh-elfs-style binary tree for comparison.
 */
 
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/icl/interval_map.hpp>
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <cxxgen/tokens.hpp>
#include <dwarfpp/lib.hpp>
#include <dwarfpp/frame.hpp>
#include <dwarfpp/regs.hpp>
#include <fileno.hpp>

#include "stickyroot.hpp"
#include "uniqtypes.hpp"
#include "relf.h"

using std::cin;
using std::cout;
using std::cerr;
using std::map;
using std::make_shared;
using std::ios;
using std::ifstream;
using std::dynamic_pointer_cast;
using boost::optional;
using std::ostringstream;
using std::set;
using namespace dwarf;
//using boost::filesystem::path;
using dwarf::core::iterator_base;
using dwarf::core::iterator_df;
using dwarf::core::iterator_sibs;
using dwarf::core::type_die;
using dwarf::core::subprogram_die;
using dwarf::core::compile_unit_die;
using dwarf::core::member_die;
using dwarf::core::with_data_members_die;
using dwarf::core::variable_die;
using dwarf::core::program_element_die;
using dwarf::core::with_static_location_die;
using dwarf::core::with_dynamic_location_die;
using dwarf::core::address_holding_type_die;
using dwarf::core::array_type_die;
using dwarf::core::type_chain_die;
using dwarf::encap::loc_expr;

using namespace dwarf::lib;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

using namespace allocs::tool;

static int debug_out = 1;

using dwarf::lib::Dwarf_Off;
using dwarf::lib::Dwarf_Addr;
using dwarf::lib::Dwarf_Signed;
using dwarf::lib::Dwarf_Unsigned;

using std::unordered_set;

template <class Target>
struct iter_hash
{
	typedef iterator_df<Target> T;
	
	static size_t hash_fn(const T& v) { return v.offset_here(); }
	static bool eq_fn(const T& v1, const T& v2)
	{ return v1.offset_here() == v2.offset_here(); }
	
	struct set : unordered_set<
		T,
		std::function<__typeof__(hash_fn)>,
		std::function<__typeof__(eq_fn)>
	>
	{
		set() : unordered_set<T, std::function<__typeof__(hash_fn)>, std::function<__typeof__(eq_fn)> >({}, 0, hash_fn, eq_fn) {}
	};
};

template <class Target, class Second>
struct iterfirst_pair_hash
{
	typedef pair<iterator_df<Target>, Second> T;
	
	static size_t hash_fn(const T& v)
	{ return v.first.offset_here() ^ std::hash<Second>()(v.second); }
	static bool eq_fn(const T& v1,  const T& v2)
	{ return v1.first.offset_here() == v2.first.offset_here(); }

	struct set : unordered_set< 
		T,
		std::function<__typeof__(hash_fn)>,
		std::function<__typeof__(eq_fn)>
	>
	{
		set() : unordered_set<T, std::function<__typeof__(hash_fn)>, std::function<__typeof__(eq_fn)> >
			({}, 0, hash_fn, eq_fn) 
			{}
	};
};

template <class First, class Target>
struct itersecond_pair_hash
{
	typedef pair<First, iterator_df<Target> > T;
	
	static size_t hash_fn(const T& v) 
	{ return v.second.offset_here() ^ std::hash<First>()(v.first); }
	static bool eq_fn(const T& v1, 	const T& v2)
	{ return v1.first == v2.first &&
	    v1.second.offset_here() == v2.second.offset_here(); }

	struct set : unordered_set< 
		T,
		std::function<__typeof__(hash_fn)>,
		std::function<__typeof__(eq_fn)>
	>
	{
		set() : unordered_set<T, std::function<__typeof__(hash_fn)>, std::function<__typeof__(eq_fn)> >
			({}, 0, hash_fn, eq_fn) 
			{}
	};
};


namespace std {
template <>
struct hash<const dwarf::lib::Dwarf_Loc>
{
	size_t operator()(const dwarf::lib::Dwarf_Loc& v)
	{
		size_t working = 0;
		working ^= v.lr_atom;
		working ^= v.lr_number;
		working ^= v.lr_number2;
		working ^= v.lr_offset;
		return working;
	}
};
template <>
struct hash<dwarf::encap::loc_expr>
{
	size_t operator()(const dwarf::encap::loc_expr& v)
	{
		size_t working = 0;
		for (auto i = v.begin(); i != v.end(); ++i)
		{
			working ^= std::hash<__typeof__(*i)>()(*i);
		}
		return working;
	}
};
}

// typedef iterfirst_pair_hash< 
// 	with_dynamic_location_die, encap::loc_expr/* ,
// 	compare_first_iter_offset<encap::loc_expr> */
// >::set live_set_t;
// typedef boost::icl::interval_map< Dwarf_Off, live_set_t > varset_intervals_t;
struct frame_interval_map_set_value
 : pair< iterator_df< with_dynamic_location_die >,
         pair< Dwarf_Unsigned /* caller regnum */, loc_expr /* where */ >
       >
{
	using pair::pair;
	frame_interval_map_set_value(Dwarf_Unsigned reg, const loc_expr& expr)
	 : pair(iterator_base::END, make_pair(reg, expr)) {}
	frame_interval_map_set_value(iterator_df<with_dynamic_location_die> d)
	 : pair(d, make_pair(0, loc_expr())) { assert(d); }
	opt<Dwarf_Unsigned> get_caller_regnum() const
	{ if (first == iterator_base::END) return second.first; return opt<Dwarf_Unsigned>(); }
	opt<loc_expr> get_save_location() const
	{ if (first == iterator_base::END) return second.second; return opt<loc_expr>(); }
	iterator_df<with_dynamic_location_die> get_die() const
	{ return first; }
};
struct compare_frame_interval_map_set_value
{
	bool operator()(const frame_interval_map_set_value& x,
		            const frame_interval_map_set_value& y)
		const
	{
		return (x.first < y.first)
			|| ((x.first == y.first) && x.second < y.second)
		//	|| ((x.first == y.first) && x.second.first.offset_here() == y.second.first.offset_here()
		//		&& x.second.first.second.second < y.second.first.second.second );
		;
	}
};

typedef set< frame_interval_map_set_value, compare_frame_interval_map_set_value >
   frame_interval_map_set_t;
typedef boost::icl::interval_map<
		Dwarf_Off /* interval base type */,
		frame_interval_map_set_t
	> frame_intervals_t;

typedef boost::icl::interval_map< 
		Dwarf_Off /* interval base type */,
		iterfirst_pair_hash< 
			with_dynamic_location_die,
			string
		>::set/* ,
			compare_first_iter_offset<string> */
	> discarded_intervals_t;

#ifndef NDEBUG
// used for sanity-checking
unsigned count_intervals(const frame_intervals_t& f)
{
	unsigned count = 0;
	for (auto i = f.begin(); i != f.end(); ++i, ++count);
	return count;
}
template<typename _Key, typename _Compare = std::less<_Key>,
	   typename _Alloc = std::allocator<_Key> >
bool sanity_check_set(const std::set<_Key, _Compare, _Alloc>& s)
{
	unsigned count = 0;
	for (auto i = s.begin(); i != s.end(); ++i, ++count);
	return count == s.size();
}
#endif
struct iterator_bf_skipping_types : public core::iterator_bf<>
{
	typedef core::iterator_bf<> super;
	void increment(unsigned min_depth)
	{
		/* The idea here is not that we skip types per se.
		 * It's that we skip the children of types, e.g.
		 * local vars or formals that actually belong to
		 * methods. Remember that subprograms are types.
		 * Also remember that we're allowed to start above
		 * the minimum depth. */
		if (*this != END && depth() < min_depth)
		{
			this->increment_skipping_siblings();
		}
		else if (tag_here() != DW_TAG_subprogram &&
			spec_here().tag_is_type(tag_here()))
		{
			this->increment_skipping_subtree();
		} else this->super::increment();
		if (*this != END && depth() < min_depth) *this = END;
	}
	void increment() { this->increment(0); }
	// forward constructors
	using core::iterator_bf<>::iterator_bf;
};

void print_sp_expr(sticky_root_die& root, Dwarf_Addr lower, Dwarf_Addr upper)
{
	/* Last question. What's the stack pointer in terms of the 
	 * CFA? We can answer this question by faking up a location
	 * list referring to the stack pointer, and asking libdwarfpp
	 * to rewrite that.*/
	cerr << "Calculating rewritten-SP loclist..." << endl;
	auto sp_loclist = encap::rewrite_loclist_in_terms_of_cfa(
		encap::loclist(dwarf_stack_pointer_expr_for_elf_machine(
			root.get_frame_section().get_elf_machine(),
			lower, upper
		)),
		root.get_frame_section(), 
		dwarf::spec::opt<const encap::loclist&>() /* opt_fbreg */
	);
	cerr << "Got SP loclist " << sp_loclist << endl;
}

static
void print_intervals_stats(sticky_root_die& root, /* iterator_df<subprogram_die> i_subp, */
	const frame_intervals_t& frame_intervals)
{
	cerr << "frame intervals" // for " << i_subp->summary() 
		//<< " in compilation unit " << i_subp.enclosing_cu().summary()
		<< " now contains "
		<< frame_intervals.size()
		<< " intervals, with total set size ";
	unsigned count = 0;
	for (auto i_int = frame_intervals.begin(); i_int != frame_intervals.end(); ++i_int)
	{
		count += i_int->second.size();
	}
	cerr << count << std::endl;
}

static
with_static_location_die::sym_binding_t
resolve_subp_address(iterator_df<subprogram_die> i_subp, sticky_root_die& root)
{
	/* We need this symbol resolver because sometimes the DWARF info
	 * won't include a with-address-range entry for a function. I have
	 * seen this for external-definition-emitted C99 inline functions
	 * in gcc 7.2.x, but other cases are possible. */
	Dwarf_Off file_relative_start_addr; 
	Dwarf_Unsigned size;

	if (!i_subp.name_here()) throw No_entry();
	string s = *i_subp.name_here();

	/* FIXME: account for linkage name, name mangling, etc. */
	auto symtab_etc = root.get_symtab();
	auto &symtab = symtab_etc.first.first;
	auto &strtab = symtab_etc.first.second;
	unsigned &n = symtab_etc.second.second;

	for (auto p = symtab; p < symtab + n; ++p)
	{
		if (p->st_name != 0 && string(strtab + p->st_name) == s)
		{
			return (with_static_location_die::sym_binding_t)
			{ p->st_value, p->st_size };
		}
	}

	throw No_entry();
}

struct subprogram_key : public pair< pair<string, string>, string > // ordering for free
{
	subprogram_key(const string& subprogram_name, const string& sourcefile_name, 
		const string& comp_dir) : pair(make_pair(subprogram_name, sourcefile_name), comp_dir) {}
	string subprogram_name() const { return first.first; }
	string sourcefile_name() const { return first.second; }
	string comp_dir() const { return second; }
};

/* We gather subprograms by the ranges they cover
 * AND by their identity (key).
 * We also store a key although. */
typedef boost::icl::interval_map<
	Dwarf_Off,
	/* It's a set only so that we can detect and warn about overlaps... */
	std::set< pair< subprogram_key, iterator_df<subprogram_die> > >
> subprogram_vaddr_interval_map_t;

void
gather_defined_subprograms(sticky_root_die& root,
	subprogram_vaddr_interval_map_t& out_by_vaddr,
	map<subprogram_key, iterator_df<subprogram_die> >& out_by_key
	)
{
	map<subprogram_key, iterator_df<subprogram_die> > gathered;
	for (iterator_df<> i = root.begin(); i != root.end(); ++i)
	{
		if (i.is_a<subprogram_die>())
		{
			auto i_cu = i.enclosing_cu();
			
			iterator_df<subprogram_die> i_subp = i;
			// only add real, defined subprograms to the list
			if (
				// not a declaration
				(!i_subp->get_declaration() || !*i_subp->get_declaration()) &&
				// not an "abstract instance"
				// FIXME: lift this up into libdwarfpp
				(!i_subp->get_inline() || *i_subp->get_inline() == DW_INL_not_inlined)
			)
			{
				string sourcefile_name = i_subp->get_decl_file() ? 
					i_cu->source_file_name(*i_subp->get_decl_file())
					: "(unknown source file)";
				string comp_dir = i_cu->get_comp_dir() ? *i_cu->get_comp_dir() : "";

				string subp_name;
				if (i_subp.name_here()) subp_name = *i_subp.name_here();
				else 
				{
					std::ostringstream s;
					s << "0x" << std::hex << i_subp.offset_here();
					subp_name = s.str();
				}

				subprogram_key k(subp_name, sourcefile_name, comp_dir);
				auto ret = out_by_key.insert(make_pair(k, i_subp));
				if (!ret.second)
				{
					/* This means that "the same value already existed". */
					cerr << "Warning: subprogram " << *i_subp
						<< " already in subprograms_list as " 
						<< ret.first->first.subprogram_name() 
						<< " (in " 
						<< ret.first->first.sourcefile_name()
						<< ", compiled in " << ret.first->first.comp_dir()
						<< ")"
						<< endl;
				}
				auto all_intervals = i_subp->file_relative_intervals(root, nullptr, nullptr);
				cerr << "Adding subprogram " << i_subp.summary()
					<< " with intervals: ";
				for (auto i_int = all_intervals.begin(); i_int != all_intervals.end();
					++i_int)
				{
					set< pair< subprogram_key, iterator_df<subprogram_die> > > singleton_set;
					singleton_set.insert(make_pair(k, i_subp));
					if (i_int != all_intervals.begin()) cerr << ", ";
					cerr << std::hex << i_int->first << std::dec;
					out_by_vaddr.insert(make_pair(
						i_int->first,
						singleton_set
					));
				}
				cerr << endl;
			}
		}
	}
}
static bool
locexpr_is_for_all_vaddrs(const loc_expr& locexpr)
{
	return locexpr.lopc == 0 && 0 == locexpr.hipc
		|| locexpr.lopc == 0 && locexpr.hipc == std::numeric_limits<Dwarf_Off>::max();
}

static bool
locexpr_is_base_address_selector(const loc_expr& locexpr, root_die& root)
{
	// FIXME: disgusting hack for detecting base address selection entries
	// -- should be sensitive to DWARF word size
	return locexpr.lopc == 0xffffffffffffffffULL
				|| locexpr.lopc == 0xffffffffUL;
}

static
vector<boost::icl::discrete_interval<Dwarf_Off> >
intervals_for_local_var_locexpr(const loc_expr& locexpr, iterator_df<subprogram_die> i_subp,
	iterator_df<with_dynamic_location_die> i_dyn, sticky_root_die& root)
{
	vector<boost::icl::discrete_interval<Dwarf_Off> > out;
	if (locexpr_is_for_all_vaddrs(locexpr))
	{
		/* we will just add the intervals of the containing subprogram */
		auto subp_intervals = i_subp->file_relative_intervals(root, nullptr, nullptr);
			//pc_intervals_by_subprogram[i_subp]; // re-use cached
		for (auto i_subp_int = subp_intervals.begin();
			i_subp_int != subp_intervals.end(); 
			++i_subp_int)
		{
			out.push_back(i_subp_int->first);
			cerr << "Borrowing vaddr ranges of " << *i_subp
				<< " for dynamic-location " << *i_dyn << endl;
			// print_sp_expr(root, our_interval.lower(), our_interval.upper());
			// print_intervals_stats(root, i_subp, subp_frame_intervals);
		}
	}
	else /* we have nonzero lopc and/or hipc */
	{
		/* We *do* have to adjust these by cu_base, because 
		 * we're getting them straight from the location expression. */
		auto opt_cu_base = i_subp.enclosing_cu()->get_low_pc();
		if (!opt_cu_base)
		{
			cerr << "ERROR: subprogram " << *i_subp 
				<< " -- in CU with no base address (CU: "
				<< *i_subp.enclosing_cu()
				<< ")" << endl;
			abort();
			// FIXME: can CUs use DW_AT_ranges instead? should handle this if so
		}
		auto our_interval = boost::icl::interval<Dwarf_Off>::right_open(
			locexpr.lopc + opt_cu_base->addr, locexpr.hipc + opt_cu_base->addr
		); 
		out.push_back(our_interval);

		/* assert sane interval */
		assert(our_interval.lower() < our_interval.upper());
		/* assert sane size -- no bigger than biggest sane function */
		assert(our_interval.upper() - our_interval.lower() < 1024*1024);
		// print_sp_expr(root, our_interval.lower(), our_interval.upper());
		// print_intervals_stats(root, i_subp, subp_frame_intervals);
	}
	return out;
}

void
gather_local_var_locations_by_pc_interval(
	frame_intervals_t& out,
	iterator_df<subprogram_die> i_subp,
	sticky_root_die& root)
{
	unsigned start_depth = i_subp.depth();
	for (iterator_bf_skipping_types i_bf = i_subp;
		i_bf != core::iterator_base::END;
		/* After the first inc, we should always be at *at least* 1 + start_depth. */
		i_bf.increment(start_depth + 1))
	{
		// skip if not a with_dynamic_location_die
		if (!i_bf.is_a<with_dynamic_location_die>()) continue;

		// skip static variables
		if (i_bf.is_a<variable_die>() && i_bf.as_a<variable_die>()->has_static_storage())
		{
			// FIXME: check that symbol-less static variables
			// are handled in extrasyms.
			continue;
		}
		auto i_dyn = i_bf.as_a<with_dynamic_location_die>();
		// skip member/inheritance DIEs
		if (i_dyn->location_requires_object_base()) continue;

		/* enumerate the vaddr ranges of this DIE
		 * -- note that some DIEs will be "for all vaddrs" */
		auto var_loclist = i_dyn->get_dynamic_location();
		// rewrite the loclist to use the CFA/frame_base maximally
#ifdef DEBUG
		cerr << "Saw loclist " << var_loclist << endl;
#endif
		var_loclist = encap::rewrite_loclist_in_terms_of_cfa(
			var_loclist, 
			root.get_frame_section(), 
			dwarf::spec::opt<const encap::loclist&>() /* opt_fbreg */
		);
#ifdef DEBUG
		cerr << "Rewrote to loclist " << var_loclist << endl;
#endif

		// for each of this variable's intervals, add it to the map
		int interval_index = 0;
		for (auto i_locexpr = var_loclist.begin(); 
			i_locexpr != var_loclist.end(); ++i_locexpr)
		{
			if (locexpr_is_base_address_selector(*i_locexpr, root))
			{
				// we got a base address selection entry -- not handled yet
				assert(false);
				abort();
			}
			if (i_locexpr->lopc == i_locexpr->hipc && i_locexpr->hipc != 0) continue; // skip empties
			if (i_locexpr->hipc <  i_locexpr->lopc)
			{
				cerr << "Warning: lopc (0x" << std::hex << i_locexpr->lopc << std::dec
					<< ") > hipc (0x" << std::hex << i_locexpr->hipc << std::dec << ")"
					<< " in " << *i_dyn << endl;
				continue;
			}
			auto opt_cu_base = i_subp.enclosing_cu()->get_low_pc();
			if (!opt_cu_base)
			{
				cerr << "Warning: skipping subprogram " << *i_dyn 
					<< " -- in CU with no base address (CU: "
					<< *i_subp.enclosing_cu()
					<< ")" << endl;
				continue;
				// FIXME: can CUs use DW_AT_ranges instead? should handle this if so
			}
			Dwarf_Unsigned cu_base = opt_cu_base->addr;
			if (locexpr_is_for_all_vaddrs(*i_locexpr))
			{
				// if we have a "for all vaddrs" entry, we should be the only index
				assert(interval_index == 0);
				assert(i_locexpr + 1 == var_loclist.end());
			}

			/* We need to remember not only that each i_dyn is valid 
			 * in a given range, but with what loc_expr. So we pair the i_dyn with
			 * the relevant loc_expr. */
			frame_interval_map_set_t just_this_variable = { i_dyn };
			//just_this_variable_loc_pair.insert(frame_interval_map_set_value(i_dyn));
			//iterfirst_pair_hash< with_dynamic_location_die, encap::loc_expr >::set /*,
			//	compare_first_iter_offset<encap::loc_expr> */ ;
			//just_this_variable_loc_pair.insert(make_pair(i_dyn, *i_locexpr));

			// handle "for all vaddrs" entries
			vector<boost::icl::discrete_interval<Dwarf_Off> > our_intervals
			= intervals_for_local_var_locexpr(*i_locexpr, i_subp, i_bf.as_a<with_dynamic_location_die>(),
				root);
			// An "all vaddrs" entry may have multiple intervals,
			// if a function is not contiguous.
			for (auto i_our_interval = our_intervals.begin();
				i_our_interval != our_intervals.end();
				++i_our_interval)
			{
				auto& our_interval = *i_our_interval;

				/* assert sane interval */
				assert(our_interval.lower() < our_interval.upper());
				/* assert sane size -- no bigger than biggest sane function */
				assert(our_interval.upper() - our_interval.lower() < 1024*1024);

				// add it
				out += make_pair(
					our_interval,
					just_this_variable
				);
			}
		} // end for each locexpr
	} /* end for each var bfs */
}

iterator_df<subprogram_die>
unique_subprogram_at(
	subprogram_vaddr_interval_map_t const& subprograms,
	Dwarf_Addr pc)
{
	iterator_df<subprogram_die> one_seen = iterator_base::END;
	bool unique = true;
	auto i = subprograms.find(pc);
	if (i == subprograms.end()) cerr << "No subprogram found at 0x" << std::hex << pc << std::dec
		<< endl;
	else cerr << "First subprogram found at 0x" << std::hex << pc << std::dec
		<< " has interval " << std::hex << i->first << std::dec << endl;
	unsigned nseen = 0;
	for (; i != subprograms.end() && i->first.lower() <= pc; ++i, ++nseen)
	{
		if (i->second.size() == 0) continue;
		if (i->second.size() > 1 || one_seen)
		{
			unique = false;
			cerr << "Over interval (" << std::hex << i->first.lower()
				<< ", " << i->first.upper() << "]" << std::dec
				<< ", found multiple (" << i->second.size() << ") subprograms: {";
			for (auto i_s = i->second.begin(); i_s != i->second.end(); ++i_s)
			{
				cerr << "Found overlap with subprogram ";
				if (i_s->second.name_here()) cerr << *i_s->second.name_here();
				else cerr << "0x" << std::dec << i_s->second.offset_here() << std::dec;
				cerr << endl;
			}
		}
		if (i->second.size() >= 1 && !one_seen) one_seen = i->second.begin()->second;
	}
	cerr << "nseen at " << std::hex << pc << ": " << std::dec << nseen << endl;
	if (unique && one_seen) return one_seen;
	return iterator_base::END;
}

static
bool is_callee_save_register(int col)
{
	return col == DWARF_X86_64_RBX
		|| col == DWARF_X86_64_RBP
		|| col == DWARF_X86_64_R12
		|| col == DWARF_X86_64_R13
		|| col == DWARF_X86_64_R14
		|| col == DWARF_X86_64_R15;
}

void
gather_saved_register_locations_by_pc_interval(
	frame_intervals_t& out,
	subprogram_vaddr_interval_map_t const& subprograms,
	sticky_root_die& root)
{
	auto process_frame_section = [&out, subprograms](core::FrameSection& fs) {
		using core::FrameSection;
		using core::Cie;
		using dwarf::encap::expr_instr;
		for (auto i_fde = fs.fde_begin(); i_fde != fs.fde_end(); ++i_fde)
		{
			Dwarf_Addr fde_lopc = i_fde->get_low_pc();
			Dwarf_Addr fde_hipc = i_fde->get_low_pc() + i_fde->get_func_length();
			auto fde_interval = boost::icl::interval<Dwarf_Addr>::right_open(fde_lopc, fde_hipc);

			cerr << "Considering FDE beginning 0x" << std::hex << fde_lopc << std::dec << endl;

			/* Enumerate the overlapping subprograms. Warn if the count is not
			 * exactly 1. */
			iterator_df<subprogram_die> i_subp;
			if (!(i_subp = unique_subprogram_at(subprograms, fde_lopc)))
			{
				cerr << "FDE address 0x" << std::hex << fde_lopc << " does not belong"
					<< " to a unique subprogram" << endl;
			}
			/* Enumerate the locations of saved registers */
			const Cie& cie = *i_fde->find_cie();

			cerr << "Processing FDE for range " << std::hex << fde_lopc << "-"
				<< fde_hipc << std::dec << " (subprogram ";
			if (!i_subp) { cerr << "(unknown)"; }
			else
			{
				if (i_subp.name_here()) cerr << *i_subp.name_here();
				else cerr << "0x" << std::hex << i_subp.offset_here() << std::dec;
			}
			cerr << ")" << endl;

			/* decode the FDE */
			auto result = i_fde->decode();
			result.add_unfinished_row(i_fde->get_low_pc() + i_fde->get_func_length());

			// enumerate our columns
			set<int> all_columns;
			all_columns.insert(DW_FRAME_CFA_COL3);
			for (auto i_row = result.rows.begin(); i_row != result.rows.end(); ++i_row)
			{
				for (auto i_reg = i_row->second.begin(); i_reg != i_row->second.end(); ++i_reg)
				{
					all_columns.insert(i_reg->first);
				}
			}
			// visit them
			typedef std::function<void(int, optional< pair<int, FrameSection::register_def> >)>
			 visitor_function;
			int ra_rule_number = cie.get_return_address_register_rule();
			auto visit_columns = [all_columns, ra_rule_number](
				 visitor_function visit, 
				 optional<const set< pair<int, FrameSection::register_def> > &> opt_i_row
				) {

				auto get_column = [&opt_i_row](int col) {

					if (!opt_i_row) return optional< pair<int, FrameSection::register_def> >();
					else
					{
						map<int, FrameSection::register_def> m(opt_i_row->begin(), opt_i_row->end());
						auto found = m.find(col);
						return found != m.end() ? make_pair(found->first, found->second) : optional< pair<int, FrameSection::register_def> >();
					}
				};

				// always visit CFA column
				visit(DW_FRAME_CFA_COL3, get_column(DW_FRAME_CFA_COL3));

				// visit other columns that exist, except the ra rule for now
				for (auto i_col = all_columns.begin(); i_col != all_columns.end(); ++i_col)
				{
					if (*i_col != DW_FRAME_CFA_COL3 && *i_col != ra_rule_number)
					{
						visit(*i_col, get_column(*i_col));
					}
				}

				// finally, always visit the ra rule 
				visit(ra_rule_number, get_column(ra_rule_number));
			};

	#ifndef NDEBUG
			auto sanity_check_post = [](const frame_intervals_t& f, unsigned previous_size) {
				unsigned count = count_intervals(f);
				if (count != f.size())
				{
					cerr << "Warning: count " << count << " != iterative size " << f.iterative_size() 
						<< " (previous size: " << previous_size << ")" 
						<< endl;
				}
				assert(count == f.iterative_size());
				/* Also sanity-check the member sets. */
				for (auto i = f.begin(); i != f.end(); ++i, ++count)
				{
					unsigned set_size = 0;
					for (auto i_s = i->second.begin(); i_s != i->second.end(); ++i_s, ++set_size)
					{

					}
					if (set_size != i->second.size())
					{
						cerr << "Warning: set iterative size " << set_size
							 << " != claimed size() " << i->second.size()
						<< endl;
					}
				}
			};
			#define SANITY_CHECK_PRE(f) /* do { unsigned count = count_intervals(f); \
				cerr << "Adding an interval (width " << (i.upper() - i.lower()) \
					<< " to a map of size " << f.size() << ", count " << count << endl; */ \
					do { for (auto i = f.begin(); i != f.end(); ++i) { \
						assert(sanity_check_set(i->second)); \
					} } while (0)

			#define SANITY_CHECK_POST(f) /* sanity_check_post(f, count); } while (0) */
	#else
			#define SANITY_CHECK_PRE(f) do { 
			#define SANITY_CHECK_POST(f)  } while (0)
	#endif

			visitor_function row_column_visitor = [all_columns, ra_rule_number,
				fde_lopc, fde_hipc, &out]
				(int col, optional< pair<int, FrameSection::register_def> > found_col)  -> void {

				if (!found_col /*|| !is_callee_save_register(col)*/) {} // s << std::left << "u" << std::right;
				else
				{
					switch (found_col->second.k)
					{
						case FrameSection::register_def::INDETERMINATE:
						case FrameSection::register_def::UNDEFINED: 
							break;

						case FrameSection::register_def::REGISTER: {
							// caller's register "col" is saved in callee register "regnum"
							int regnum = found_col->second.register_plus_offset_r().first;
							frame_interval_map_set_value v(col,
								{ (expr_instr) { .lr_atom = DW_OP_reg0 + regnum } });

							SANITY_CHECK_PRE(out);
							out += make_pair(
								boost::icl::interval<Dwarf_Addr>::right_open(
									fde_lopc,
									fde_hipc
								),
								frame_interval_map_set_t({ v })
							);
							SANITY_CHECK_POST(out);
						} break;

						case FrameSection::register_def::SAVED_AT_OFFSET_FROM_CFA: {
							int saved_offset = found_col->second.saved_at_offset_from_cfa_r();
							// caller's register "col" is saved at "saved_offset" from CFA
							frame_interval_map_set_value v(col,
								{ (expr_instr) { .lr_atom = DW_OP_call_frame_cfa },
								  (expr_instr) { .lr_atom = DW_OP_consts, .lr_number = saved_offset },
								  (expr_instr) { .lr_atom = DW_OP_plus } });
							frame_interval_map_set_t singleton_set = { v };
							//singleton_set.insert(
							//    make_pair(iterator_base::END /* not a with_dynamic_location_die */,
							//              make_pair(regnum /* yes a saved caller reg */,
							//                (loc_expr) 
							//);
							SANITY_CHECK_PRE(out);
							out += make_pair(
								boost::icl::interval<Dwarf_Addr>::right_open(
									fde_lopc,
									fde_hipc
								),
								singleton_set
							);
							SANITY_CHECK_POST(out);
						} break;
						case FrameSection::register_def::SAVED_AT_EXPR:
							// we can't represent this. :-(
							break;
						case FrameSection::register_def::VAL_IS_OFFSET_FROM_CFA:
						case FrameSection::register_def::VAL_OF_EXPR: 
						default:
							// FIXME: is it useful for us to have VAL_IS and VAL_OF?
							break;
					}
				}
			};

			// process the row contents
			for (auto i_int = result.rows.begin(); i_int != result.rows.end(); ++i_int)
			{
				visit_columns(row_column_visitor, i_int->second);
			}
		} // end for each FDE
	};
	
	/* PROBLEM:
	 * In the case of 'strip --only-keep-debug', the .eh_frame remains
	 * in the original binary. So our root_die may be bound to the
	 * debuginfo binary, but we may need to look back at the original
	 * 'base_fd' to get the frame section
	 */
	core::FrameSection fs(root.get_dbg(), /* use_eh */ true);
	cerr << ".eh_frame in DWARF binary has " << fs.fde_element_count << " FDEs and "
		<< fs.cie_element_count << " CIEs" << endl;
	if (fs.fde_element_count > 0)
	{
		process_frame_section(fs);
	}
	else
	{
		if (root.base_elf_if_different)
		{
			/* Try the base ELF instead. */
			root_die base_root(root.base_elf_fd);
			core::FrameSection base_fs(base_root.get_dbg(), /* use_eh */ true);
			cerr << ".eh_frame in base binary has " << base_fs.fde_element_count << " FDEs and "
				<< base_fs.cie_element_count << " CIEs" << endl;
			process_frame_section(base_fs);
		}
		else
		{
			// try the .debug_frame in the original binary
			core::FrameSection frame_fs(root.get_dbg(), /* use_eh */ false);
			cerr << ".debug_frame in DWARF binary has " << frame_fs.fde_element_count << " FDEs and "
				<< frame_fs.cie_element_count << " CIEs" << endl;
			process_frame_section(frame_fs);
		}
	}
}

enum flags_t
{
	ONLY_POINTERS = 1,
	INCLUDE_REGISTERS = 2,
	INCLUDE_CFA = 4,
	INCLUDE_COMPUTED = 8,
	INCLUDE_INCOMPLETE = 16,
	INCLUDE_STATIC = 32
};
int main(int argc, char **argv)
{
	optional<string> input_filename;
	flags_t flags = INCLUDE_REGISTERS | INCLUDE_CFA | INCLUDE_COMPUTED;
	auto usage = [=]() {
		cerr << "Usage: " << argv[0]
		<< "[--[no-]include-registers]" << " "
		<< "[--[no-]only-pointers]" << " "
		<< "[--[no-]include-cfa]" << " "
		<< "[--[no-]include-computed]" << " "
		<< "[--[no-]include-incomplete]" << " "
		<< "[--[no-]include-static]" << " "
		<< " input_file" << endl;
	};
	auto process_opt = [&](const string& s) {
		if (s == "--include-registers")    { flags |= INCLUDE_REGISTERS; return; }
		if (s == "--no-include-registers") { flags &= ~INCLUDE_REGISTERS; return; }
		if (s == "--only-pointers")        { flags |= ONLY_POINTERS; return; }
		if (s == "--no-only-pointers")     { flags &= ~ONLY_POINTERS; return; }
		if (s == "--include-cfa")          { flags |= INCLUDE_CFA; return; }
		if (s == "--no-include-cfa")       { flags &= ~INCLUDE_CFA; return; }
		if (s == "--include-computed")     { flags |= INCLUDE_COMPUTED; return; }
		if (s == "--no-include-computed")  { flags &= ~INCLUDE_COMPUTED; return; }
		if (s == "--include-incomplete")   { flags |= INCLUDE_INCOMPLETE; return; }
		if (s == "--no-include-incomplete"){ flags &= ~INCLUDE_INCOMPLETE; return; }
		if (s == "--include-static")       { flags |= INCLUDE_STATIC; return; }
		if (s == "--no-include-static")    { flags &= ~INCLUDE_STATIC; return; }
		cerr << "Unrecognised option: " << s << endl;
		usage();
		exit(1);
	};
	auto set_input_file = [&input_filename, usage](const string& s) {
		if (input_filename)
		{
			cerr << "Multiple input files not supported: " << s << endl;
			usage();
			exit(1);
		}
		input_filename = optional<string>(s);
	};
	for (unsigned i = 1; i < argc; ++i)
	{
		// '-' is a valid filename, otherwise it's an option
		if (argv[i][0] == '-' && argv[i][1] != '\0') process_opt(argv[i]);
		else set_input_file(argv[i]);
	}
	if (!input_filename) { usage(); exit(1); }
	std::ifstream infstream(*input_filename);
	if (!infstream)
	{
		cerr << "Could not open file " << *input_filename << endl;
		exit(1);
	}
	
	if (getenv("FRAMETYPES_DEBUG"))
	{
		debug_out = atoi(getenv("FRAMETYPES_DEBUG"));
	}
	
	using core::root_die;
	int fd = fileno(infstream);
	shared_ptr<sticky_root_die> p_root = sticky_root_die::create(fd);
	if (!p_root) { std::cerr << "Error reading DWARF for input file" << std::endl; return 1; }
	sticky_root_die& root = *p_root;
	assert(&root.get_frame_section());

	subprogram_vaddr_interval_map_t subprograms_by_vaddr;
	map<subprogram_key, iterator_df<subprogram_die> > subprograms_by_key;
	gather_defined_subprograms(root, subprograms_by_vaddr, subprograms_by_key);

	cerr << "Found " << subprograms_by_key.size() << " subprograms." << endl;
	/* What's our new algorithm?
	 * 1. Collect all intervals across all subprograms.
	 *    We also add 
	 */
	frame_intervals_t all_local_intervals;
	for (auto i_pair = subprograms_by_key.begin();
		i_pair != subprograms_by_key.end(); ++i_pair)
	{
		gather_local_var_locations_by_pc_interval(
			all_local_intervals,
			i_pair->second,
			root
		);
	}
	// also gather the CFA
	if (flags & INCLUDE_CFA) gather_saved_register_locations_by_pc_interval(
		all_local_intervals,
		subprograms_by_vaddr,
		root);
	/* 2. Partition the set elements into interesting and not interesting,
	 *    discarding the not-interesting ones. (To save memory we could
	 *    do the partitioning/discarding as we collect, but for now we don't.)
	 *    The uninteresting cases in the original frametypes were:
	 *     static-masquerading-as-local
	 *     register-located
	 *     no location
	 *     unsupported DWARF
	 *     incomplete type
	 *    ... but now most of these are interesting. I think only no-location
	 *    should be eliminated. For static-masquerading-as-local, we do want to
	 *    record that a stack location holds a transient copy of a static variable,
	 *    if it does.
	 */
	
	// discard reasons:
	// static-masquerading-as-local
	// register-located
	// no location (incl. DW_OP_stack_value)
	// unsupported DWARF
	// incomplete type
	
	/* 3. emit a vector of <name, type> pairs are commoned across the whole DSO.
	 *    How? Just build a map keyed on <name, type>, then walk it to emit.
	 *    The map needs a way to represent complex cases:
	 *        - no type -- OK, just use 
	 *        - incomplete type -- OK, just use the type as-is
	 *        - type of "opaque data" i.e. the saved-register case -- can we represent this
	 *               specially? We already have some precedents like uninterpreted_byte...
	 *               do we need something new here? The problem is that the type of a word
	 *               is context-dependent. Potentially our stackframe query logic, which
	 *               we have to rewrite, should even go up the stack one or more levels to
	 *               answer the query... if, and only if, it is asked about such a save slot.
	 *               Some remarks:
	 *                - it should be possible to query an mcontext, vaguely uniformly
	 *                      with an ordinary stack frame
	 *                      (in a sense, an mcontext consists entirely of saved registers, albeit
	 *                       not of the "caller" per se but of whatever state generated the
	 *                       mcontext)
	 *                - we seem no longer to be computing the "accidental stack maps"
	 *                    that the previous uniqtype construction was producing.
	 *                    That seems like a pity. Oh, but we are -- layout vectors are
	 *                    just that -- just not quite so localised. We probably want at least
	 *                    the comments in our .c file to redundantly elaborate the components
	 *                    that the vector is referencing, so it can easily be read in one place.
	 *     Meta-completeness issue:
	 *         If we do the merging thing, to describe layouts, I'm tempted to encode the
	 *         "run length" in the symbol that marks the start of each run.
	 *         We probably want the run length to be represented elsewhere too,
	 *           i.e. in the per-PC table (but could just use a symidx! not sure).
	 *         But in any case, once ew do merging, we have overlapping allocations,
	 *           and that is a problem for liballocs's meta-model.
	 *         In the long run we may have to support overlapping objects for
	 *           the static allocators, and maybe any other non-mutable allocator?
	 *         Then again, mutable unions are arguably mutable overlapping objects.
	 *           I guess the point with those is that we want to trap writes to them,
	 *           in order to track the "last written", whereas
	 *           there's no need for that in the case of immutable sections.
	 *     Reducing indirection:
	 *          shall we initially just
	 *             for each interval
	 *                 emit the layout vector, as a mergeable pushsection
	 *                    it's a vector of pairs...
	 *                     pair-id, location-descr
	 *                    but we could emit it as a pair of vectors -- TRY BOTH
	 *                     + can we describe the location in one word?
	 *                         simple cases yes: signed 32-bit number, except in the range
	 *                           [INT_MAX - NREGS - 1, INT_MAX - 1] where it's a reg num
	 *                           and [INT_MAX] means "too complex, use a side table"? yes + omit side table for now
	 *                    or we could do bit-fields within a 64-bit number:
	 *                    { pair-id:24;                 // max 16M pairs across a DSO
	 *                      stack_offset:24;            // max +/- 8MB stack offset
	 *                      regn:6;                     // max 64 regs (DWARF has 32 plus escape hatch)
	 *                      piece_sz_if_not_whole:5;    // max 32-byte pieces
	 *                      piece_byte_offs:5
	 *                    }
	 *                 emit the PC table entry, pointing back to the vector.
	 *    How have we saved memory relative to emitting uniqtypes?
	 *        merging of vectors, if we have it to any appreciable degree
	 *        commoning of name-type pairs
	 *        reduced width -- name-type pair idxs are narrower than a uniqtype 'related' entry
	 *        NOT reduced width -- a vector entry pointer is te same width as a uniqtype ptr
	 *    TO COMPARE against the old way, we really want a way to set
	 *        the same discard criteria
	 *        and to turn off the frame info...
	 *        command-line options? interval-gathering is library code, so
	 *         at laast API-level options....
	 */
	map< pair<string, /*iterator_df<type_die>*/ codeful_name >, vector< frame_interval_map_set_value > >
	by_name_and_type;
	unsigned anonctr = 0; // for generating names for anonymous things
	for (auto i_int = all_local_intervals.begin(); i_int != all_local_intervals.end();
		++i_int)
	{
		auto& die_or_reg_pairs = i_int->second;
		for (auto i_el = die_or_reg_pairs.begin(); i_el != die_or_reg_pairs.end(); ++i_el)
		{
			auto maybe_local = i_el->get_die();
			if (maybe_local)
			{
				auto maybe_name = maybe_local->find_name();
				string name;
				if (!maybe_name)
				{
					ostringstream fake_name;
					//fake_name << "__anon" << anonctr++;
					fake_name << "__anon" << std::hex << maybe_local.offset_here();
					cerr << "Strange: " << maybe_local
						<< ". Calling it " << fake_name.str()
						<< "." << endl;
					name = fake_name.str();
				} else name = *maybe_name;
				auto t = maybe_local->find_type();
				assert(t);
				codeful_name tn = codeful_name(t);
				by_name_and_type[make_pair(name, tn)].push_back(*i_el);
			}
			else
			{
				opt<Dwarf_Unsigned> caller_regnum = i_el->get_caller_regnum();
				assert(caller_regnum);
				opt<loc_expr> save_location = i_el->get_save_location();
				assert(save_location);
				// we make up a name
				ostringstream name;
				name << "__saved_caller_reg" << *caller_regnum;
				// NOTE: __saved_caller_reg_1436 is the CFA column.
				// It should never be stored anywhere, so when we filter out those
				// intervals that don't have a stored location, it should disappear.
				// But that tells us that we should filter out from our name--type pairs
				// anything that is not stored. Except stuff that is computed might also
				// be valuable? as the program itself might compute it? Hmm. And the CFA
				// is computed. What is the right logic for this?
				codeful_name tn = make_pair("", "__opaque_word");
				by_name_and_type[make_pair(name.str(), tn)].push_back(*i_el);
			}
		}
	}
	cout << "name\ttype";
	for (auto i_pair = by_name_and_type.begin(); i_pair != by_name_and_type.end(); ++i_pair)
	{
		cout << i_pair->first.first << "\t";
		cout << mangle_typename(i_pair->first.second) << "\t";
		for (auto i_el = i_pair->second.begin(); i_el != i_pair->second.end(); ++i_el)
		{
			// hmm, what to print?
		}
		cout << "\t(" << i_pair->second.size() << " intervals)";
		cout << endl;
	}

#if 0
	/* 4. emit a vector of var locators, i.e. of < pair-id, location >
	 *    also commoned across the whole DSO.
	 *    How? Build a map
	 *    pbuild a vector  the with_dynamic_location_dies into a set...
	 *    or rather the pairs, i.e. a saved-register slot is represented differently.
	 *
	 * 5. emit a vector of vaddr range records... as we do this,
	 *      lazily emit a layout vector, i.e. a location-sorted vector of
	 *      var locators active for that PC range. The same layout vector
	 *      will recur multiple times but should only be emitted once.
	 *    We could possibly use section merging on these vectors.
	 *    String merging is not the right thing because .
	 *    But section merging might work?
	 *
	 * To location-sort register locations, use a negative offset for registers?
	 * To deal with pieces, each type can optionally have a "piece size, piece offset" pair
	 * To deal with "saved caller registers", that do not have a with_dynamic_location_die,
	 * 

	 * Each interval is a <pc-range, var, location> triple.
	 * A location is a location expression.
	 * A var is either a with_dynamic_location_die (variable or formal parameter)
	 * or something denoting a 
	 * 
	 * 
	 */

	map< iterator_df<subprogram_die>, frame_intervals_t > frame_intervals_by_subprogram;
	/* The frame offset is the most negative stack frame offset for any member
	 * of any frame belonging to the subprogram. We record this for every
	 * subprogram and add it to the stack frame base before interpreting the 
	 * frame as a uniqtype COMPOSITE (struct) object. Field offsets in the uniqtype
	 * are all calculated from this "virtual frame base" position, which is the
	 * numerically lowest used location on the stack ("used" by locals placed
	 * relative to the frame base... alloca() is another matter).
	 * NOTE: I think we don't need this any more, as we don't have a frame uniqtype
	 * any more. We will need some way to capture overlaps though. */
	map< iterator_df<subprogram_die>, unsigned > frame_offsets_by_subprogram;

	using dwarf::core::with_static_location_die;
	cout << "#include \"allocmeta-defs.h\"\n";
	cout << "#include \"uniqtype-defs.h\"\n\n";
	set<string> names_emitted;
	
				/* Check we are not getting unreasonably big. */
			static const unsigned MAX_INTERVALS = 10000;
			if (out.size() > MAX_INTERVALS)
			{
#if 0
				cerr << "Warning: abandoning gathering frame intervals for " << i_subp->summary() 
						<< " in compilation unit " << i_subp.enclosing_cu().summary()
						<< " after reaching " << MAX_INTERVALS << std::endl;
				subp_frame_intervals.clear();
				break;
#endif
			}

	// for all subprograms...
	for (auto i_i_subp = subprograms_list.begin(); i_i_subp != subprograms_list.end(); ++i_i_subp)
	{
		auto i_subp = i_i_subp->second;

		/* Now we write a *series* of object layouts for this subprogram, 
		 * discriminated by a set of (disjoint) vaddr ranges. */
		
		/* Our naive earlier algorithm had the problem that, once register-based 
		 * locals are discarded, the frame layout is often unchanged from one vaddr range
		 * to the next. But we were outputting a new uniqtype anyway, creating 
		 * huge unnecessary bloat. So instead, we do a pre-pass where we remember
		 * only the stack-located elements, and store them in a new interval map, 
		 * by offset from frame base. 
		 *
		 * Also, we want to report discarded fps/locals once per subprogram, as 
		 * completely discarded or partially discarded. How to do this? 
		 * Keep an interval map of discarded items.
		 * When finished, walk it and build another map keyed by 
		  */
		frame_intervals_t subp_frame_intervals;
#ifdef DEBUG
		discarded_intervals_t subp_discarded_intervals;
#endif
		 
		for (auto i_int = subp_frame_intervals.begin(); 
			i_int != subp_frame_intervals.end(); ++i_int)
		{
			/* Get the set of <p_dyn, locexpr>s for this vaddr range. */
			auto& frame_elements = i_int->second;
			
			/* Calculate their offset from the frame base, and sort. */
			//std::map<Dwarf_Signed, shared_ptr<with_dynamic_location_die > > by_frame_off;
			//std::vector<pair<shared_ptr<with_dynamic_location_die >, string> > discarded;

			/* We used to check that we don't see the same DIE twice within the same interval.
			 * But WHY? We could have two pairs in frame_elements, with different loc_exprs.
			 * In fact this does happen. So I've deleted the check. */
			for (auto i_el_pair = frame_elements.begin(); i_el_pair != frame_elements.end(); ++i_el_pair)
			{
				/* Note that thanks to the aggregation semantics of subp_frame_intervals, 
				 * i_int is already the intersection of the loc_expr interval *and* all
				 * other loc_expr intervals in use within this subprogram. W*/

				/* NOTE: our offset can easily be negative! For parameters, it 
				 * usually is. So we calculate the offset from the middle of the 
				 * (imaginary) address space, a.k.a. 1U<<((sizeof(Dwarf_Addr)*8)-1). 
				 * In a signed two's complement representation, 
				 * this number is -MAX. 
				 * NO -- just reinterpret_cast to a signed? */
				
				auto i_el = &i_el_pair->first;
				
				Dwarf_Addr addr_from_zero;
				/* Check for vars that are part static, part on-stack. 
				 * How does this happen? One example is 
				 * the 'git_packed' that is local within rearrange_packed_git
				 * which gets inlined into prepare_packed_git in sha1_file.c.
				 * 
				 * The answer is: they're static vars that are being manipulated
				 * locally within the function. Because they're "variables" that are
				 * "in scope" (I think this is an interaction with inlining), 
				 * they get their own DW_TAG_variable DIEs within the inlined 
				 * instance's DWARF. While they're being manipulated, these have 
				 * register locations. It would be pointless to spill them to the 
				 * stack, however, so I don't think we need to worry about them. */
				if (i_el_pair->second.size() > 0 && i_el_pair->second.at(0).lr_atom == DW_OP_addr
				 && i_el_pair->second.at(i_el_pair->second.size() - 1).lr_atom != DW_OP_stack_value)
				{
					cerr << "Skipping static var masquerading as local: "
						<< *i_el 
						<< "in the vaddr range " 
						<< std::hex << i_int->first << std::dec << std::endl;
					iterfirst_pair_hash< with_dynamic_location_die, string>::set /*,
						compare_first_iter_offset<string>*/ just_this_variable_discard_reason_pair;
					just_this_variable_discard_reason_pair.insert(make_pair(*i_el, string("static-masquerading-as-local")));
#ifdef DEBUG
					discarded_intervals += make_pair(i_int->first, just_this_variable_discard_reason_pair);
#endif
					continue;
				}
				
				bool saw_register = false;
				auto& spec = i_el_pair->first.spec_here();
				for (auto i_instr = i_el_pair->second.begin(); i_instr != i_el_pair->second.end();
					++i_instr)
				{
					if (spec.op_reads_register(i_instr->lr_atom))
					{ saw_register = true; break; }
				}
				
				/* FIXME: DW_OP_piece complicates this. If we have part in a register, 
				 * part on the stack, we'd like to record this somehow. Perhaps supply
				 * a getter and setter in the make_precise()-generated uniqtype? */
				
				if (saw_register)
				{
					/* This means our variable/fp is in a register and not 
					 * in a stack location. That's fine. Warn and continue. */
					if (debug_out > 1)
					{
						cerr << "Warning: we think this is a register-located local/fp or pass-by-reference fp "
							<< "in the vaddr range " 
							<< std::hex << i_int->first << std::dec
							<< ": "
					 		<< *i_el;
					}
					//discarded.push_back(make_pair(*i_el, "register-located"));
					iterfirst_pair_hash< with_dynamic_location_die, string>::set/*,
						compare_first_iter_offset<string> */ just_this_variable_discard_reason_pair;
					just_this_variable_discard_reason_pair.insert(make_pair(*i_el, string("register-located")));
#ifdef DEBUG
					discarded_intervals += make_pair(i_int->first, just_this_variable_discard_reason_pair);
#endif
					continue;
				}
				else try
				{
					std::stack<Dwarf_Unsigned> initial_stack; 
					// call the evaluator directly
					// -- push zero (a.k.a. the frame base) onto the initial stack
					initial_stack.push(0); 
					// FIXME: really want to push the offset of the stack pointer from the frame base
					dwarf::expr::evaluator e(i_el_pair->second,
						i_el_pair->first.spec_here(),
						/* fb */ 0, 
						initial_stack);
					switch (e.tos_state())
					{
						case dwarf::expr::evaluator::ADDRESS: // the good one
							break;
						default:
							if (debug_out > 1)
							{
								cerr << "Top-of-stack indicates non-address result" << std::endl;
							}
					}
					addr_from_zero = e.tos(dwarf::expr::evaluator::ADDRESS); // may *not* be value; must be loc
				}
				catch (dwarf::lib::No_entry)
				{
					/* Not much can cause this, since we scanned for registers.
					 * One thing would be a local whose location gives DW_OP_stack_value,
					 * i.e. it has only a debug-time-computable value but no location in memory,
					 * or DW_OP_implicit_pointer, i.e. it points within some such value. */
					if (debug_out > 1)
					{
						cerr << "Warning: failed to locate non-register-located local/fp "
							<< "in the vaddr range " 
							<< std::hex << i_int->first << std::dec
							<< ": "
					 		<< *i_el;
					}
					//discarded.push_back(make_pair(*i_el, "register-located"));
					iterfirst_pair_hash< with_dynamic_location_die, string>::set/*,
						compare_first_iter_offset<string> */ just_this_variable_discard_reason_pair;
					just_this_variable_discard_reason_pair.insert(make_pair(*i_el, string("no location")));
#ifdef DEBUG
					discarded_intervals += make_pair(i_int->first, just_this_variable_discard_reason_pair);
#endif
					continue;
				}
				catch (dwarf::expr::Not_supported)
				{
					cerr << "Warning: unsupported DWARF opcode when computing location for fp: "
						<< *i_el;
					//discarded.push_back(make_pair(*i_el, "register-located"));
					iterfirst_pair_hash< with_dynamic_location_die, string>::set /*,
						compare_first_iter_offset<string> */ just_this_variable_discard_reason_pair;
					just_this_variable_discard_reason_pair.insert(make_pair(*i_el, string("unsupported-DWARF")));
#ifdef DEBUG
					discarded_intervals += make_pair(i_int->first, just_this_variable_discard_reason_pair);
#endif
					continue;
				}
				catch (...)
				{
					cerr << "Warning: something strange happened when computing location for fp: " 
					 	<< *i_el;
					//discarded.push_back(make_pair(*i_el, "register-located"));
					iterfirst_pair_hash< with_dynamic_location_die, string>::set /*,
						compare_first_iter_offset<string> */ just_this_variable_discard_reason_pair;
					just_this_variable_discard_reason_pair.insert(make_pair(*i_el, string("something-strange")));
#ifdef DEBUG
					discarded_intervals += make_pair(i_int->first, just_this_variable_discard_reason_pair);
#endif
					continue;
				}
				Dwarf_Signed frame_offset = static_cast<Dwarf_Signed>(addr_from_zero);
				// cerr << "Found on-stack location (fb + " << frame_offset << ") for fp/var " << *i_el 
				// 		<< "in the vaddr range " 
				// 		<< std::hex << i_int->first << std::dec << endl;

				/* We only add to by_frame_off if we have complete type => nonzero length. */
				if ((*i_el)->find_type() && (*i_el)->find_type()->get_concrete_type())
				{
					//by_frame_off[frame_offset] = *i_el;
					frame_interval_map_set_t just_this_offset_variable_pair;
					just_this_offset_variable_pair.insert(make_pair(frame_offset, *i_el));
					frame_intervals += make_pair(i_int->first, just_this_offset_variable_pair);
				}
				else
				{
					iterfirst_pair_hash< with_dynamic_location_die, string>::set/*,
						compare_first_iter_offset<string> */ just_this_variable_discard_reason_pair;
					just_this_variable_discard_reason_pair.insert(make_pair(*i_el, string("no_concrete_type")));
#ifdef DEBUG
					discarded_intervals += make_pair(i_int->first, just_this_variable_discard_reason_pair);
#endif
				}
			}
		} /* end for i_int */
		

		
		/* Now figure out the positive and negative extents of the frame. */
		typedef decltype(frame_intervals) is_t;
		std::map< is_t::key_type, unsigned> interval_maxoffs;
		std::map< is_t::key_type, signed>   interval_minoffs;
		signed overall_frame_minoff = 0;
		for (auto i_frame_int = frame_intervals.begin(); i_frame_int != frame_intervals.end();
			++i_frame_int)
		{
			unsigned interval_maxoff;
			signed interval_minoff;
			//if (by_frame_off.begin() == by_frame_off.end()) frame_size = 0;
			if (i_frame_int->second.size() == 0) { interval_maxoff = 0; interval_minoff = 0; }
			else
			{
				{
					frame_intervals_t::codomain_type::iterator i_maxoff_el = i_frame_int->second.end(); --i_maxoff_el;
// 					Dwarf_Signed seen_maxoff = std::numeric_limits<Dwarf_Signed>::min();
// 					for (auto i_el = i_frame_int->second.begin(); i_el != i_frame_int->second.end(); ++i_el)
// 					{
// 						if (i_el->first > seen_maxoff)
// 						{
// 							seen_maxoff = i_el->first;
// 							i_maxoff_el = i_el;
// 						}
// 					}
					auto p_maxoff_type = i_maxoff_el->second->find_type();
					unsigned calculated_maxel_size;
					if (!p_maxoff_type || !p_maxoff_type->get_concrete_type()) 
					{
						cerr << "Warning: found local/fp with no type  (assuming zero length): " 
							<< *i_maxoff_el->second;
						calculated_maxel_size = 0;
					}
					else 
					{
						opt<Dwarf_Unsigned> opt_size = p_maxoff_type->calculate_byte_size();
						if (!opt_size)
						{
							cerr << "Warning: found local/fp with no size (assuming zero length): " 
								<< *i_maxoff_el->second;
							calculated_maxel_size = 0;						
						} else calculated_maxel_size = *opt_size;
					}
					signed interval_max_offset = i_maxoff_el->first + calculated_maxel_size;
					interval_maxoff = (interval_max_offset < 0) ? 0 : interval_max_offset;
				}
				{
					auto i_minoff_el = i_frame_int->second.begin();
					signed interval_min_offset = i_minoff_el->first;
					interval_minoff = (interval_min_offset > 0) ? 0 : interval_min_offset;
				}
			}
			
			interval_maxoffs.insert(make_pair(i_frame_int->first, interval_maxoff));
			interval_minoffs.insert(make_pair(i_frame_int->first, interval_minoff));
			if (interval_minoff < overall_frame_minoff) overall_frame_minoff = interval_minoff;
		}
		unsigned offset_to_all = 0;
		if (overall_frame_minoff < 0)
		{
			/* The offset we want to apply to everything is the negation of 
			 * overall_frame_minoff, rounded *up* to a word. */
			// FIXME: don't assume host word size
			unsigned remainder = (-overall_frame_minoff) % (sizeof (void*));
			unsigned quotient  = (-overall_frame_minoff) / (sizeof (void*));
			offset_to_all =
				remainder == 0 ? quotient * (sizeof (void*))
					: (quotient + 1) * (sizeof (void*));
		}
		frame_offsets_by_subprogram[i_subp] = offset_to_all;
		
		/* Now for each distinct interval in the frame_intervals map... */
		for (auto i_frame_int = frame_intervals.begin(); i_frame_int != frame_intervals.end();
			++i_frame_int)
		{
			auto found_maxoff = interval_maxoffs.find(i_frame_int->first);
			assert(found_maxoff != interval_maxoffs.end());
			unsigned interval_maxoff = found_maxoff->second;
			auto found_minoff = interval_minoffs.find(i_frame_int->first);
			assert(found_minoff != interval_minoffs.end());
			signed interval_minoff = found_minoff->second;
			auto& by_off = i_frame_int->second;
			
			/* Before we output anything, extern-declare any that we need and haven't
			 * declared yet. */
			for (auto i_by_off = by_off.begin(); i_by_off != by_off.end(); ++i_by_off)
			{
				auto el_type = i_by_off->second->find_type();
				auto name_pair = codeful_name(el_type);
				string mangled_name = mangle_typename(name_pair);
				if (names_emitted.find(mangled_name) == names_emitted.end())
				{
					emit_extern_declaration(std::cout, name_pair, /* force_weak */ false);
					names_emitted.insert(mangled_name);
				}
			}

			/* Output in offset order, CHECKing that there is no overlap (sanity). */
			cout << "\n/* uniqtype for stack frame ";
			string unmangled_typename = typename_for_vaddr_interval(i_subp, i_frame_int->first);
			
			string cu_name = *i_subp.enclosing_cu().name_here();
			
			cout << unmangled_typename
				 << " defined in " << cu_name << ", "
				 << "vaddr range " << std::hex << i_frame_int->first << std::dec << " */\n";
			ostringstream min_s; min_s << "actual min is " << interval_minoff + offset_to_all;
			string mangled_name = mangle_typename(make_pair(string(""), cu_name + unmangled_typename));

			/* Is this the same as a layout we've seen earlier for the same frame? */
			bool emitted_as_alias = false;
			for (auto i_earlier_frame_int = frame_intervals.begin();
				i_earlier_frame_int != i_frame_int;
				++i_earlier_frame_int)
			{
				if (by_off == i_earlier_frame_int->second)
				{
					// just output as an alias
					string unmangled_earlier_typename
					 = typename_for_vaddr_interval(i_subp, i_earlier_frame_int->first);
					string mangled_earlier_name = mangle_typename(
						make_pair("", cu_name + unmangled_earlier_typename));
					cout << "\n/* an alias will do */\n";
					emit_weak_alias_idem(cout, mangled_name, mangled_earlier_name); // FIXME: not weak
					emitted_as_alias = true;
				}
			}
			if (emitted_as_alias) continue;

			write_uniqtype_section_decl(cout, mangled_name);
			write_uniqtype_open_composite(cout,
				mangled_name,
				unmangled_typename,
				interval_maxoff + offset_to_all,
				i_frame_int->second.size(),
				false,
				min_s.str()
			);
			opt<unsigned> prev_offset_plus_size;
			opt<unsigned> highest_unused_offset = opt<unsigned>(0u);
			// FIXME: prev_offset_plus_size needn't be the right thing.
			// We want the highest offset yet seen.
			for (auto i_by_off = by_off.begin(); i_by_off != by_off.end(); ++i_by_off)
			{
				ostringstream comment_s;
				auto el_type = i_by_off->second->find_type();
				unsigned offset_after_fixup = i_by_off->first + offset_to_all;
				opt<Dwarf_Unsigned> el_type_size = el_type ? el_type->calculate_byte_size() :
					opt<Dwarf_Unsigned>();
				if (i_by_off->second.name_here())
				{
					comment_s << *i_by_off->second.name_here();
				}
				else comment_s << "(anonymous)"; 
				comment_s << " -- " << i_by_off->second.spec_here().tag_lookup(
						i_by_off->second.tag_here())
					<< " @" << std::hex << i_by_off->second.offset_here() << std::dec
					<< "(size ";
				if (el_type_size) comment_s << *el_type_size;
				else comment_s << "(no size)";
				comment_s << ")";
				if (highest_unused_offset)
				{
					if (offset_after_fixup > *highest_unused_offset)
					{
						unsigned hole_size = offset_after_fixup - *highest_unused_offset;
						unsigned align = el_type.enclosing_cu()->alignment_of_type(el_type);
						unsigned highest_unused_offset_rounded_to_align
						 = ROUND_UP(highest_unused_offset, align);
						comment_s << " (preceded by ";
						if (hole_size ==
							highest_unused_offset_rounded_to_align - highest_unused_offset)
						{
							comment_s << "an alignment-consistent hole";
						}
						else
						{
							comment_s << " (preceded by an alignment-unexpected HOLE";
						}
						comment_s << " of " << hole_size << " bytes)";
					}
					else if (offset_after_fixup < *highest_unused_offset)
					{
						comment_s << " (constituting an OVERLAP in the first " << (*highest_unused_offset - offset_after_fixup)
							<< " bytes)";
					}
				}
				// FIXME: also want to report holes at the start or end of the frame

				string mangled_name = mangle_typename(codeful_name(el_type));
				write_uniqtype_related_contained_member_type(cout,
					/* is_first */ i_by_off == i_frame_int->second.begin(),
					offset_after_fixup,
					mangled_name,
					comment_s.str()
				);
				if (el_type_size)
				{
					prev_offset_plus_size = offset_after_fixup + *el_type_size;
					highest_unused_offset = std::max<unsigned>(
						offset_after_fixup + *el_type_size, highest_unused_offset);
				}
				else
				{
					prev_offset_plus_size = opt<unsigned>();
					highest_unused_offset = opt<unsigned>();
				}
			}
			write_uniqtype_close(cout, mangled_name);
		}
		/* Now print a summary of what was discarded. */
// 		for (auto i_discarded = discarded.begin(); i_discarded != discarded.end(); 
// 			++i_discarded)
// 		{
// 			cout << "\n\t/* discarded: ";
// 			if (i_discarded->first.name_here())
// 			{
// 				cout << *i_discarded->first.name_here();
// 			}
// 			else cout << "(anonymous)"; 
// 			cout << " -- " << i_discarded->first->get_spec().tag_lookup(
// 					i_discarded->first->get_tag())
// 				<< " @" << std::hex << i_discarded->first->get_offset() << std::dec;
// 			cout << "; reason: " << i_discarded->second;
// 			cout << " */ ";
// 		}
	} // end for subprogram
	
	unsigned total_emitted = 0;
	
	/* NOTE: our allocsite chaining trick in liballocs requires/d that our allocsites 
	 * are sorted in vaddr order, so that adjacent allocsites in the memtable buckets
	 * are adjacent in the table. So we sort them here. */
	set< pair< boost::icl::discrete_interval<Dwarf_Addr>, iterator_df<subprogram_die> > > sorted_intervals;
	for (map< iterator_df<subprogram_die>, frame_intervals_t >::iterator i_subp_intervals 
	  = frame_intervals_by_subprogram.begin(); i_subp_intervals != frame_intervals_by_subprogram.end();
	  ++ i_subp_intervals)
	{
		// now output an allocsites-style table for these 
		for (auto i_int = i_subp_intervals->second.begin(); i_int != i_subp_intervals->second.end(); 
			++i_int)
		{
			sorted_intervals.insert(make_pair(i_int->first, i_subp_intervals->first));
		}
	}
	cout << "struct frame_allocsite_entry frame_vaddrs[] = {" << endl;
	for (auto i_pair = sorted_intervals.begin(); i_pair != sorted_intervals.end(); ++i_pair)
	{
		unsigned offset_from_frame_base = frame_offsets_by_subprogram[i_pair->second];
	
		if (i_pair != sorted_intervals.begin()) cout << ",";
		cout << "\n\t/* frame alloc record for vaddr 0x" << std::hex << i_pair->first.lower() 
			<< "+" << i_pair->first.upper() << std::dec << " */";
		cout << "\n\t{\t" << offset_from_frame_base << ","
			<< "\n\t\t{ 0x" << std::hex << i_pair->first.lower() << "UL, " << std::dec
			<< "&" << mangle_typename(make_pair("", *i_pair->second.enclosing_cu().name_here() +
				typename_for_vaddr_interval(i_pair->second, i_pair->first)))
			<< " }"
			<< "\n\t}";
		++total_emitted;
	}
	// close the list
	cout << "\n};\n";
#endif
	// success! 
	return 0;
}
