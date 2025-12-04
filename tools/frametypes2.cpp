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
#include "frame-element.hpp"
#include "uniqtypes.hpp"
#include "relf.h"

using std::cin;
using std::cout;
using std::cerr;
using std::map;
using std::make_shared;
using std::ios;
using std::ifstream;
using std::ostream;
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

/* FIXME: put these elsewhere */
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

// FIXME: unused? where did frametypes use this?
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

void
gather_defined_subprograms(sticky_root_die& root,
	subprogram_vaddr_interval_map_t& out_by_vaddr,
	map<subprogram_key, iterator_df<subprogram_die> >& out_by_key
	)
{
	/* FIXME: could speed this up by cutting off the search underneath
	 * certain tags. But which? Subprograms need not be grandchildren of the root,
	 * if we have namespaces or the like. */
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

unsigned get_frame_offset(frame_intervals_t const& subp_frame_intervals)
{
	// In the original code, frame_intervals_t is a map <K, V> where V is
	// pair<Dwarf_Signed /* frame offset */, iterator_df<with_dynamic_location_die> >
	// so they are naturally sorted by offset. So, retrieving the maximum and minimum
	// for each interval is trivial, and then we have simply to compute the overall
	// maximum and minimum.
	/* In our case, by contrast, not all frame elements have an offset. So we are
	 * better off walking *all* elements and simply computing the maximum and minimum
	 * as we go. In fact we don't need the maximum (which was used only for the overall
	 * frame size, which we don't even define any more), just the minimum.
	 * But since we want to generate traditional output, we do need to keep
	 * this around. */
	Dwarf_Signed least_offset_seen = std::numeric_limits<Dwarf_Signed>::max();
	for (auto i_frame_int = subp_frame_intervals.begin();
		i_frame_int != subp_frame_intervals.end();
		++i_frame_int)
	{
		for (auto i_el = i_frame_int->second.begin(); i_el != i_frame_int->second.end();
			++i_el)
		{
			optional<Dwarf_Signed> maybe_offs = i_el->has_fixed_offset_from_frame_base();
			if (maybe_offs && *maybe_offs < least_offset_seen) least_offset_seen = *maybe_offs;
		}
	}
	Dwarf_Signed overall_frame_minoff = least_offset_seen;
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
	return offset_to_all;
}

unsigned frame_max_extent(frame_intervals_t const& subp_frame_intervals)
{
	// In the original code, frame_intervals_t is a map <K, V> where V is
	// pair<Dwarf_Signed /* frame offset */, iterator_df<with_dynamic_location_die> >
	// so they are naturally sorted by offset. So, retrieving the maximum and minimum
	// for each interval is trivial, and then we have simply to compute the overall
	// maximum and minimum.
	/* In our case, by contrast, not all frame elements have an offset. So we are
	 * better off walking *all* elements and simply computing the maximum and minimum
	 * as we go. In fact we don't need the maximum (which was used only for the overall
	 * frame size, which we don't even define any more), just the minimum.
	 * But since we want to generate traditional output, we do need to keep
	 * this around. */
	Dwarf_Signed greatest_offset_seen = std::numeric_limits<Dwarf_Signed>::min();
	frame_element *greatest_offset_element = nullptr;
	for (auto i_frame_int = subp_frame_intervals.begin();
		i_frame_int != subp_frame_intervals.end();
		++i_frame_int)
	{
		for (auto i_el = i_frame_int->second.begin(); i_el != i_frame_int->second.end();
			++i_el)
		{
			optional<Dwarf_Signed> maybe_offs = i_el->has_fixed_offset_from_frame_base();
			if (maybe_offs && *maybe_offs > greatest_offset_seen)
			{
				greatest_offset_seen = *maybe_offs;
				greatest_offset_element = &*i_el;
			}
		}
	}

	if (greatest_offset_seen == std::numeric_limits<Dwarf_Signed>::min())
	{
		// nothing here, so max extent 0
		return 0;
	}
	assert(greatest_offset_element);
	optional<Dwarf_Unsigned> maybe_sz = greatest_offset_element->piece_size_in_bytes();
	if (!maybe_sz)
	{
		cerr << "Warning: highest-offset frame element has no size (assuming zero length)"
			<< endl;
		return greatest_offset_seen;
	}
	return greatest_offset_seen + *maybe_sz;
}

static string typename_for_vaddr_interval(iterator_df<subprogram_die> i_subp, 
	const boost::icl::discrete_interval<Dwarf_Off> interval)
{
	std::ostringstream s_typename;
	if (i_subp.name_here()) s_typename << *i_subp.name_here();
	else s_typename << "0x" << std::hex << i_subp.offset_here() << std::dec;
	s_typename << "_vaddrs_0x" << std::hex << interval.lower() << "_0x" 
		<< interval.upper() << std::dec;

	return s_typename.str();
}

multimap<Dwarf_Signed, frame_element>
local_elements_by_stack_offset(set<frame_element> const& elts)
{
	multimap<Dwarf_Signed, frame_element> out;
	for (auto i_el = elts.begin();
		i_el != elts.end(); ++i_el)
	{
		auto maybe_offs = i_el->has_fixed_offset_from_frame_base();
		if (maybe_offs && i_el->m_local)
		{
			out.insert(make_pair(*maybe_offs, *i_el));
		}
		else if (i_el->m_local) cerr << "local but not fixed-stack-offset: " << i_el->m_local.summary()
			<< " (expr: " << i_el->effective_expr_piece.copy_as_if_whole() << ")" << endl;
	} /* end for i_el_pair */
	return out;
}

void write_traditional_output(
	subprogram_vaddr_interval_map_t const& subprograms_by_vaddr,
	map<subprogram_key, iterator_df<subprogram_die> > const& subprograms_by_key,
	frame_intervals_t const& all_intervals)
{
	map< iterator_df<subprogram_die>, frame_intervals_t > frame_intervals_by_subprogram;
	//set< iterator_df<subprogram_die> > all_subprograms;
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

	// we need to build frame_intervals_by_subprogram
	for (auto i_int = all_intervals.begin(); i_int != all_intervals.end(); ++i_int)
	{
		Dwarf_Addr addr = i_int->first.lower();
		auto found_subprograms = subprograms_by_vaddr.find(addr);
		if (found_subprograms == subprograms_by_vaddr.end())
		{
			/* This can happen for FDEs covering startup files, say... there's no
			 * DW_TAG_subprogram for these. We can safely skip such intervals
			 * for traditional output. */
			cerr << "WARNING: pc 0x" << std::hex << addr << std::dec
				<< " belongs to no DWARF-info'd subprogram, so ignoring" << endl;
			continue;
		}
		assert(found_subprograms->second.size() > 0);
		/* The value type of subprogram_vaddr_map is a set only so that we can detect
		 * and warn about overlaps... */
		if (found_subprograms->second.size() != 1)
		{
			cerr << "WARNING: pc 0x" << std::hex << addr << std::dec
				<< " belongs to more than one subprogram, so ignoring" << endl;
			continue;
		}
		iterator_df<subprogram_die> i_subp = found_subprograms->second.begin()->second;
		frame_intervals_by_subprogram[i_subp].insert(*i_int);
		//all_subprograms.insert(i_subp);
	}

	using dwarf::core::with_static_location_die;
	cout << "#include \"allocmeta-defs.h\"\n";
	cout << "#include \"uniqtype-defs.h\"\n\n";
	set<string> names_emitted;

#if 0 // this will need porting if we want to use it again...
	/* Check we are not getting unreasonably big. */
	static const unsigned MAX_INTERVALS = 10000;
	if (out.size() > MAX_INTERVALS)
	{
		cerr << "Warning: abandoning gathering frame intervals for " << i_subp->summary() 
				<< " in compilation unit " << i_subp.enclosing_cu().summary()
				<< " after reaching " << MAX_INTERVALS << std::endl;
		subp_frame_intervals.clear();
		break;
	}
#endif

	boost::icl::interval_map<Dwarf_Addr, multimap<Dwarf_Signed, frame_element> >
		by_off_by_interval;
	// for all subprograms...
	for (auto i_i_subp = subprograms_by_key.begin(); i_i_subp != subprograms_by_key.end(); ++i_i_subp)
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
		frame_intervals_t& subp_frame_intervals = frame_intervals_by_subprogram[i_subp];

		/* Now figure out the positive and negative extents of the frame. */
		Dwarf_Signed frame_offset = get_frame_offset(subp_frame_intervals);
		frame_offsets_by_subprogram[i_subp] = frame_offset;

		/* Dump a map of the subprogram */
		//if (debug_out > 1) 	for (auto i_frame_int = subp_frame_intervals.begin();
		//	i_frame_int != subp_frame_intervals.end(); ++i_frame_int)
		//{
			

		/* Now for each distinct interval in the frame_intervals map... */
		unsigned by_off_by_interval_nentries = by_off_by_interval.iterative_size();
		unsigned n_real_intervals = 0;
		for (auto i_frame_int = subp_frame_intervals.begin(); i_frame_int != subp_frame_intervals.end();
			++i_frame_int, ++n_real_intervals)
		{
			/* Our hack for consolidation/coalescing of equal intervals.... */
			auto i_last_equal = find_equal_range_last<set<frame_element> >(
				i_frame_int, subp_frame_intervals.end());
			if (i_last_equal != i_frame_int)
			{
				if (debug_out > 1) cerr << "Coalescing from up to "
					<< std::hex << i_last_equal->first.upper()
					<< " from " << i_frame_int->first.lower() << std::dec << std::endl;
			} else if (debug_out > 1) cerr << "Not coalescing at " << std::hex
				<< i_frame_int->first << std::dec << endl;
			auto& frame_elements = i_frame_int->second;
			auto interval = boost::icl::discrete_interval<Dwarf_Addr>::right_open(
				i_frame_int->first.lower(), i_last_equal->first.upper());

			multimap<Dwarf_Signed, frame_element> by_off
			 = local_elements_by_stack_offset(frame_elements);
			by_off_by_interval.insert(make_pair(
				i_frame_int->first,
				by_off));
			if (debug_out > 1)
			{
				cerr << "Computed a frame layout over " << std::hex
					<< i_frame_int->first << std::dec << " with " << by_off.size() << " on-stack elements "
					<< "of " << i_frame_int->second.size() << " total: ";
				//for (auto i_el = by_off.begin(); i_el != by_off.end(); ++i_el)
				for (auto i_el = i_frame_int->second.begin();
					i_el != i_frame_int->second.end(); ++i_el)
				{
					//if (i_el != by_off.begin()) cerr << ", ";
					if (i_el != i_frame_int->second.begin()) cerr << ", ";
					if (i_el->m_local) cerr << std::hex << i_el->m_local.offset_here()
						<< std::dec;
					else cerr << "caller_reg" << *i_el->m_caller_regnum;
					cerr << " @(" << std::hex << i_el->effective_expr_piece.copy() << std::dec << ")";
				}
				cerr << endl;
				/* We should have weeded out everything that is not an on-stack
				 * slot earlier, otherwise we will not replicate frametypes.*/
				assert(i_frame_int->second.size() == by_off.size());
			}
			if (by_off.size() == 0)
			{
				cerr << "Warning: no stack-offset frame element intervals for subprogram " << i_subp
					<< " in range " << std::hex << interval << std::dec << endl;
				goto continue_loop;
			}
		
			/* Before we output anything, extern-declare any that we need and haven't
			 * declared yet. */
			for (auto i_by_off = by_off.begin(); i_by_off != by_off.end(); ++i_by_off)
			{
				auto el_type = i_by_off->second.m_local->find_type();
				auto name_pair = codeful_name(el_type);
				string mangled_name = mangle_typename(name_pair);
				if (names_emitted.find(mangled_name) == names_emitted.end())
				{
					emit_extern_declaration(std::cout, name_pair, /* force_weak */ false);
					names_emitted.insert(mangled_name);
				}
			}

			{ // for goto-over purposes
				/* Output in offset order, CHECKing that there is no overlap (sanity). */
				cout << "\n/* uniqtype for stack frame ";
				string unmangled_typename = typename_for_vaddr_interval(i_subp, interval);

				string cu_name = *i_subp.enclosing_cu().name_here();

				cout << unmangled_typename
					 << " defined in " << cu_name << ", "
					 << "vaddr range " << std::hex << interval << std::dec << " */\n";

				ostringstream min_s; min_s << "actual min is "
					<< ((by_off.size() == 0 ? 0 : by_off.begin()->first) + frame_offset);
				string mangled_name = mangle_typename(make_pair(string(""), cu_name + unmangled_typename));

				/* Is this the same as a layout we've seen earlier for the same frame? */
				bool emitted_as_alias = false;
				for (auto i_earlier_frame_int = subp_frame_intervals.begin();
					i_earlier_frame_int != i_frame_int;
					++i_earlier_frame_int)
				{
					auto found_earlier_by_off = by_off_by_interval.find(
						i_earlier_frame_int->first);
					assert(found_earlier_by_off != by_off_by_interval.end());
					multimap<Dwarf_Signed, frame_element> const& earlier_by_off
					 = found_earlier_by_off->second;
					if (earlier_by_off == by_off)
					{
						// just output as an alias
						auto i_earlier_last_equal = find_equal_range_last<set<frame_element> >(
							i_earlier_frame_int, i_frame_int);
						string unmangled_earlier_typename
						 = typename_for_vaddr_interval(i_subp,
							boost::icl::discrete_interval<Dwarf_Addr>::right_open(
								i_earlier_frame_int->first.lower(), i_earlier_last_equal->first.upper()
							)
						);
						string mangled_earlier_name = mangle_typename(
							make_pair("", cu_name + unmangled_earlier_typename));
						cout << "\n/* an alias will do */\n";
						emit_weak_alias_idem(cout, mangled_name, mangled_earlier_name); // FIXME: not weak
						emitted_as_alias = true;
						break; // just one alias is enough, even if other duplicates exist
							// (they themselves having been emitted as aliases)
					}
				}
				if (emitted_as_alias) continue;

				/* In frametypes we define the structure size as always extending up
				 * to the CFA, i.e. maxoff of zero */
				Dwarf_Signed end_offset_of_highest_member = (by_off.size() == 0) ? 0
				 : ({ auto i_end = by_off.end(); --i_end; i_end->first + *i_end->second.piece_size_in_bytes(); });
				// FIXME: in ambiguous/overlapping cases this is not entirely right:
				// a lower-starting field might still end higher, if it is bigger.
				// We want highest_end_offset, not end_offset_of_highest_(starting_)member.
				Dwarf_Unsigned interval_maxoff = (end_offset_of_highest_member < 0) ? 0
					: end_offset_of_highest_member;
				write_uniqtype_section_decl(cout, mangled_name);
				write_uniqtype_open_composite(cout,
					mangled_name,
					unmangled_typename,
					interval_maxoff + frame_offset,
					by_off.size(),
					/* not_simultaneous */ false,
					/* comment_str */ min_s.str()
				);
				opt<unsigned> prev_offset_plus_size;
				opt<unsigned> highest_unused_offset = opt<unsigned>(0u);
				// FIXME: prev_offset_plus_size needn't be the right thing.
				// We want the highest offset yet seen.
				for (auto i_by_off = by_off.begin(); i_by_off != by_off.end(); ++i_by_off)
				{
					ostringstream comment_s;
					unsigned offset_after_fixup = i_by_off->first + frame_offset;
					iterator_df<type_die> el_type = i_by_off->second.m_local->find_type();
					if (i_by_off->second.m_local.name_here())
					{
						comment_s << *i_by_off->second.m_local.name_here();
					}
					else comment_s << "(anonymous)"; 
					comment_s << " -- " << i_by_off->second.m_local.spec_here().tag_lookup(
							i_by_off->second.m_local.tag_here())
						<< " @" << std::hex << i_by_off->second.m_local.offset_here() << std::dec
						<< "(size ";
					if (el_type && el_type->calculate_byte_size()) comment_s << *el_type->calculate_byte_size();
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
						/* is_first */ i_by_off == by_off.begin(),
						offset_after_fixup,
						mangled_name,
						comment_s.str()
					);
					if (el_type && el_type->calculate_byte_size())
					{
						prev_offset_plus_size = offset_after_fixup + *el_type->calculate_byte_size();
						highest_unused_offset = std::max<unsigned>(
							offset_after_fixup + *el_type->calculate_byte_size(), highest_unused_offset);
					}
					else
					{
						prev_offset_plus_size = opt<unsigned>();
						highest_unused_offset = opt<unsigned>();
					}
				}
				write_uniqtype_close(cout, mangled_name);
			} // end for goto-over purposes

		continue_loop:
			i_frame_int = i_last_equal;
		} /* end for i_int */
		/* The number of intervals we're dealing with should equal the number
		 * of ... souldn't it? */
		if (debug_out > 1) cerr << "processed " << n_real_intervals
			<< " real intervals for this subprogram... by_off_by_interval iterative_size"
			<< " was " << by_off_by_interval_nentries << ", now " << by_off_by_interval.iterative_size() 
			<< endl;
		assert(n_real_intervals == by_off_by_interval.iterative_size() -
			by_off_by_interval_nentries);

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
	set< pair< boost::icl::discrete_interval<Dwarf_Addr>, iterator_df<subprogram_die> > >
	 sorted_intervals;
	for (map< iterator_df<subprogram_die>, frame_intervals_t >::iterator i_subp_intervals 
	  = frame_intervals_by_subprogram.begin(); i_subp_intervals != frame_intervals_by_subprogram.end();
	  ++ i_subp_intervals)
	{
		// now output an allocsites-style table for these 
		for (auto i_int = i_subp_intervals->second.begin(); i_int != i_subp_intervals->second.end(); 
			++i_int)
		{
			/* Skip any that don't contain a stack-offset'd element. In the original
			 * frametypes, these intervals would never appear in the interval map.
			 * But for us they do because we record extra stuff. */
			auto found_earlier_by_off = by_off_by_interval.find(i_int->first);
			assert(found_earlier_by_off != by_off_by_interval.end());
			multimap<Dwarf_Signed, frame_element> const& by_off
			 = found_earlier_by_off->second;
			if (by_off.size() == 0) continue;
			sorted_intervals.insert(make_pair(i_int->first, i_subp_intervals->first));
		}
	}
	/* Frame alloc records need to be exactly one-for-one with the
	 * records we emitted earlier, even if that results in multiple
	 * contiguous entries with the same offset value. This is because
	 * each record includes a pointer back to a frame type structure,
	 * and these are named according to the address range they cover.
	 * We need to refer to that range's frametype, even if the frame
	 * offset is coincidentally the same as a neighbouring range's. */
	cout << "struct frame_allocsite_entry frame_vaddrs[] = {" << endl;
	for (auto i_pair = sorted_intervals.begin(); i_pair != sorted_intervals.end(); ++i_pair)
	{
		auto interval = i_pair->first;
		unsigned offset_from_frame_base = frame_offsets_by_subprogram[i_pair->second];
	
		if (i_pair != sorted_intervals.begin()) cout << ",";
		cout << "\n\t/* frame alloc record for vaddr 0x" << std::hex << interval.lower() 
			<< "+" << interval.upper() << std::dec << " */";
		cout << "\n\t{\t" << offset_from_frame_base << ","
			<< "\n\t\t{ 0x" << std::hex << interval.lower() << "UL, " << std::dec
			<< "&" << mangle_typename(make_pair("", *i_pair->second.enclosing_cu().name_here() +
				typename_for_vaddr_interval(i_pair->second, interval)))
			<< " }"
			<< "\n\t}";
		++total_emitted;
	}
	// close the list
	cout << "\n};\n";
}

struct triple : public pair<string, pair< codeful_name, pair<unsigned,unsigned> > >
{                    // element name, codeful name, piece pair (see below)
	explicit triple(const frame_element& el)
	{
		string name_to_use;
		codeful_name type;
		if (el.m_local)
		{
			auto maybe_name = el.m_local->find_name();
			if (!maybe_name)
			{
				ostringstream fake_name;
				fake_name << "__anon" << std::hex << el.m_local.offset_here();
				cerr << "Strange: " << el.m_local
					<< ". Calling it " << fake_name.str()
					<< "." << endl;
				name_to_use = fake_name.str();
			} else name_to_use = *maybe_name;
			auto t = el.m_local->find_type();
			assert(t);
			type = codeful_name(t);
		}
		else
		{
			assert(el.m_caller_regnum);
			Dwarf_Signed caller_regnum = *el.m_caller_regnum;
			auto save_location = el.effective_expr_piece.copy_as_if_whole();
			// we make up a name
			ostringstream name;
			name << "__saved_caller_reg" << caller_regnum;
			assert(caller_regnum != DW_FRAME_CFA_COL3);
			/* NOTE: __saved_caller_reg_1436 is the CFA column.
			 * Hmm. And the CFA is computed. What is the right logic for this?
			 * We could pretend that every arch has an additional register,
			 * number 1436, whose value is always computable and when we compute
			 * it for a given caller, we get the *callee*'s CFA, or equivalently
			 * (*usually* equivalently) the "end" of the caller's stack frame.
			 * Note that it lives in the callee's DWARF so this requires an
			 * explicit re-homing.
			 *
			 * This duplicates our "frame offset" map, if we are still generating
			 * that, but I guess we don't need it any more because there is no
			 * overall frame layout.
			 *
			 * Let's keep the assertion and filter it out on the caller side, i.e.
			 * do consider the CFA a frame element, but
			 * don't create triples for it. Hence the assertion above! */
			name_to_use = name.str();
			type = make_pair("", "__opaque_word");
		}
		this->first = name_to_use;
		this->second.first = type;
		/* The "piece pair" is encoded specially to account for the fact that
		 * in some cases we don't know how many bits/bytes the entire element
		 * covers, e.g. for an incomplete type. So:
		 * - the second element of the pair is not the size in bits, but the
		 *   number of uncovered bits remaining *after* this piece. If there
		 *   is only one implicit piece, this number is always 0. (If there is
		 *   only one piece but it's explicit, it has an explicit size.) */
		this->second.second = make_pair(
			el.effective_expr_piece.offset_in_bits(),
			(el.effective_expr_piece.size_in_bits() && el.program_element_size_in_bytes()) ?
				(8 * *el.program_element_size_in_bytes()
				 - el.effective_expr_piece.offset_in_bits()
				 - *el.effective_expr_piece.size_in_bits())
				: 0 /* if we have no size bound and/or no next piece, assume it
				       covers everything remaining */
		);
	}
};
std::ostream& operator<<(std::ostream& s, const triple& t)
{
	s << "<" << t.first << ", " << mangle_typename(t.second.first) << ", "
		 << "(" << t.second.second.first << ", " << t.second.second.second << ")" << ">";
	return s;
}

void write_triples(ostream& s,
	map< triple, vector< frame_element > > const& m,
	map< triple, unsigned >& out_idx_map)
{
	s << "name\ttype\tpiece-coords" << endl;
	unsigned i = 0;
	for (auto i_map_pair = m.begin(); i_map_pair != m.end(); ++i_map_pair)
	{
		s << i_map_pair->first.first << "\t";
		s << mangle_typename(i_map_pair->first.second.first) << "\t";
		s << std::dec << i_map_pair->first.second.second.first << " "
			<< i_map_pair->first.second.second.second;
		s << "\t(" << i_map_pair->second.size() << " elements)";
		s << endl;
		out_idx_map[i_map_pair->first] = i++;
	}
}

typedef pair< Dwarf_Signed, triple > quad;
/* this generalises to stack quads, regfile quads, computed quads, ... more?
 * Recall: a triple is <var, type, piece-spec>
 * and a quad is <location, triple>
 *
 * Quads have many micro-intervals and one mega-interval *per subprogram*.
 * (Initially I collected mega-intervals across the whole text segment but
 * it just created enormous mega-intervals which could be mostly empty,
 * i.e. one same-name/type variable in two distant functions.)
 *
 * Quads appear and disappear over the code address space;
 * the micro intervals are the PC ranges over which that quad is in the layout.
 * The mega-interval is the lowest-addressed appearance
 * and the highest-addressed disappearance.
 *
 * If we record quads by their micro-intervals only, we get a lot of
 * intervals.
 * If we record them by their mega-intervals only, we get a lot of
 * *simultaneous quads* of which not all are valid, so we need a
 * longer, sparser bitmap which also wastes space.
 *
 * So we want to pick the practical "macro-intervals" that balance
 * this trade-off.
 *
 * We can create the macro intervals by finding ranges with >NBITS
 * spanning intervals and splitting a macro interval which spans that range
 * but has no micro-interval intersecting that range.
 *
 * We need to split this until no bitmap requires more than NBITS.
 * NBITS cannot be lower than the maximum number of simultaneously live
 * micro-intervals.
 *
 * After this splitting, we know we have a representable result but it may
 * not be space-optimal, i.e. more splitting might yield a more compact
 * result. TODO: understand how to optimise this. We probably want to
 * minimise the number of *bitmap changes*, since the bitmap only needs
 * re-emitting when it changes.
 *
 * We can write about this as a sliding window scheme.
 * The window slides over a sorted sequence of quad intervals.
 * The window has a fixed maximum size N.
 * If there are ever more than N live micro-intervals, we mark
 * that range as special and fall back on a slower structure
 * (One possible: if we have M bits, N = M-1 and so we know an all-1s bitmap
 * signifies "use slower structure".)
 *
 * The excess bits in our bitmap give us latitude to use bigger
 * intervals than the micro-intervals.
 *
 * Now we know our limit N, our job is to pick a minimal set of splittings
 * of the mega-intervals s.t. 
 * the number of included intervals is always <=N.
 * Over some interval I where we have >N, which is the best one to split?
 * Obviously, we'd like to pick one interval that is not live over all of I.
 * There might not be such an interval. We need to pick some set whose
 * non-live parts collectively cover I.
 * Or put differently, we pick one that will narrow I to some I' < I,
 * then iterate this approach until we always have <=N included intervals.
 * Do we just pick the biggest-non-live-extent and keep doing that? Sounds good.
 *
 * (If we split everything, we'd degenerate into the classic struct-style
 * approach where each quad's micro-interval gets its own entry in the
 * list. This minimises the window size, at the cost of multiplying up
 * the number of records. By contrast, we can allow quads to recur across
 * multiple micro-intervals at small cost, because it's only a bit in a
 * bitmap.)
 *
 * XXX: check we don't get screwed up by functions that are discontiguous
 * (Bolt/Propeller might split / reorder -- talk from EuroLLVM 2025
 *   HMM... liballocs generally cares about this. One function may be
 *   many allocations. That is conceptually OK but our practice of
 *   declaring that a function's entry point is an allocation
 *   "of" a zero-sized __FUN_* type may or may not be? Actually it's OK.
 *   If a function is split over many sections, its instructions are split
 *   over many allocations, but it still has single entry point.)
 */
void collect_quad_stats(
	frame_intervals_t const& elements_by_interval,
	subprogram_vaddr_interval_map_t const& subprograms_by_vaddr,
	std::function<optional<Dwarf_Signed>(frame_element const&)> maybe_get_key,
	map<quad, boost::icl::interval_set<Dwarf_Addr> >& micro_intervals_by_quad,
	vector< pair< boost::icl::discrete_interval<Dwarf_Addr>, pair<quad, subprogram_key> > >&
	   quad_mega_intervals,
	boost::icl::interval_map<Dwarf_Addr, set< quad > >& quads_by_mega_interval_address
)
{
	map< pair<quad, subprogram_key>, set< boost::icl::discrete_interval<Dwarf_Off> > >
	  micro_intervals_by_quad_and_subprogram;
	for (auto i_int = elements_by_interval.begin(); i_int != elements_by_interval.end();
		 ++i_int)
	{
		auto i_found_subp = subprograms_by_vaddr.find(i_int->first.lower());
		/* collect the relevant (either CFA-offset or register),
		 * sort them by offset/regnum,
		 * output them as a mergeable sequence,
		 * then point to that list (including a length) */
		vector< pair< Dwarf_Signed, frame_element > > elements;
		map< pair< Dwarf_Signed, triple >, frame_element > elements_map; // for sanity checking
		for (auto i_el = i_int->second.begin(); i_el != i_int->second.end(); ++i_el)
		{
			optional<Dwarf_Signed> maybe_offset;
			if (optional<Dwarf_Signed>() != (maybe_offset = maybe_get_key(*i_el)))
			{
				quad quad = make_pair(*maybe_offset, triple(*i_el));
				micro_intervals_by_quad[quad].insert(i_int->first);
				if (i_found_subp != subprograms_by_vaddr.end())
				{
					micro_intervals_by_quad_and_subprogram[
						make_pair(quad, i_found_subp->second.begin()->first)
						].insert(i_int->first);
				}
				else
				{
					// FIXME: use a null subprogram key
				}
			}
		}
	}
	/* Now for each quad, get its highest and lowest addr.
	 * We do this once per subprogram, i.e. we calculate one
	 * mega-interval per quad-subprogram pair. */
	for (auto i_quad_pair = micro_intervals_by_quad_and_subprogram.begin();
	          i_quad_pair != micro_intervals_by_quad_and_subprogram.end();
		++i_quad_pair)
	{
		auto& quad_subp_pair = i_quad_pair->first;
		auto& q = i_quad_pair->first.first;
		auto& subp_k = i_quad_pair->first.second;

		// these are the whole-DSO mega-mega-interval that we must break down by subprogram
		// XXX: are we just clamping this to the subprogram boundaries? That's not what
		// we want. Walk subprograms and then walk all micro intervals filtered by subprogram.
		// This also works if the subprogram is discontiguous!
		// 
		Dwarf_Addr lowest_micro_lower = i_quad_pair->second.begin()->lower();
		Dwarf_Addr highest_micro_upper = i_quad_pair->second.rbegin()->upper();

		// XXX: want to print these sorted by ...?
		auto the_int = boost::icl::discrete_interval<Dwarf_Addr>::right_open(
			lowest_micro_lower, highest_micro_upper);
		quad_mega_intervals.push_back(make_pair(the_int, quad_subp_pair));
		set<quad> singleton; singleton.insert(q);
		unsigned set_size_previously_at_lower =
		    (quads_by_mega_interval_address.find(highest_micro_upper)
		  == quads_by_mega_interval_address.end()) ? 0 : 
		       quads_by_mega_interval_address.find(highest_micro_upper)->second.size();
		quads_by_mega_interval_address += make_pair(
			the_int,
			singleton
		);
		unsigned set_size_now_at_lower =
		    (quads_by_mega_interval_address.find(highest_micro_upper)
		  == quads_by_mega_interval_address.end()) ? 0 : 
		       quads_by_mega_interval_address.find(highest_micro_upper)->second.size();
		assert(set_size_now_at_lower >= set_size_previously_at_lower);
		assert(set_size_now_at_lower <= set_size_previously_at_lower + 1);
	}
	std::sort(quad_mega_intervals.begin(), quad_mega_intervals.end());
	for (auto i_mega = quad_mega_intervals.begin();
			i_mega != quad_mega_intervals.end(); ++i_mega)
	{
		auto& q_subp_pair = i_mega->second;
		auto& q = q_subp_pair.first;
		auto& subp_k = q_subp_pair.second;
		auto& the_int = i_mega->first;
		cerr << "quad "
			<< "<" << std::hex << q.second
			<< ", " << std::dec << q.first
			<< "> in subprogram "
			<< subp_k.subprogram_name()
			<< " (idx " << quad_mega_intervals.size() << ")"
			<< " has mega-interval 0x" << std::hex << the_int.lower()
			<< ", 0x" << std::hex << the_int.upper()
			<< std::endl;
	}
	/* Now we want to print a visual map, by subprogram.
	 * We calculate the subprogram's columns
	 * as the set of all quads active during any part of the subprogram
	 * ... each may have >=1 micro-interval.
	 * We group them horizontally by their triple, then sort by key within the triple group
	 * We output one row per byte (!) of instruction space.
	 * We output an 'x' in a quad's column
	 * iff some micro-interval, of the quad, includes this byte address
	 */
	optional<subprogram_key> current_subp;
	Dwarf_Addr current_subp_begin;
	Dwarf_Addr current_subp_end;
	auto compare_quads = [](quad const& q1, quad const& q2) -> bool {
		// we are operator<
		return q1.second < q2.second
		|| (q1.second == q2.second && q1.first < q2.first);
	};
	set< quad, __typeof(compare_quads) > columns(compare_quads);
	for (unsigned long vaddr = quad_mega_intervals.begin()->first.lower();
		vaddr != quad_mega_intervals.rbegin()->first.upper();
		++vaddr)
	{
		/* Has our subprogram changed? If so, recalculate columns. */
		if (!current_subp || vaddr == current_subp_end)
		{
			// current subp is...
			auto i_found_subp = subprograms_by_vaddr.find(vaddr);
			if (i_found_subp == subprograms_by_vaddr.end())
			{
				// no current subp
				current_subp = optional<subprogram_key>();
				current_subp_begin = (Dwarf_Addr) -1;
				current_subp_end = (Dwarf_Addr) -1;
				continue;
			}
			current_subp = i_found_subp->second.begin()->first;
			current_subp_begin = vaddr;
			current_subp_end = //end_of_contiguous_range(vaddr, current_subp);
				i_found_subp->first.upper();
			
			/* Our columns are the triple and the key, i.e. the quad!
			 * We have one per quad that is *active at any PC in the current
			 * subprogram [nitpick: contiguous fragment thereof].  */
			//columns = quads_over(current_subp_begin, current_subp_end);
			columns.clear();
			vector<quad> spanning_quads;
			assert(current_subp_end != (Dwarf_Addr) -1);
			assert(current_subp_end >= vaddr);
			for (auto i_mega_intersecting = quads_by_mega_interval_address.find(vaddr);
				i_mega_intersecting != quads_by_mega_interval_address.end()
				&& i_mega_intersecting != quads_by_mega_interval_address.find(current_subp_end);
				++i_mega_intersecting)
			{
				auto& s = i_mega_intersecting->second;
				for (auto i_quad = s.begin(); i_quad != s.end(); ++i_quad)
				{
					spanning_quads.push_back(*i_quad);
				}
			}
			for (auto i_spanning = spanning_quads.begin(); i_spanning != spanning_quads.end();
				++i_spanning)
			{
				auto& q = *i_spanning;
				for (auto i_micro = micro_intervals_by_quad[q].find(current_subp_begin);
					i_micro != micro_intervals_by_quad[q].find(current_subp_end);
					++i_micro)
				{
					// if this loop body runs once per quad, that's enough
					columns.insert(q);
					break;
				}
			}
			/* Output a header for this subprogram. */
			cerr << "Subprogram " << current_subp->subprogram_name() << " over range ["
				<< std::hex << vaddr << ", " << current_subp_end << ") has " << columns.size()
				<< " quads:" << endl;
			cerr << "          ";
			for (auto i_col = columns.begin(); i_col != columns.end(); ++i_col)
			{
				if (i_col != columns.begin() &&
					({ auto i_prev_col = i_col; --i_prev_col; })->first != i_col->first )
				{
					cerr << '|';
				}
				cerr << ' ';
			}
			cerr << endl;
		}
		/* Has our row changed from the last one we output? If not, just remember
		 * this and go to the next. */

		cerr << std::setw(9) << std::hex << vaddr << ' ';
		/* For each column, output an 'x' if and only if that quad is active, else ' ' */
		for (auto i_col = columns.begin(); i_col != columns.end(); ++i_col)
		{
			if (i_col != columns.begin() &&
				({ auto i_prev_col = i_col; --i_prev_col; })->first != i_col->first )
			{
				cerr << '.';
			}
			/* Have we switched to a new triple? If so output '|' (header line)
			 * or ' ' (otherwise).
			 * -- XXX- our quads are the wrong way around! want triple first, key
			 * second. BUT in other places we want the key first.
			 * So we need a reversed comparator.
			 */
			if (micro_intervals_by_quad[*i_col].find(vaddr)
				!= micro_intervals_by_quad[*i_col].end())
			{
				cerr << 'x';
			}
			else cerr << ' ';
		}
		cerr << endl;
	}
#if 0
	/* Since quads are pairs <offset, triple>
	 * and quad intervals are pairs <interval, quad>
	 * if we sort the quad intervals we are sorting by the start address. */
	std::sort(quad_mega_intervals.begin(), quad_mega_intervals.end());
	for (auto i_mega_int = quad_mega_intervals.begin(); i_mega_int != quad_mega_intervals.end();
		++i_mega_int)
	{
		/* Intersect this interval with the intervals in the
		 * subprogram_vaddr_interval_map. We want to iterate
		 * over all intersecting intervals. Since the subprograms are
		 * sorted by vaddr, it is not expensive to zoom in on the right range. */
		for (auto i_found_subp = subprograms_by_vaddr.find(
			i_mega_int->first.lower());
			i_found_subp != subprograms_by_vaddr.end() &&
			   i_found_subp->first.lower() < i_mega_int->first.upper();
			++i_found_subp)
		{
//			if (i_mega_int->first.upper() - i_mega_int->first.lower() > 8192)
//			{
//				cerr << " SUSPICIOUS"; // i.e. we should break by function
//			}


			set<quad> singleton; singleton.insert(i_mega_int->second.first);
			quads_by_mega_interval_address += make_pair(
				boost::icl::discrete_interval<Dwarf_Addr>::right_open(
					lower, //i_mega_int->first.first,
					upper //i_mega_int->first.second
				),
				singleton
			);
		}
	}
#endif
	// how many live at each PC?
	for (auto i_int = quads_by_mega_interval_address.begin(); i_int != quads_by_mega_interval_address.end();
		++i_int)
	{
		/* Find the linear index of the lowest-mega-interval-addressed and
		 * highest-mega-interval-addressed quad spanning this interval.
		 * We should only find quad mega-intervals for the current
		 * subprogram. How do we ensure this? By not adding to
		 * quads_by_mega_interval_address any mega-interval that spans
		 * subprograms. This does mean, however, that one quad has
		 * many mega-intervals.
		 * 
		 * This is how many entries, in quad index space,
		 * our bitmap has to be able to address. If there are too many
		 * we will split a quad whose mega-interval spans here but
		 * that does not have any micro-interval intersecting here.
		 */

		auto subprogram_at = [subprograms_by_vaddr](Dwarf_Addr addr) {
			return subprograms_by_vaddr.find(addr);
		};
		auto i_current_subp = subprogram_at(i_int->first.lower());
		assert(i_current_subp != subprograms_by_vaddr.end());
		assert(i_current_subp->second.size() == 1);
		auto current_subp_k = i_current_subp->second.begin()->first;

		/* There is a set of quad mega-intervals spanning this PC range.
		 * Of those, what is the lowest mega-interval bottom
		 * and the highest mega-interval top?
		 * We don't know! We would have to search backwards and forwards.
		 * We haven't kept the right data structures to answer this efficiently.
		 * OK, added subprogram to mega_intervals. That might be enough?
		 * AH NO. We still can't get the mega-interval of this quad,
		 * except by searching.
		 *
		 * WHY do we want to know this? To get the width in idx-space
		 * that a bitmap covering this address range would have to span.
		 * If it's more than our bitmap max width, we do some splitting.
		 *
		 * (To accommodate occasional over-width bitmaps, maybe we can do a
		 * "continuation record" thing? i.e. a rare case of multiple words
		 * of bitmap squished together.)
		 */
#if 0
		auto i_lowest_quad = i_int->second.begin();
		__typeof(i_lowest_quad) i_highest_quad;

		if (i_int->second.size() == 0) i_highest_quad = i_lowest_quad;
		else { i_highest_quad = i_int->second.end(); --i_highest_quad; }
		assert(i_highest_quad != i_lowest_quad);
		quad lowest_q = *i_lowest_quad;
		quad highest_q = *i_highest_quad;
#endif
		auto& quad_set_here = i_int->second;
		// FIXME: these find_if are doing linear search, but we can do binary search
		// We want to find the linear index of the lowest-star-addressed
		// mega-interval that intersects this interval,
		// and similar for the highest.
#define CONTAINS(s, el) \
  ((s).find(el) != (s).end())

#define COND (qpp.second.second == current_subp_k && \
				qpp.first.upper() >= i_int->first.lower() \
				&& qpp.first.lower() <= i_int->first.upper())

		auto i_vecpos_lowest = std::find_if(quad_mega_intervals.begin(),
			quad_mega_intervals.end(), [/*lowest_q,*/ current_subp_k, quad_set_here, i_int](
				pair< boost::icl::discrete_interval<Dwarf_Addr>, pair< quad, subprogram_key > > const& qpp
			) { return COND; });
				/* This is wrong. It is checking whether the *micro* intervals
				 * active here contain our quad.  We want to find the lowest
				 * mega-*/
				//CONTAINS(quad_set_here, qpp.second.first)
				//&& qpp.second.second == current_subp_k; /* <-- should alwyas be true? */});
		auto i_vecpos_highest_plus_one = std::find_if(i_vecpos_lowest,
			quad_mega_intervals.end(), [/*highest_q,*/ current_subp_k, quad_set_here, i_int](
				pair<boost::icl::discrete_interval<Dwarf_Addr>, pair< quad, subprogram_key> > const& qpp
			) { return !COND; });
		unsigned vecidx_low = i_vecpos_lowest - quad_mega_intervals.begin();
		unsigned vecidx_high = i_vecpos_highest_plus_one - quad_mega_intervals.begin();
		cerr << std::hex << i_int->first << ": " << std::dec
			<< i_int->second.size() << " quad mega-intervals spanning; "
			<< "addr-sorted mega-interval indices lowest " << vecidx_low
			<< ", highest-plus-one " << vecidx_high
			<< ", range " << (vecidx_high - vecidx_low)
			<< endl;
		
	}
}

void write_compact_output(
	subprogram_vaddr_interval_map_t const& subprograms_by_vaddr,
	map<subprogram_key, iterator_df<subprogram_die> > const& subprograms_by_key,
	frame_intervals_t const& elements_by_interval)
{
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
	 *         If we do the SHF_MERGE thing, to describe layouts, I'm tempted to encode the
	 *         "run length" in the symbol that marks the start of each run.
	 *         We probably want the run length to be represented elsewhere too,
	 *           i.e. in the per-PC table (but could just use a symidx! not sure).
	 *         But in any case, once we do merging, we have overlapping allocations,
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


	cerr << "Calculating name--type--piece triples for all elements" << endl;
	map< triple, vector< frame_element > > m;
	map< frame_element, triple > reverse_m;
	/* We need to make getting a 'triple idx' easy. */
	map< triple, unsigned > triple_idx_map;
	for (auto i_int = elements_by_interval.begin(); i_int != elements_by_interval.end();
		++i_int)
	{
		for (auto i_el = i_int->second.begin(); i_el != i_int->second.end(); ++i_el)
		{
			/* Currently we don't add a synthetic "saved register"-like entry
			 * for the current CFA. */
			if (!i_el->is_current_cfa())
			{
				assert(!i_el->m_caller_regnum ||
					!(*i_el->m_caller_regnum == DW_FRAME_CFA_COL3));
				auto t = triple(*i_el);
				m[t].push_back(*i_el);
				auto inserted = reverse_m.insert(make_pair(*i_el, t));
				/* Why do we think the element is unique in the reverse map?
				 * Well, one element denotes one name--type--piece at one
				 * location (e.g. stack or reg), but the same name--type--piece
				 * may recur at the same location over many PC ranges. So the
				 * best we can say is that we may see the same element many times
				 * but it should be the same triple. */
				if (!(inserted.second ||
					inserted.first->second == t))
				{
					std::clog << "Re-inserting but triples non-equal: `"
						<< inserted.first->second << "' vs `" << t << "'" << endl;
				}
				assert(inserted.second ||
					inserted.first->second == t);
			}
		}
	}
	cerr << "Finished calculating name--type--piece triples" << endl;
	write_triples(cout, m, triple_idx_map);

	/* After the triples, what's next? It's the location descriptions.
	 * A description is always a *piece* of an "effective expression"
	 * (see frame_element.hpp). Cases that need splitting here:
	 * - implicit pointer value
	 * - implicit literal value
	 * - other computed values
	 * - computed locations: simple cases (reg number or stack offset)
	 * - other computed locations
	 *
	 * I THINK what we want to do is:
	 * - walk PC intervals
	 * - for each, emit the whole frame layout, as a mergeable sequence of 32-bit numbers
	 *      -- emit (1) CFA-relative first as one sequence, sorted by offset
	 *      -- emit regs next as another sequence, sorted by register number
	 *      -- emit a set of functions that handle the computeds and implicit-values next
	 *           (XXX: can functions handle the "implicit value" case?)
	 *      -- then emit the computed as a final mergeable sequence,
	 *           sorted by idx of the name--type triple
	 *      (all ASSUMING that merging of these sequences will really happen,
	 *       to an appreciable degee. See below.)
	 * - MEASURE the merge gain
	 * - label with symbols -- how are we going to consume this?
	 *       -- liballocs querying a stack address will use table (1)
	 *       -- liballocs may gain an "explain this mcontext" API? for regs
	 *       -- .. and a "resolve source identifier" API? for computed/implicit-values
	 */
	/* This code "works" but I'm suspicious, because
	 * - too often we get multiple distinct vars with the same triple and stack slot -- why?
	 *   - can be legit: e.g. multiple lexical blocks declaring the same name/type get commoned
	 * - we never get callee-save registers -- why? are they always saved in a register?
	 * - we never get non-zero piece specs -- why?
	 *
	 * We also have a compactness crisis: it'll be far more compact to group the frames
	 * by subprogram, then compute a "super-vector", then for each interval
	 * record which subset of the vector is valid. Only layouts with >63 elements
	 * need to be represented explicitly. Maybe we can do that by generating a
	 * synthetic struct type?
	 *
	 * Maybe we can do a scan for PCs having >64 simultaneous elements?
	 * Need not even pick 64; e.g. maybe 32 would be optimal.
	 * If we emit the layout in order of last-valid PC, then we get a sliding window
	 * in PC-space.
	 *
	 * Let's make a list of the optimizations we want to apply, then measure the effect
	 * of each?
	 *
	 * 1. Naive approach: distinct layout vectors for each layout-distinct interval,
	 *   table of pairs <base-addr, layout vector>
	 * 2. Turn on mergeability of layout vectors; table is
	 *   <base-addr, layout vector begin, layout vector end>
	 * 3. Simple bitmap approach: N=32- or N=64-bit bitmap (do profiling to pick which),
	 *   pool all layouts of a given frame,

	 *   GAGHAGHAGH. The bitmap approach doesn't work unless we also encode
	 *   the offset of each element, since this currently isn't represented.
	 *   We need a "Super-layout vector" and calculate bitmaps over that.
	 *    i.e. all the <triple, offset> pairs across the whole function -- "quads", not triples.
	 *
	 *    Then we can represent the function by a sequence of words that is
	 *    run-length encoded: <ninstrs, superlayout bitmap> ?
	 *
	 *       PROBLEM: the superlayout might be fairly big.
	 *       We can't expect one bitmap to cover all quads for the whole function, say.
	 *       BUT we can do something clever: sort the superlayout by vaddr,
	 *       meaning each RLE entry has an "earliest superlayout vaddr".
	 *       The bitmap is indexed relative to this offset.
	 *           How do we record this earliest vaddr?
	 *           We are basically trying to achieve "one word per change in layout",
	 *           and we borrow some bits from each word to represent how far in PC-space the layout lasts,
	 *           but we now *also* need some bits to represent hte delta in sorted-quad-space.
	 *           We could reserve 0 bits and say the delta is always 1?
	 *           Oh, no because if an element goes away but we still need the same earliest-span-start
	 *             element, we don't want to advance in span-space at all. So, 1 bit is the minimum.
	 *             If we want to advance multiple places in span-space, we need to write multiple words
	 *                 with the 'advance span space' bit set.
	 *             Their bitmaps would just be shifted by 1, while nothing changes in the layout
	 *                 (but something will! specifically,
	 *                 some new element will be entering the layout;
	 *                 otherwise we wouldn't need to advance in the span space)
	 *
	 *           i.e. the idea of this design is to emit one word per "elementary change in layout"
	 *
	 *               PROBLEM? How do we binary-search by offset in this design?
	 *               The bitmap gives us a bunch of elements but we have to
	 *               traverse these linearly because they are not sorted by offset.
	 *               Clever caching perhaps? We could build an offset-sorted vector from the bitmap
	 *                    and try to cache these for frequently queried layouts?
	 *               More generally, to evaluate this we need a workload, even if highly synthetic.
	 *               We could say "randomly query the leaf type" i.e. for a random stack address.
	 *               That would give us sampling-based coverage measurement of the stack,
	 *               weighted by program time spent at each layout.
	 *               We would have to measure the cost of the lookup carefully, since interrupting
	 *               the main program is already expensive but is not a cost we want to measure...
	 *               I think we could use SIGPROF but then just use perf counters / rdtsc to measure
	 *                    time spent in metadata routines, i.e. ignoring time spent in signal handling
	 *               "Zero-cost reflection on unmodified native stacks [and register files]"
	 *                 -- want to say we subsume eh_frame (like eh-elfs),
	 *                       offer a better space/time trade-off than eh-elfs,
	 *                       and encode more information / support more+new applications / ...
	 *                       Demos are libunwind (perf?), ltrace (has stack-walking option!),
	 *                           some liballocs(libcrunch?) workload
	 *
	 *       For cases where the "span-space span" is too large,
	 *       i.e. the earliest-span-starting active element is more than 56 spans away from the
	 *                latest-span-starting element,
	 *       Then we repeat the elements as necessary by splitting spans.
	 *       E.g. if we have
	 *       24 bits to play with (8 bits for the run length &c, 24 for the bitmap)
	 *       we ensure that we repeat any element in a timely way, e.g. if a superelement
	 *       it's still alive 24 elements later (however many bytes of vaddr-space
	 *       that proves to be), we re-emit it.
	 *       INSTABILITY: this will bump some other superlayout elements outside the 24?
	 *       EXPERIMENT: let's visualise the distribution. I am imagining a
	 *         "piano roll"-style plot for a function, where vaddrs are along the bottom
	 *         and superlayout elements going up, bracketed by their triple;
	 *         also plot the number of simultaneously active elements, so we can get a
	 *         feel for the right size of bitmap.
	 *       Can we view outputting the superlayout elements as a scheduling problem,
	 *         a bit like instruction scheduling? We have a queue of obligations,
	 *         i.e. long-lived old superelements create such obligations and
	 *         we have a deadline for emitting them, in preference to a new superelement.
	 *         This is also a lot like range-splitting: re-emitting the old element
	 *         could be viewed as breaking its lifetime in two. HMM yes, that is better.
	 *         As long as there are not more live items than bits,
	 *         we can always represent a layout simply by advancing its base address
	 *         for every instruction -- and splitting every element so that
	 *         it begins a fresh range at that base address. So our bitmap begins with
	 *         is all 1s and our superlayout contains all those 
	 *
	 * LET's PRINT: "function <foo> has N distinct triples (maximum M live simultaneously)
	 *       and Q superelements". Need a better name for "superelement" first.
	 *       "elplace"? "elslots"? "expanded slots"? "slot product"?
	 *
	 *   Initially our super-layouts are sorted by offset and may not have >N
	 *   elements.
	 *
	 *   use frame-splitting to handle frames of >64 elements
	 *   use structs to handle any simultaneously-more-than-N-element intervals.
	 *   Table is <base_addr, frame-range-begin, Nhighest, bitmap> <-- Nhighest encodes frame range end; it's the highest idx of any set bit
	 * 4. "Sliding window": same but we compute a craftier frame-range-begin
	 *   table is <base_addr, frame-range-begin/end, bitmap>
	 *   i.e. unlike the simple bitmap approach, frame-range-begin is not the same
	 *   for every entry within the same frame (modulo splitting)
	 *      -- maybe we'd find there's no longer a need for splitting? well,
	 *      sometimes they probably will be, if there's >N elements
	 * 5.
	 */
	auto output_layout = [](Dwarf_Addr lower, Dwarf_Addr upper, unsigned nquads,
		vector< pair< Dwarf_Signed, frame_element > > const& elements,
		const string& comment,
		const string& layout_macro_prefix,
		std::function<void(pair< Dwarf_Signed, frame_element > const&)> output_element_pair) {
		/* TODO: For profiling the possible bitmap-based approach,
		 * output in a comment how many quads are spanning this
		 * start vaddr. */
		cout << "#undef " << layout_macro_prefix << "_LAYOUT" << endl;
		cout << "#define " << layout_macro_prefix << "_LAYOUT(start_vaddr, element_at_key) /* " << comment << " from 0x"
			<< std::hex << lower
			<< " to 0x" << std::hex << upper
			<< " (at start there are " << std::dec << nquads << " quads spanning)"
			<< " */ \\" << endl
			<< "\tBEGIN_" << layout_macro_prefix << "_LAYOUT(start_vaddr) \\" << endl;
		for (auto i_el_pair = elements.begin();
			i_el_pair != elements.end(); ++i_el_pair)
		{
			output_element_pair(*i_el_pair);
		}
		cout << "\tEND_" << layout_macro_prefix << "_LAYOUT(start_vaddr)" << endl;
		cout << layout_macro_prefix << "_LAYOUT(0x" << std::hex << lower
			<< ", emit_" << layout_macro_prefix << "_element)" << std::dec << endl;
	};
	auto output_element = [triple_idx_map](pair< Dwarf_Signed, frame_element > const& el_pair ) {
		triple t(el_pair.second);
		cout << "\telement_at_key("
			<< std::dec << (Dwarf_Signed) el_pair.first
			<< ", 0x" << std::hex << triple_idx_map[t] << ") "
			<< "/* " << t;
		if (el_pair.second.m_local) cout << " (local at 0x" << std::hex
			<< el_pair.second.m_local.offset_here() << std::dec << ")";
		cout << " */ \\"<< endl;
	};
	auto get_cfa_offset = [](frame_element const& el) -> optional<Dwarf_Signed> {
		return (el.is_stored() && el.has_fixed_offset_from_frame_base()) ?
			*el.has_fixed_offset_from_frame_base() : optional<Dwarf_Signed>();
	};
	auto get_register = [](frame_element const& el) -> optional<Dwarf_Signed> {
		optional<Dwarf_Signed> ret = el.has_fixed_register();
		if (ret)
		{
			if (el.m_caller_regnum)
			{
				assert(*el.m_caller_regnum != DW_FRAME_CFA_COL3); // the CFA is not itself stored
			}
			assert(*ret != DW_FRAME_CFA_COL3); // the CFA is not a register in which anything is stored
		}
		return ret;
	};
	auto output_all_layouts_by_key = [elements_by_interval, subprograms_by_vaddr](
		const string& layout_macro_prefix,
		std::function<optional<Dwarf_Signed>(frame_element const&)> maybe_get_key,
		std::function<void(Dwarf_Addr /* lower */, Dwarf_Addr /* upper */, unsigned /* nquads */,
			vector< pair< Dwarf_Signed, frame_element > > const& /* elements */,
			const string& /* comment */,
			const string& /* layout macro prefix */,
			std::function<void(pair< Dwarf_Signed, frame_element > const&)> /*output_element_pair */)
		> output_one_layout /* used also for padding => MUST be parameterised by element outputter... */,
		std::function<void(pair< Dwarf_Signed, frame_element > const&)> output_one_element
		)
	{

		/* Want a rolling picture of quads.
		 * Within a given function,
		 * track when a quad first appears and when it last appears.
		 * (Why by function? We should be able to cope with longer ranges than that,
		 * although doubtful.)
		 */
		map<quad, boost::icl::interval_set<Dwarf_Addr> > micro_intervals_by_quad;
		vector< pair< boost::icl::discrete_interval<Dwarf_Addr>, pair<quad, subprogram_key> > > quad_mega_intervals;
		boost::icl::interval_map<Dwarf_Addr, set< quad > > quads_by_mega_interval_address;
		
		/* We need a way to get the ordinal of a given quad.
		 */
		collect_quad_stats(
			elements_by_interval, // is an element just a quad for us? only keyed ones, ofc
			subprograms_by_vaddr,
			maybe_get_key,        // may return nothing i.e. "ignore for this table", e.g. we are doing frame offsets and it's a reg-located element
			micro_intervals_by_quad, // map from quad to set of its micro-intervals
			quad_mega_intervals,  // sorted vector of mega-intervals, quad+subprogram
			quads_by_mega_interval_address // quads whose mega-interval spans addr
		);

		auto i_prev_int = elements_by_interval.end();
		vector< pair< Dwarf_Signed, frame_element > > prev_elements;
		for (auto i_int = elements_by_interval.begin(); i_int != elements_by_interval.end();
			i_prev_int = i_int, ++i_int)
		{
			/* collect the relevant (either CFA-offset or register),
			 * sort them by offset/regnum,
			 * output them as a mergeable sequence,
			 * then point to that list (including a length) */
			vector< pair< Dwarf_Signed, frame_element > > elements;
			map< pair< Dwarf_Signed, triple >, frame_element > elements_map; // for sanity checking
			for (auto i_el = i_int->second.begin(); i_el != i_int->second.end(); ++i_el)
			{
				optional<Dwarf_Signed> key;
				if (optional<Dwarf_Signed>() != (key = maybe_get_key(*i_el)))
				{
					/* NOTE: it is possible to get duplicates here: same triple,
					 * same CFA offset or reg, same interval, ... different frame element!
					 * This is because two variables might have the same name, across
					 * distinct scopes / lexical blocks. If the compiler transforms
					 * the code so their lifetimes are interleaved, they might be
					 * "commoned" and result in this state of affairs. I have seen
					 * this happen for va_list instances, which makes a lot of sense.
					 * 
					 * What this really tells us is that "name" is not enough: really
					 * we want "source-level identity", which should be defined to
					 * account for scope. We had some approaches to dealing with this
					 * in the context of "effective names" and line number variation
					 * falsely deduplicating uniqtypes; see GitHub issue #71. */
					elements.push_back(make_pair(*key, *i_el));
					/* maybe_get_key should not have let us get a CFA frame element.
					 * Rationale: the CFA is always computed, never stored directly on
					 * the stack or in a register. NOTE that despite 'm_caller_regnum',
					 * when the regnum = DW_FRAME_CFA_COL3 it refers to *our* CFA, not
					 * the caller's. */
					if (i_el->m_caller_regnum && *i_el->m_caller_regnum == DW_FRAME_CFA_COL3)
					{
						std::clog << "Over " << std::hex << i_int->first
							<< " found a frame (" << layout_macro_prefix
							<< ") element describing the CFA, which"
							" should not have passed get_register() but did: reg is "
							<< *key << std::endl << std::dec;
					}
					assert(!i_el->m_caller_regnum || *i_el->m_caller_regnum != DW_FRAME_CFA_COL3);
					auto pair = elements_map.insert(make_pair(
						make_pair(*key, triple(*i_el)),
						*i_el
					));
					// assert(pair.second);
					if (!pair.second)
					{
						if (debug_out > 1) cerr << "Warning: distinct frame elements for the same triple: "
							<< "existing " << &pair.first->second << ", new "
							<< &*i_el << endl; // the printed addresses are useful in a debugger
					}
				}
			}
			std::sort(elements.begin(), elements.end());
			/* Skip output if we're contiguous with the last lot and identical. We will just
			 * implicitly extend. */
			if (i_prev_int != elements_by_interval.end()
			 && i_prev_int->first.upper() == i_int->first.lower()
			 && elements == prev_elements)
			{
				cout << "/* same layout continuing: 0x" << std::hex << i_int->first.lower()
					<< " to 0x" << std::hex << i_int->first.upper() << " */" << endl;
				continue; // OK to skip "next" here
			}

			/* If we're *not* contiguous with the last interval,
			 * output an empty frame layout spanning the gap. */
			auto output_no_element = [](pair< Dwarf_Signed, frame_element > const& ignored) {};
			if (i_prev_int != elements_by_interval.end()
			 && i_prev_int->first.upper() != i_int->first.lower())
			{
#define GET_QUADS_COUNT(addr) \
	( (quads_by_mega_interval_address.find(addr) == quads_by_mega_interval_address.end()) ? 0 : quads_by_mega_interval_address.find(addr)->second.size() )
				output_one_layout(i_prev_int->first.upper(), i_int->first.lower(),
					//quads_by_mega_interval_address.find(i_prev_int->first.upper())->second.size(),
					GET_QUADS_COUNT( i_prev_int->first.upper() ),
					vector< pair< Dwarf_Signed, frame_element > >(),
					"empty layout (padding)", layout_macro_prefix,
					output_no_element
				);
			}
			output_one_layout(i_int->first.lower(), i_int->first.upper(),
				GET_QUADS_COUNT( i_int->first.upper() ),
				elements, "bona fide layout (not padding)", layout_macro_prefix, output_one_element);

		next:
		// store for next time around
			prev_elements = elements;
		}
	};
	output_all_layouts_by_key("FRAME", get_cfa_offset,
		output_layout,
		output_element);
	output_all_layouts_by_key("REGFILE", get_register,
		output_layout,
		output_element);

} /* end write_compact_output */

enum flags_t
{
	ONLY_POINTERS = 1,
	INCLUDE_REGISTERS = 2,
	INCLUDE_CFI = 4,
	INCLUDE_COMPUTED = 8,
	INCLUDE_INCOMPLETE = 16,
	INCLUDE_STATIC = 32,
	OUTPUT_TRADITIONAL = 64
};

void add_local_elements(frame_intervals_t& out, sticky_root_die& root,
	map<subprogram_key, iterator_df<subprogram_die> > const& subprograms_by_key, flags_t flags)
{
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
	
	for (auto i_i_subp = subprograms_by_key.begin();
		i_i_subp != subprograms_by_key.end(); ++i_i_subp)
	{
		iterator_df<subprogram_die> i_subp = i_i_subp->second;
		iterator_bf_skipping_types start_bf(i_subp);
		unsigned start_depth = i_subp.depth();
		for (iterator_bf_skipping_types i_bf = start_bf;
			i_bf != core::iterator_base::END;
			/* After the first inc, we should always be at *at least* 1 + start_depth. */
			i_bf.increment(start_depth + 1))
		{
			// skip if not a with_dynamic_location_die
			if (!i_bf.is_a<with_dynamic_location_die>()) continue;

			/* Exploit "clever" (hopefully) aggregation semantics of 
			 * interval maps.
			 * http://www.boost.org/doc/libs/1_51_0/libs/icl/doc/html/index.html
			 */

			// enumerate the vaddr ranges of this DIE
			// -- note that some DIEs will be "for all vaddrs"
			// -- noting also that static variables need handling!
			//    ... i.e. they need to be handled in the *static* handler!

			// skip static variables
			if (i_bf.is_a<variable_die>() && i_bf.as_a<variable_die>()->has_static_storage())
			{
				/* FIXME: does sranges already deal with these? */
				continue;
			}
			auto i_dyn = i_bf.as_a<with_dynamic_location_die>();

			// skip member/inheritance DIEs
			if (i_dyn->location_requires_object_base()) continue;

			set< pair< boost::icl::discrete_interval<Dwarf_Addr>, frame_element > >
			local_elements = frame_element::local_elements_for(i_dyn, i_subp, root);
			for (auto i_el_pair = local_elements.begin(); i_el_pair != local_elements.end(); ++i_el_pair)
			{
				boost::icl::discrete_interval<Dwarf_Addr> interval = i_el_pair->first;
				auto& element = i_el_pair->second;
				set<frame_element> singleton_set = { element };

#define DO_DISCARD(r) \
				{ cerr << "Discarding element "; \
				  if (element.m_local) cerr << element.m_local.summary(); \
				  cerr << " at " << std::hex << i_el_pair->first << std::dec \
				  	<< " for reason " << r << endl; \
				  goto continue_to_next_element; \
				}
				if (!(flags & INCLUDE_REGISTERS) && element.has_fixed_register()) DO_DISCARD("register-located");
				if (!(flags & INCLUDE_COMPUTED) && element.has_value_function()) DO_DISCARD("value-function");
				if (!(flags & INCLUDE_STATIC) && element.is_static_masquerading_as_local()) DO_DISCARD("static-masquerading-as-local");
				if (!(flags & INCLUDE_INCOMPLETE) && element.m_local &&
					!(element.m_local->find_type() && element.m_local->find_type()->get_concrete_type())) DO_DISCARD("incomplete");
				if ((flags & ONLY_POINTERS) && (
					!element.m_local ||
					!(element.m_local->find_type()
						&& element.m_local->find_type()->get_concrete_type()
						&& element.m_local->find_type()->get_concrete_type().is_a<address_holding_type_die>())
					)
				) DO_DISCARD("not-a-pointer");
				if ((flags & OUTPUT_TRADITIONAL) && element.m_local)
				{
					/* Compatibility hack: drop if *any* piece (not just ours)
					 * reads a register, and drop any non-initial piece.
					 * These are to match the original frametypes.
					 * Note that neither DW_OP_fbreg nor DW_OP_call_frame_cfa is
					 * deemed to read a register *or* name a register. */
					shared_ptr<encap::loc_expr> p_whole_expr
					 = element.p_effective_expr;
					for (auto i_instr = p_whole_expr->begin();
						i_instr != p_whole_expr->end();
						++i_instr)
					{
						if (element.m_local.spec_here().op_reads_register(i_instr->lr_atom))
						{
							DO_DISCARD("reads-register");
						}
						if (element.m_local.spec_here().op_names_register(i_instr->lr_atom))
						{
							DO_DISCARD("names-register");
						}
					}
					if (element.effective_expr_piece.offset_in_bits() > 0)
					{
						DO_DISCARD("non-first-piece");
					}
					// also discard if the *initial* piece includes unsupported DWARF
					// (we will never loop
					auto is_recognised_dwarf = [](unsigned op) -> bool {
#define computed_case(num, ignored...)   if (op == num) return true;
#define special_case(num, ignored...)    if (op == num) return true;
						dwarf_expr_computed_ops(computed_case)
						dwarf_expr_special_ops(special_case)
						return false;
					};
					for (auto i_instr = p_whole_expr->begin();
						i_instr != p_whole_expr->end();
						++i_instr)
					{
						/* hit the end of a piece? stop now */
						if (i_instr->lr_atom == DW_OP_piece
						|| i_instr->lr_atom == DW_OP_bit_piece) break;
						/* needs memory? */
						if (i_instr->lr_atom == DW_OP_deref
						||  i_instr->lr_atom == DW_OP_deref_size
						||  i_instr->lr_atom == DW_OP_xderef
						||  i_instr->lr_atom == DW_OP_xderef_size)
						{
							DO_DISCARD("reads-memory");
						}
						/* unrecognised or known-unsupported-among-known-specials?
						 * i.e. something that would have thrown Not_supported in our
						 * old DWARF interpreter in libdwarfpp's expr.cpp.
						 * But we covered the names-register/reads-register cases above. */
						if (!is_recognised_dwarf(i_instr->lr_atom)
						|| i_instr->lr_atom ==  DW_OP_bra
						|| i_instr->lr_atom ==  DW_OP_skip
#ifdef DW_OP_implicit_value
						|| i_instr->lr_atom == DW_OP_implicit_value
#endif
#ifdef DW_OP_implicit_pointer
						|| i_instr->lr_atom == DW_OP_implicit_pointer
#endif
						|| i_instr->lr_atom == DW_OP_GNU_implicit_pointer
						) DO_DISCARD("unsupported-DWARF");
						
					}
				}

				out += make_pair(interval, singleton_set);
			continue_to_next_element: ;
			}
		}
	}
}

void add_cfi_elements(frame_intervals_t& out, sticky_root_die& root,
	subprogram_vaddr_interval_map_t const& subprograms, flags_t flags)
{
	if (!(flags & INCLUDE_CFI)) return;

	auto process_frame_section = [subprograms, &out](core::FrameSection& fs) {
		for (auto i_fde = fs.fde_begin(); i_fde != fs.fde_end(); ++i_fde)
		{
			set< pair< boost::icl::discrete_interval<Dwarf_Addr>, frame_element > >
			fde_elements = frame_element::cfi_elements_for(*i_fde, fs, subprograms);
			for (auto i_el_pair = fde_elements.begin();
				i_el_pair != fde_elements.end();
				++i_el_pair)
			{
				boost::icl::discrete_interval<Dwarf_Addr> interval = i_el_pair->first;
				set<frame_element> singleton_set = { i_el_pair->second };
				out += make_pair(interval, singleton_set);
			}
			// FIXME: ideally eliminate the copying here... means eliminating the
			// set-of-pairs API for an uglier 'out' interval_map& pattern.
		} // end for each FDE
	};

	/* PROBLEM:
	 * In the case of 'strip --only-keep-debug', the .eh_frame remains
	 * in the original binary. So our root_die may be bound to the
	 * debuginfo binary, but we may need to look back at the original
	 * 'base_fd' to get the frame section
	 */
	core::FrameSection *p_fs = root.find_nonempty_frame_section();
	if (p_fs->fde_element_count > 0)
	{
		cerr << "Found frame section with " << p_fs->fde_element_count << " FDEs and "
			<< p_fs->cie_element_count << " CIEs" << endl;
		process_frame_section(*p_fs);
	}
	else
	{
		cerr << "Failed to find a non-empty frame section" << std::endl;
	}
#if 0
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
#endif
}

int main(int argc, char **argv)
{
	optional<string> input_filename;
	flags_t flags = INCLUDE_REGISTERS | INCLUDE_CFI | INCLUDE_COMPUTED;
	auto usage = [=]() {
		cerr << "Usage: " << argv[0]
		<< "[--[no-]include-registers]" << " "
		<< "[--[no-]only-pointers]" << " "
		<< "[--[no-]include-cfi]" << " "
		<< "[--[no-]include-computed]" << " "
		<< "[--[no-]include-incomplete]" << " "
		<< "[--[no-]include-static]" << " "
		<< "[--[no-]output-traditional]" << " "
		<< " input_file" << endl;
	};
	auto process_opt = [&](const string& s) {
		if (s == "--include-registers")    { flags |= INCLUDE_REGISTERS; return; }
		if (s == "--no-include-registers") { flags &= ~INCLUDE_REGISTERS; return; }
		if (s == "--only-pointers")        { flags |= ONLY_POINTERS; return; }
		if (s == "--no-only-pointers")     { flags &= ~ONLY_POINTERS; return; }
		if (s == "--include-cfi")          { flags |= INCLUDE_CFI; return; }
		if (s == "--no-include-cfi")       { flags &= ~INCLUDE_CFI; return; }
		if (s == "--include-computed")     { flags |= INCLUDE_COMPUTED; return; }
		if (s == "--no-include-computed")  { flags &= ~INCLUDE_COMPUTED; return; }
		if (s == "--include-incomplete")   { flags |= INCLUDE_INCOMPLETE; return; }
		if (s == "--no-include-incomplete"){ flags &= ~INCLUDE_INCOMPLETE; return; }
		if (s == "--include-static")       { flags |= INCLUDE_STATIC; return; }
		if (s == "--no-include-static")    { flags &= ~INCLUDE_STATIC; return; }
		if (s == "--output-traditional")   { flags |= OUTPUT_TRADITIONAL; /* implies others... */
		 flags &= ~(INCLUDE_COMPUTED|INCLUDE_CFI|INCLUDE_STATIC|INCLUDE_INCOMPLETE); return; }
		if (s == "--no-output-traditional"){ flags &= ~OUTPUT_TRADITIONAL; return; }
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
		// '-' is a valid filename, but '-'-prefixed means it's an option
		if (argv[i][0] == '-' && argv[i][1] != '\0') process_opt(argv[i]);
		else set_input_file(argv[i]);
	}
	if (!input_filename) { usage(); exit(1); }
	std::ifstream infstream(*input_filename == "-" ? "/dev/stdin" : *input_filename);
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
	 */
	frame_intervals_t elements_by_interval;
	add_local_elements(elements_by_interval, root, subprograms_by_key, flags);

	// also gather the CFI
	if (flags & INCLUDE_CFI) add_cfi_elements(elements_by_interval, root, subprograms_by_vaddr, flags);

	// do output
	if (!(flags & OUTPUT_TRADITIONAL))
	{
		write_compact_output(subprograms_by_vaddr, subprograms_by_key, elements_by_interval);
		exit(0);
	}
	else /* flags & OUTPUT_TRADITIONAL */
	{
		write_traditional_output(subprograms_by_vaddr, subprograms_by_key, elements_by_interval);
		exit(0);
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
#endif
	// success! 
	return 0;
}
