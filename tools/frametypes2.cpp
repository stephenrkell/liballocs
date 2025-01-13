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

void write_pairs(ostream& s,
	map< pair<string, /*iterator_df<type_die>*/ codeful_name >, 
	     vector< frame_element >
	> const& by_name_and_type)
{
	s << "name\ttype";
	for (auto i_pair = by_name_and_type.begin(); i_pair != by_name_and_type.end(); ++i_pair)
	{
		s << i_pair->first.first << "\t";
		s << mangle_typename(i_pair->first.second) << "\t";
		for (auto i_el = i_pair->second.begin(); i_el != i_pair->second.end(); ++i_el)
		{
			// hmm, what to print?
		}
		s << "\t(" << i_pair->second.size() << " intervals)";
		s << endl;
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
	optional<Dwarf_Unsigned> maybe_sz = greatest_offset_element->size_in_bytes();
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
			<< " (expr: " << i_el->effective_expr_piece.copy() << ")" << endl;
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
					else cerr << "caller_reg" << i_el->m_caller_regnum;
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
				 * to the CFA, i.e. maxoff of zero
				 * */
				Dwarf_Signed end_offset_of_highest_member = (by_off.size() == 0) ? 0
				 : ({ auto i_end = by_off.end(); --i_end; i_end->first + *i_end->second.size_in_bytes(); });
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
	 * We need to refer to that range. */
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
#if 0 /* discard logic salvaged from frametypes -- do something with this */


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
				<< std::hex << the_int << std::dec
				<< ": "
				<< i_dyn.summary() << endl;
		}
		//discarded.push_back(make_pair(*i_el, "register-located"));
		iterfirst_pair_hash< with_dynamic_location_die, string>::set/*,
			compare_first_iter_offset<string> */ just_this_variable_discard_reason_pair;
		just_this_variable_discard_reason_pair.insert(make_pair(*i_el, string("no location")));
#ifdef DEBUG
		discarded_intervals += make_pair(i_int->first, just_this_variable_discard_reason_pair);
#endif
		return ret_t();
	}
	catch (dwarf::expr::Not_supported)
	{
		cerr << "Warning: unsupported DWARF opcode when computing location for fp: "
			<< i_dyn.summary() << endl;
		//discarded.push_back(make_pair(*i_el, "register-located"));
		iterfirst_pair_hash< with_dynamic_location_die, string>::set /*,
			compare_first_iter_offset<string> */ just_this_variable_discard_reason_pair;
		just_this_variable_discard_reason_pair.insert(make_pair(i_dyn, string("unsupported-DWARF")));
#ifdef DEBUG
		discarded_intervals += make_pair(the_int, just_this_variable_discard_reason_pair);
#endif
		return ret_t();
	}
	catch (...)
	{
		cerr << "Warning: something strange happened when computing location for fp: " 
			<< i_dyn.summary() << endl;
		//discarded.push_back(make_pair(*i_el, "register-located"));
		iterfirst_pair_hash< with_dynamic_location_die, string>::set /*,
			compare_first_iter_offset<string> */ just_this_variable_discard_reason_pair;
		just_this_variable_discard_reason_pair.insert(make_pair(i_dyn, string("something-strange")));
#ifdef DEBUG
		discarded_intervals += make_pair(the_int, just_this_variable_discard_reason_pair);
#endif
		return ret_t();
	}
	assert(false);
}




		//discarded.push_back(make_pair(*i_el, "register-located"));
		iterfirst_pair_hash< with_dynamic_location_die, string>::set/*,
			compare_first_iter_offset<string> */ just_this_variable_discard_reason_pair;
		just_this_variable_discard_reason_pair.insert(make_pair(*i_el, string("no location")));
#ifdef DEBUG
		discarded_intervals += make_pair(i_int->first, just_this_variable_discard_reason_pair);
#endif



		//discarded.push_back(make_pair(*i_el, "register-located"));
		iterfirst_pair_hash< with_dynamic_location_die, string>::set /*,
			compare_first_iter_offset<string> */ just_this_variable_discard_reason_pair;
		just_this_variable_discard_reason_pair.insert(make_pair(i_dyn, string("unsupported-DWARF")));
#ifdef DEBUG
		discarded_intervals += make_pair(the_int, just_this_variable_discard_reason_pair);
#endif


		//discarded.push_back(make_pair(*i_el, "register-located"));
		iterfirst_pair_hash< with_dynamic_location_die, string>::set /*,
			compare_first_iter_offset<string> */ just_this_variable_discard_reason_pair;
		just_this_variable_discard_reason_pair.insert(make_pair(i_dyn, string("something-strange")));
#ifdef DEBUG
		discarded_intervals += make_pair(the_int, just_this_variable_discard_reason_pair);
#endif
				
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
					 		<< *i_el << endl;
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
				else 





	
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





#endif /* #if 0 */
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
						 * old DWARF interprefer in libdwarfpp's expr.cpp.
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
	/* FIXME: handle the missing forms like VALUE_IS !!!111 */

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
	if (!(flags & OUTPUT_TRADITIONAL))
	{
		cerr << "Calculating name--type pairs for all elements" << endl;
		map< pair<string, /*iterator_df<type_die>*/ codeful_name >, vector< frame_element > >
		by_name_and_type;
		unsigned anonctr = 0; // for generating names for anonymous things
		for (auto i_int = elements_by_interval.begin(); i_int != elements_by_interval.end();
			++i_int)
		{
			for (auto i_el = i_int->second.begin(); i_el != i_int->second.end(); ++i_el)
			{
				auto maybe_local = i_el->m_local;
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
					Dwarf_Unsigned caller_regnum = i_el->m_caller_regnum;
					assert(caller_regnum != 0);
					auto save_location = i_el->effective_expr_piece.copy();
					// we make up a name
					ostringstream name;
					name << "__saved_caller_reg" << caller_regnum;
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
		cerr << "Finished calculating name--type pairs" << endl;
		write_pairs(cerr, by_name_and_type);
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
