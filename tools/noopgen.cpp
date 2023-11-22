#include <cstdio>
#include <cassert>
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <cmath>

#include <boost/algorithm/string.hpp>
#include <srk31/indenting_ostream.hpp>
#include "dwarfidl/cxx_model.hpp"
#include "dwarfidl/dependency_ordering_cxx_target.hpp"
#include <dwarfidl/dwarf_interface_walk.hpp>
#include <srk31/algorithm.hpp>
#include "stickyroot.hpp"
#include "uniqtypes.hpp"

using namespace srk31;
using namespace dwarf;
using namespace dwarf::lib;
using std::vector;
using std::set;
using std::map;
using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::hex;
using std::dec;
using std::ostringstream;
using std::istringstream;
using std::stack;
using std::deque;
using boost::optional;
using namespace dwarf::lib;
using dwarf::core::iterator_base;
using dwarf::core::root_die;
using dwarf::core::abstract_die;
using dwarf::core::program_element_die;
using dwarf::core::with_static_location_die;
using dwarf::core::variable_die;
using dwarf::core::type_die;
using dwarf::core::type_set;
using dwarf::core::base_type_die;
using dwarf::core::pointer_type_die;
using dwarf::core::subprogram_die;
using dwarf::tool::gather_interface_dies;
using dwarf::core::iterator_df;
using dwarf::spec::opt;

using namespace allocs::tool;

int main(int argc, char **argv)
{
	using dwarf::tool::dependency_ordering_cxx_target;
	enum mode
	{
		NOOPGEN,
		IFUNCGEN
	} mode;
	// open the file passed in on the command-line
	assert(argc > 1);
	if (basename(argv[0]) == string("noopgen")) mode = NOOPGEN;
	else if (basename(argv[0]) == string("ifuncgen")) mode = IFUNCGEN;
	else
	{
		std::cerr << "Did not understand the name by which we were invoked: " << argv[0]
			<< std::endl;
		exit(1);
	}
	FILE* f = fopen(argv[1], "r");
	
	// construct a dwarf::file
	struct root_die_with_sticky_types : public root_die
	{
		using root_die::root_die;
		
		bool is_sticky(const abstract_die& d)
		{
			return /* d.get_spec(*this).tag_is_type(d.get_tag())
				|| */this->root_die::is_sticky(d);
		}
	} r(fileno(f));
	vector<string> compiler_argv = dwarf::tool::cxx_compiler::default_compiler_argv(true);
	compiler_argv.push_back("-fno-eliminate-unused-debug-types");
	compiler_argv.push_back("-fno-eliminate-unused-debug-symbols");
	indenting_ostream& s = srk31::indenting_cout;

	/* If the user gives us a list of function names on stdin, we use that. */
	using std::cin;
	std::istream& in = /* p_in ? *p_in :*/ cin;
	/* populate the subprogram and types lists. */
	char buf[4096];
	set<string> element_names;
	map<string, iterator_base> named_element_dies;
	map<string, string> visibility_by_symbol_name; // only for IFUNCGEN

	auto read_sym_line = [&](const string& str,
		string& file,
		unsigned long& addr,
		string& symtype,
		string& symbind,
		string& symvis,
		string& symname
	) -> bool
	{
		istringstream s(str);

		string addrstr;

		#define report_error(fieldname, buf) \
		do { cerr << "Error reading field '" #fieldname "' from line: " << (buf) << endl; \
			 return false; \
		   } while (0)
		#define check_error(stream, fieldname, buf) \
		do { \
			if ((stream).bad()) report_error(fieldname, (buf)); \
		   } while (0)
		   
		#define read_fieldstr(name) \
		std::getline(s, name, '\t'); check_error(s, name, str);
		
		read_fieldstr(file)
		read_fieldstr(addrstr)
		read_fieldstr(symtype)
		read_fieldstr(symbind)
		read_fieldstr(symvis)
		read_fieldstr(symname)
		
		// we don't accept "0x"-prefixing; if we required it we might do something like this
		//if (addrstr.substr(0, 2) != "0x") 
		//{
		//	cerr << "str is " << str << "\nfile_addrstr is " << file_addrstr << endl;
		//	report_error(file_addr, file_addrstr);
		//}
		istringstream addrstream(addrstr); addrstream >> std::hex >> addr; check_error(addrstream, addr, addrstr);
		return true;
	};

	bool success = true;
	while (in.getline(buf, sizeof buf - 1))
	{
		//element_names.insert(buf);
		string file;
		unsigned long addr;
		string symtype;
		string symbind;
		string symvis;
		string symname;
		success &= read_sym_line(buf,
			file, addr, symtype, symbind, symvis, symname
		);
		if (!success) exit(1);
		element_names.insert(symname);
		visibility_by_symbol_name[symname] = symvis;
	}
	cerr << "Received " << element_names.size() << " element names" << endl;
	/* FIXME: we really need to receive <name, address> pairs,
	 * in order to handle aliases correctly. */

	set<pair<dependency_ordering_cxx_target::emit_kind, iterator_base>,
		dependency_ordering_cxx_target::compare_with_type_equality > to_output;
	auto seq = r.visible_named_grandchildren();
	for (auto i_el = seq.first; i_el != seq.second; ++i_el)
	{
		auto i_pe = i_el.as_a<program_element_die>();
		// is it a visible subprogram or variable?
		/* This is the basic test for whether an interface element is of 
		 * interest. For us, it's just whether it's a visible subprogram or variable
		 * in our list. Or, if our list is empty, it's any subprogram. Variables too!*/
		if (i_pe && i_pe.name_here()
			&& ((i_pe.is_a<variable_die>() && i_pe.as_a<variable_die>()->has_static_storage())
				|| (i_pe.is_a<subprogram_die>()
					/* extern declarations of subprogram DIEs do not always have arg/ret type
					 * info, at least coming out of GCC. */
					&& !(i_pe.as_a<subprogram_die>()->get_declaration() &&
							*i_pe.as_a<subprogram_die>()->get_declaration()
						  && i_pe.as_a<subprogram_die>()->get_external() &&
							*i_pe.as_a<subprogram_die>()->get_declaration()
						)
					)
				)
			&& (!i_pe->get_visibility() || *i_pe->get_visibility() == DW_VIS_exported)
			&& element_names.find(*i_pe.name_here()) != element_names.end()
		)
		{
			named_element_dies.insert(make_pair(*i_el.name_here(), i_el));
		}
	}
	// now we have uniqued by name, we can build to_output
	for (auto i_pair = named_element_dies.begin(); i_pair != named_element_dies.end(); ++i_pair)
	{
		auto retpair = to_output.insert(
			make_pair(dwarf::tool::dependency_ordering_cxx_target::EMIT_DEF, i_pair->second)
		);
	}

	// static const members are too much faff
#define preload_prefix "__yesop_"
#define nopreload_prefix "__noop_"
	/* TODO: instead of "__yesop_" polluting our symtabs, ideally we would like
	 * the .dynsym to include only the ifuncs and noops, and the .symtab to
	 * include only the yesops (or those plus noops) but with their unprefixed name.
	 * Can we achieve this? Using --dynamic-list we can remove yesops from dynsym.
	 * After that we can probably use objcopy to undo the '__yesop_' prefix in the
	 * .symtab, just as we added the prefix earlier in the build. */
	struct our_target : dependency_ordering_cxx_target
	{
	private:
		enum mode mode;
		map<string, string> const& visibility_by_symbol_name;
	public:
		virtual string get_reserved_prefix() const { return "_noopgen_"; }

#if 0
		string
		decl_of_die(
			iterator_df<program_element_die> d,
			bool emit_fp_names,
			bool write_semicolon /* = false */,
			opt<string> override_name /* = opt<string>() */
		)
		{
			string returned = this->dependency_ordering_cxx_target(d, emit_fp_names,
				write_semicolon, override_name);
			if (d.is_a<type_die>() && d.name_here())
			{
				type_definitions_generated_by_name[*d.name_here()] = make_pair(
					d.as_a<type_die>()->summary_code(), returned);
			}
			return returned;
		}
#endif

		/* Definitions we emit should be prefixed with a visibility attribute.
		 * For noops it's always 'hidden'.
		 * For ifuncs it matches the yesop's (real function's) so might be protected or
		 * default (public). Might it also be 'hidden'? NO.
		 * Also, if we're IFUNCGEN, defns we emit are different. They don't have the signature
		 * of the original DWARF-described function. They're just functions from
		 * void to a func_ptr_t.
		 */
		virtual cxx_generator_from_dwarf::strmanip_t defn_of_die(
			iterator_df<core::program_element_die> d,
			opt<string> override_name /* = opt<string>() */,
			bool emit_fp_names /* = true */,
			bool write_semicolon /* = true */
		) {
			opt<string> maybe_symname = d.is_a<with_static_location_die>() ?
			 d.as_a<with_static_location_die>()->get_linkage_name() : opt<string>();
			// wrap the manipulator with one which first outputs the visibility, if it's a sym
			return [=](indenting_ostream& o) -> indenting_ostream& {
				if (maybe_symname) o << "extern \"C\" {" << endl; // HACK
				string visibility_attr = "";
				if (maybe_symname)
				{
					visibility_attr = string("__attribute__((visibility(\"")
					  + ((mode == NOOPGEN)
					      ? "hidden" 
					      : boost::algorithm::to_lower_copy(visibility_by_symbol_name[*maybe_symname])
					   )
					  + "\")))\n";
				}
				if (mode == IFUNCGEN && d.is_a<subprogram_die>())
				{
					// we need to declare the __yesop_ and __noop_ functions
					o << decl_of_die(d, true, true, string(nopreload_prefix) + *d.name_here());
					o << decl_of_die(d, true, true, string(preload_prefix) + *d.name_here());
					auto with_loc = d.as_a<with_static_location_die>();
					auto maybe_symname = with_loc->get_linkage_name();
					// if the name matches one of our symbols...
					if (maybe_symname
						&& visibility_by_symbol_name.find(*maybe_symname) != visibility_by_symbol_name.end())
					{
						o << visibility_attr
						  << "func_ptr_t " << *maybe_symname << "(void)" << endl << "{";
						o.inc_level();
						o << endl;
						o << body_of_subprogram_die(d.as_a<subprogram_die>());
						o.dec_level();
						o << endl << "}" << endl;
						o << "__asm__(\".type "
						  << *maybe_symname << ",%gnu_indirect_function\");" << endl;
						goto out;
					}
				}
				o << visibility_attr;
				o << this->dependency_ordering_cxx_target::defn_of_die(
				         d, override_name, emit_fp_names, write_semicolon);
			out:
				if (maybe_symname) o << "} /* end extern \"C\" */" << endl; // HACK
				return o;
			};
		}
		
		virtual strmanip_t body_of_subprogram_die(
			iterator_df<core::subprogram_die> d
		) {
			opt<string> maybe_symname = d.is_a<with_static_location_die>() ?
			 d.as_a<with_static_location_die>()->get_linkage_name() : opt<string>();
			if (mode == NOOPGEN)
			{
				return this->dependency_ordering_cxx_target::body_of_subprogram_die(d);
			}
			assert(maybe_symname);
			return [=](indenting_ostream& o) -> indenting_ostream& {
				o << "if (check_head_preload_position()) return (func_ptr_t) "
					<< preload_prefix << *maybe_symname << ";" << endl;
				o << "return (func_ptr_t) " << nopreload_prefix << *maybe_symname << ";";
				return o;
			};
		}
		// lots of tedious forwarding... if only local structs worked like lambdas
		our_target(enum mode mode,
		 map<string, string> const& visibility_by_symbol_name,
		 indenting_ostream& s,
		 set<pair<dependency_ordering_cxx_target::emit_kind, iterator_base>,
		     dependency_ordering_cxx_target::compare_with_type_equality > const& to_output,
		 vector<string> const& compiler_argv)
		 : dependency_ordering_cxx_target(" uintptr_t", s, to_output, compiler_argv),
		   mode(mode), visibility_by_symbol_name(visibility_by_symbol_name) {}
	} target(mode, visibility_by_symbol_name, s, to_output, compiler_argv);
/* We actually need to generate something that looks like the following.
 * - First, generate all the noops in a noop.c file. They should have hidden visibility.
 * - Second, rename and hidden-ify all the reals ('ops'). The names should be prefixed.
 *   Use objcopy opts so that already-private functions and data symbols aren't touched.
 *      Q. What about dynsym? A. We do renaming on a .a file, so before .dynsym is gen'd.
 * - Third, generate all the ifuncs, whose visibility should match the original real.
 * - Fourth, link liballocs.so by combining noop.o, ifuncs.o and the name-prefixed archive.
 * - TODO: also write a test that checks that our .pubsyms file obeys the properties we want:
 *   any public symbols use a reserved region of the symbol namespace.
 */

	/* where do we actually generate the output strings? during transitively_close */
	target.transitively_close();
	if (getenv("DEBUG_CC"))
	{
		cerr << "Generated " << target.output_fragments().size() << " output fragments." << endl;
		for (auto i_frag = target.output_fragments().begin();
			i_frag != target.output_fragments().end(); ++i_frag)
		{
			cerr << i_frag->first.first << " of " << i_frag->first.second << endl;
		}
		cerr << "=========================================" << endl;
	}

	if (mode == IFUNCGEN) cout << "#include <cstdint>" << endl
		<< "typedef uintptr_t (*func_ptr_t)(...);" << endl;
	target.write_ordered_output();

	return 0;
}
