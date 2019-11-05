#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <boost/algorithm/string.hpp>
#include <boost/optional.hpp>
#include <boost/regex.hpp>
// #include <regex> // broken in GNU libstdc++!
//#include <boost/filesystem.hpp>
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <fileno.hpp>
#include <dwarfidl/create.hpp>

#include "allocsites-info.hpp"

using std::cin;
using std::cout;
using std::cerr;
using std::map;
using std::multimap;
using std::ios;
using std::ifstream;
using std::unique_ptr;
using std::ostringstream;
using std::istringstream;

using boost::optional;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

using namespace dwarf;
using dwarf::lib::Dwarf_Unsigned;
using dwarf::core::compile_unit_die;
using dwarf::core::iterator_df;
using dwarf::core::iterator_sibs;
using dwarf::core::type_die;
using dwarf::core::root_die;
using dwarf::core::iterator_base;

namespace allocs
{
namespace tool
{
/* FIXME: need a generic approach to adding these abstract types.
 * Probably we don't want to create them in the DWARF at all, just
 * to be able to assume that they exist. Look at what the clients
 * of these functions actually need them for.
 *
 * If we do need to create them in the DWARF, then we should generate
 * -roottypes.c directly from that DWARF, so that any summary codes
 * etc that apply to these types are actually appearing in symnames
 * that really exist. */
iterator_df<type_die>
get_or_create_uninterpreted_byte_type(root_die& r)
{
	auto cu = r.get_or_create_synthetic_cu();
	auto found = cu->named_child("__uninterpreted_byte");
	if (found) return found.as_a<type_die>();
	
	auto created = r.make_new(cu, DW_TAG_base_type);
	auto& attrs = dynamic_cast<core::in_memory_abstract_die&>(created.dereference())
		.attrs();
	encap::attribute_value v_name(string("__uninterpreted_byte")); // must have a name
	attrs.insert(make_pair(DW_AT_name, v_name));
	encap::attribute_value v_encoding((Dwarf_Unsigned)0);
	attrs.insert(make_pair(DW_AT_encoding, v_encoding));
	encap::attribute_value v_byte_size((Dwarf_Unsigned)1);
	attrs.insert(make_pair(DW_AT_byte_size, v_byte_size));
	return created;
}
iterator_df<type_die>
get_or_create_generic_pointer_type(root_die& r)
{
	auto cu = r.get_or_create_synthetic_cu();
	auto found = cu->named_child("__EXISTS1___PTR__1");
	if (found) return found.as_a<type_die>();
	
	auto created = r.make_new(cu, DW_TAG_pointer_type);
	auto& attrs = dynamic_cast<core::in_memory_abstract_die&>(created.dereference())
		.attrs();
	encap::attribute_value v_name(string("__EXISTS1___PTR__1")); // must have a name
	attrs.insert(make_pair(DW_AT_name, v_name));
	return created;
}

void merge_and_rewrite_synthetic_data_types(root_die& r, vector<allocsite>& as)
{
	for (auto i_a = as.begin(); i_a != as.end(); ++i_a)
	{
		if (i_a->is_synthetic)
		{
			cerr << "Found synthetic typename " << i_a->clean_typename;

			/* Add under the last CU in the file, to avoid (for now) offset woes. */
			auto cus_seq = r.begin().children().subseq_of<compile_unit_die>();

			auto last_cu = cus_seq.first;

			for (auto i_cu = cus_seq.first; 
				i_cu != cus_seq.second; 
				++i_cu, (i_cu != cus_seq.second && ((last_cu = i_cu), true)));

			auto created = dwarfidl::create_dies(last_cu, i_a->clean_typename);
			assert(created);
			assert(created.is_a<type_die>());
			/* We use the codeless name here, which is what dumpallocs would emit. */
			i_a->clean_typename = mangle_typename(make_pair("", 
				canonical_key_for_type(created.as_a<type_die>()).second));
		}
	}
}

std::pair<std::unique_ptr<root_die>, std::unique_ptr<std::ifstream> >
make_root_die_and_merge_synthetics(vector<allocsite>& as)
{
	/* what's the objname of the first entry? */
	string seen_objname = as.begin()->objname;
	auto p_objfile = std::unique_ptr<std::ifstream>(new std::ifstream(seen_objname));
	if (!*p_objfile)
	{
		assert(false);
	}
	/* what's the objname of the first entry? */
	auto p_root = std::unique_ptr<root_die>(new root_die(fileno(*p_objfile)));
	assert(p_root);
	/* rewrite the allocsites we were passed */
	merge_and_rewrite_synthetic_data_types(*p_root, as);
	return std::move(make_pair(std::move(p_root), std::move(p_objfile)));
}

vector<allocsite>
read_allocsites(std::istream& in)
{
	char buf[4096];
	string objname;
	string symname;
	unsigned file_addr;
	string sourcefile; 
	unsigned line;
	unsigned end_line;
	string alloc_typename;
	bool might_be_array;
	
	vector<allocsite> allocsites_to_add;
	
	opt<string> seen_objname;
	
	while (in.getline(buf, sizeof buf - 1)
		&& 0 == read_allocs_line(string(buf), objname, symname, file_addr, sourcefile, line, end_line, alloc_typename, might_be_array))
	{
		string nonconst_typename = alloc_typename;
		string clean_typename = nonconst_typename;
		boost::trim(clean_typename);
		
		allocsites_to_add.push_back((allocsite){
			clean_typename, sourcefile, objname, file_addr,
			/* is_synthetic */ clean_typename.substr(0, sizeof "__uniqtype_" - 1) != "__uniqtype_",
			might_be_array
		});
	} // end while read line
	cerr << "Found " << allocsites_to_add.size() << " allocation sites" << endl;
	return allocsites_to_add;
}
void make_allocsites_relation(
	allocsites_relation_t& allocsites_relation,
	vector<allocsite> const& allocsites_to_add,
	multimap<string, iterator_df<type_die> >& types_by_codeless_name,
	root_die& r
)
{
	auto uninterpreted_byte_t = get_or_create_uninterpreted_byte_type(r);
	auto generic_pointer_t = get_or_create_generic_pointer_type(r);
	for (auto i_alloc = allocsites_to_add.begin(); i_alloc != allocsites_to_add.end(); ++i_alloc)
	{
		string type_symname = i_alloc->clean_typename;
		string sourcefile = i_alloc->sourcefile;
		string objname = i_alloc->objname;
		unsigned file_addr = i_alloc->file_addr;

		iterator_df<compile_unit_die> found_cu;
		opt<string> found_sourcefile_path;
		iterator_df<type_die> found_type;
		iterator_df<type_die> second_chance_type;
		/* Find a CU such that 
		 - one of its source files is named sourcefile, taken relative to comp_dir if necessary;
		 - that file defines a type of the name we want
		 */

		// look for a CU embodying this source file 
		std::vector<iterator_df<compile_unit_die> > embodying_cus;
		auto cus = r.begin().children();
		for (iterator_sibs<compile_unit_die> i_cu = cus.first;
			 i_cu != cus.second; ++i_cu)
		{
			if (i_cu->get_name() && i_cu->get_comp_dir())
			{
				auto cu_die_name = *i_cu->get_name();
				auto cu_comp_dir = *i_cu->get_comp_dir();

				for (unsigned i_srcfile = 1; i_srcfile <= i_cu->source_file_count(); i_srcfile++)
				{
					/* Does this source file have a matching name? */
					string current_sourcepath;
					string cu_srcfile_mayberelative = i_cu->source_file_name(i_srcfile);
					//if (!path(cu_srcfile_mayberelative).has_root_directory())
					if (cu_srcfile_mayberelative.length() > 0 && cu_srcfile_mayberelative.at(0) != '/')
					{ 
						current_sourcepath = cu_comp_dir + '/' + cu_srcfile_mayberelative;
					}
					else current_sourcepath = /*path(*/cu_srcfile_mayberelative/*)*/;

					//cerr << "CU " << *i_cu->get_name() << " sourcefile " << i_srcfile << " is " <<
					//	cu_srcfile_mayberelative 
					//	<< ", sourcepath "
					//	<< current_sourcepath
					//	<< endl;

					// FIXME: smarter search
					// FIXME: look around a bit, since sizeof isn't enough to keep DIE in the object file
					if (current_sourcepath == /*path(*/sourcefile/*)*/)
					{ 
						// YES this CU embodies the source file, so we can search for the type
						embodying_cus.push_back(i_cu);

						// void comes out in the allocsites
						if (type_symname.size() > 0 &&
							(type_symname == "__uniqtype____uninterpreted_byte"
							|| type_symname == "__uniqtype__void"))
						{
							found_type = uninterpreted_byte_t; // i.e. void
							goto cu_loop_exit;
						}
						else if (type_symname.size() > 0 &&
							(type_symname == "__uniqtype____EXISTS1___PTR__1"))
						{
							found_type = generic_pointer_t;
							goto cu_loop_exit;
						}
						else if (type_symname.size() > 0)
						{
							//auto found_type_entry = named_toplevel_types.find(clean_typename);
							auto found_types = types_by_codeless_name.equal_range(type_symname);


// 							if (found_type_entry != named_toplevel_types.end() /* && (
// 										found_type->get_tag() == DW_TAG_base_type ||
// 										(found_type->get_decl_file()
// 											&& *found_type->get_decl_file() == i_srcfile))*/)
// 							{
// 								found_type = found_type_entry->second;
// 								found_cu = i_cu;
// 								found_sourcefile_path = current_sourcepath;
// 								goto cu_loop_exit;
// 							}

							if (found_types.first == found_types.second)
							{
								cerr << "Found no types for symbol name "
									<< type_symname << "; unique symbol names were: " << endl;
								set<string> uniques;
								for (auto i_el = types_by_codeless_name.begin();
									i_el != types_by_codeless_name.end(); ++i_el)
								{
									uniques.insert(i_el->first);
								}
								for (auto i_el = uniques.begin();
									i_el != uniques.end(); ++i_el)
								{
									if (i_el != uniques.begin()) cerr << ", ";
									cerr << *i_el;
								}
							} 
							else 
							{
								/* Make sure we get the version that is defined in this CU. */
								for (auto i_found = found_types.first; i_found != found_types.second; ++i_found)
								{
									if (i_found->second.enclosing_cu()
										== i_cu)
									{
										found_type = i_found->second;
										// we can exit the loop now

										cerr << "Success: found a type named " << i_found->first
											<< " in a CU named "
											<< *i_found->second.enclosing_cu().name_here()
											<< " == "
											<< *i_cu.name_here()
											<< endl;
										goto cu_loop_exit;
									}
									else 
									{
										assert(i_found->second.enclosing_cu().offset_here()
											!= i_cu.offset_here());

										cerr << "Found a type named " << i_found->first
											<< " but it was defined in a CU named "
											<< *i_found->second.enclosing_cu().name_here()
											<< " whereas we want one named "
											<< *i_cu.name_here()
											<< endl;
										second_chance_type = i_found->second;
									}

								}
							}

							// if we got here, we failed...
							/* If we fail, we will go round again, since 
							 * we might find another CU that 
							 * - embodies this source file, and
							 * - contains more DWARF types. */

							found_type = iterator_base::END;
						}
					}
				}
			}
		} // end for each CU
	cu_loop_exit:
		if (!found_type)
		{
			cerr << "Warning: no type named " << type_symname 
				<< " in CUs embodying source file " << sourcefile
				<< " (found " << embodying_cus.size() << ":";
				for (auto i_cu = embodying_cus.begin(); i_cu != embodying_cus.end(); ++i_cu)
				{
					if (i_cu != embodying_cus.begin()) cerr << ", ";
					cerr << *(*i_cu)->get_name();
				}
				cerr << ") but required by allocsite: " << objname 
				<< "<" << type_symname << "> @" << std::hex << file_addr << std::dec << ">" << endl;

			if (second_chance_type)
			{
				cerr << "Warning: guessing that we can get away with " 
					<< second_chance_type << endl;
				found_type = second_chance_type;
			} else continue;
		}
		// now we found the type
		//cerr << "SUCCESS: found type: " << *found_type << endl;

		uniqued_name name_used = canonical_key_for_type(found_type);
		/* NOTE: we can still get incomplete types used as sizeof, if the 
		 * user did "offsetof" on a field in them. That is how we will get
		 * them here. FIXME: if the user uses offsetof even on a *complete*
		 * type, we should skip the ARR0 here. E.g. if we have the variable-
		 * -length array be [1] not [0], we would ues offsetof to allocate
		 * space for extra training elements. */
		bool incomplete = !found_type->calculate_byte_size();
		bool declare_as_array0 = !i_alloc->is_synthetic && i_alloc->might_be_array && !incomplete;

		// add to the allocsites table too
		// recall: this is the mapping from allocsites to uniqtype addrs
		// the uniqtype addrs are given as idents, so we just have to use the same name
		allocsites_relation.insert(
			make_pair(
				make_pair(objname, file_addr),
				make_pair(name_used, declare_as_array0)
			)
		);
	} // end for allocsite
}	

optional<vector<allocsite> > read_allocsites_for_binary(const string& s)
{
	/* Is there an allocsites file for the input object? */
	char *real_path = realpath(s.c_str(), NULL);
	assert(real_path);
	
	string full_path = string(getenv("META_BASE")?:"/usr/lib/meta") + "/" + real_path + ".allocs";
	std::ifstream in(full_path);
	if (in)
	{
		return read_allocsites(in);
	}
	else return opt<vector<allocsite> >();
}

int read_allocs_line(
	const string& str,
	string& objname,
	string& symname,
	unsigned& file_addr,
	string& cuname,
	unsigned& line,
	unsigned& end_line,
	string& alloc_typename,
	bool& might_be_array
)
{
	istringstream s(str);

	string file_addrstr;
	string linestr;
	string endlinestr;
	string might_be_array_str;

	#define report_error(fieldname, buf) \
	do { cerr << "Error reading field '" #fieldname "' from line: " << (buf) << endl; \
		 return 1; \
	   } while (0)
	#define check_error(stream, fieldname, buf) \
	do { \
		if ((stream).bad()) report_error(fieldname, (buf)); \
	   } while (0)		
	string alloc_targetfun;
	std::getline(s, objname, '\t'); check_error(s, objname, str);
	std::getline(s, symname, '\t'); check_error(s, symname, str);
	std::getline(s, file_addrstr, '\t'); check_error(s, offset, str);
	std::getline(s, cuname, '\t'); check_error(s, cuname, str);
	std::getline(s, linestr, '\t'); check_error(s, line, str);
	std::getline(s, endlinestr, '\t'); check_error(s, endline, str);
	std::getline(s, alloc_targetfun, '\t'); check_error(s, alloc_targetfun, str);
	std::getline(s, alloc_typename, '\t'); check_error(s, alloc_typename, str);
	std::getline(s, might_be_array_str, '\t'); check_error(s, might_be_array, str);
	// don't bother reading rest -- the line below doesn't work
	//std::getline(s, rest, '\n'); check_error(s, rest);

	if (file_addrstr.substr(0, 2) != "0x") 
	{
		cerr << "str is " << str << "\nfile_addrstr is " << file_addrstr << endl;
		report_error(file_addr, file_addrstr);
	}
	istringstream offsetstream(file_addrstr.substr(2)); offsetstream >> std::hex >> file_addr; check_error(offsetstream, file_addr, file_addrstr);
	istringstream linestream(linestr); linestream >> line; check_error(linestream, line, linestr);
	istringstream endlinestream(endlinestr); endlinestream >> end_line; check_error(endlinestream, end_line, endlinestr);
	istringstream might_be_array_stream(might_be_array_str); might_be_array_stream >> might_be_array; check_error(might_be_array_stream, might_be_aray, might_be_array_str);
	return 0;
}

} // end namespace tool
} // end namespace allocs
