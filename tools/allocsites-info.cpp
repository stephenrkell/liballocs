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
using dwarf::core::iterator_bf;
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
iterator_df<type_die>
get_or_create_array_of_uninterpreted_byte_type(root_die& r)
{
	auto cu = r.get_or_create_synthetic_cu();
	auto found = cu->named_child("__ARR___uninterpreted_byte");
	if (found) return found.as_a<type_die>();
	
	auto created = r.make_new(cu, DW_TAG_array_type);
	auto& attrs = dynamic_cast<core::in_memory_abstract_die&>(created.dereference())
		.attrs();
	encap::attribute_value v_name(string("__ARR___uninterpreted_byte")); // must have a name
	attrs.insert(make_pair(DW_AT_name, v_name));
	iterator_df<type_die> element_type = get_or_create_uninterpreted_byte_type(r);
	attrs.insert(make_pair(DW_AT_type, encap::attribute_value(
		encap::attribute_value::weak_ref(r, element_type.offset_here(), true,
					created.offset_here(), DW_AT_type))));
	// auto copy = created; // FIXME: add const& overload of print_tree()
	// r.print_tree(std::move(created), std::cerr);
	return created;
}
iterator_df<type_die>
create_arr0_type_for_element_type(root_die& r, iterator_df<type_die> element_t)
{
	auto cu = r.get_or_create_synthetic_cu();
	auto created = r.make_new(cu, DW_TAG_array_type);
	auto& attrs = dynamic_cast<core::in_memory_abstract_die&>(created.dereference())
		.attrs();
	attrs.insert(make_pair(DW_AT_type, encap::attribute_value(
		encap::attribute_value::weak_ref(r, element_t.offset_here(), true,
					created.offset_here(), DW_AT_type))));
	return created;
}
iterator_df<type_die> allocsite::find_named_type(root_die& r, const multimap<string, iterator_df<type_die> >& types_by_codeless_name)
{
	if (this->found_type) return this->found_type;
	iterator_df<compile_unit_die> found_cu;
	opt<string> found_sourcefile_path;
	iterator_df<type_die> found_type;
	iterator_df<type_die> second_chance_type;
	/* Find a CU such that
	 * - one of its source files is named sourcefile, taken relative to comp_dir if necessary;
	 * - that file defines a type of the name we want
	 * This search is necessary because
	 * - different types of the same name might appear (in different CUs), and
	 * - compilers are not always great about emitting DIEs if a type is used only
	 *   lightly (e.g. we do only 'sizeof T'), so we do "second chance" name-matching
	 */
	std::vector<iterator_df<compile_unit_die> > embodying_cus;
	auto cus = r.begin().children();
	for (iterator_sibs<compile_unit_die> i_cu = cus.first; i_cu != cus.second; ++i_cu)
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
				if (current_sourcepath == /*path(*/this->sourcefile/*)*/)
				{
					// YES this CU embodies the source file, so we can search for the type
					embodying_cus.push_back(i_cu);

					// void comes out in the allocsites
					if (this->clean_typename.size() > 0 &&
						(this->clean_typename == "__uniqtype____uninterpreted_byte"
						|| this->clean_typename == "__uniqtype__void"))
					{
						found_type = get_or_create_uninterpreted_byte_type(r); // i.e. void
						goto cu_loop_exit;
					}
					else if (this->clean_typename.size() > 0 &&
						(this->clean_typename == "__uniqtype____EXISTS1___PTR__1"))
					{
						found_type = get_or_create_generic_pointer_type(r);
						goto cu_loop_exit;
					}
					else if (clean_typename.size() > 0)
					{
						auto found_types = types_by_codeless_name.equal_range(this->clean_typename);
						if (found_types.first == found_types.second)
						{
							cerr << "Found no types for symbol name "
								<< this->clean_typename << "; unique symbol names were: " << endl;
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
		cerr << "Warning: no type named " << clean_typename
			<< " in CUs embodying source file " << sourcefile
			<< " (found " << embodying_cus.size() << ":";
			for (auto i_cu = embodying_cus.begin(); i_cu != embodying_cus.end(); ++i_cu)
			{
				if (i_cu != embodying_cus.begin()) cerr << ", ";
				cerr << *(*i_cu)->get_name();
			}
			cerr << ") but required by allocsite: " << objname
			<< "<" << clean_typename << "> @" << std::hex << file_addr << std::dec << ">" << endl;

		if (second_chance_type)
		{
			cerr << "Warning: guessing that we can get away with "
				<< second_chance_type << endl;
			found_type = second_chance_type;
		} // else return
	}
	if (!found_type) return iterator_base::END;
	/* NOTE: we can still get incomplete types used as sizeof, if the
	 * user did "offsetof" on a field in them. That is how we will get
	 * them here. FIXME: if the user uses offsetof even on a *complete*
	 * type, we should skip the ARR0 here. E.g. if we have the variable-
	 * -length array be [1] not [0], we would ues offsetof to allocate
	 * space for extra training elements. We already have "might be
	 * array", output by dumpallocs.ml, which required that the type is
	 * complete. So assert that if it might be an array, it's complete. */
	bool is_incomplete = !found_type->calculate_byte_size();
	if (this->might_be_array && is_incomplete)
	{
		std::cerr << "WARNING: dumpallocs thought an allocation of " << clean_typename
			<< " might be an array, but it's incomplete" << std::endl;
		this->might_be_array = false;
	}
	this->found_type = found_type;
	return found_type;
}

vector<iterator_df<type_die> >
ensure_needed_types_and_assign_to_allocsites(root_die& r, vector<allocsite>& as)
{
	// for fast lookup, index by codeless name
	multimap<string, iterator_df<type_die> > types_by_codeless_name;
	get_types_by_codeless_uniqtype_name(types_by_codeless_name,
		r.begin(), r.end());
	vector<iterator_df<type_die> > types_we_created;
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
			/* create_dies() may create multiple types, not just the one we asked for.
			 * HACK: rather than modify dwarfidl to tell us what we need, use a
			 * snapshot/difference algorithm for now. The number of synthetics is
			 * always small, so this isn't costing us a lot. */
			auto snapshot_types = [&last_cu]() {
				set<iterator_df<type_die>> types_existing;
				iterator_bf<> i = last_cu;
				iterator_bf<> i_end = last_cu; i_end.increment_skipping_subtree();
				for (; i != i_end; ++i)
				{
					if (i.is_a<type_die>()) types_existing.insert(i);
				}
				return types_existing;
			};
			auto before_snapshot = snapshot_types();
			// if we got here, "clean_typename" is actually a dwarfidl expression
			auto created = dwarfidl::create_dies(last_cu, i_a->clean_typename);
			assert(created);
			assert(created.is_a<type_die>());
			auto after_snapshot = snapshot_types();
			// difference the snapshots
			set<iterator_df<type_die> > all_created;
			std::set_difference(after_snapshot.begin(), after_snapshot.end(),
				before_snapshot.begin(), before_snapshot.end(),
				std::inserter(all_created, all_created.end()));
			assert(all_created.size() > 0);
			// update the allocsite record with the type we just created
			i_a->found_type = created.as_a<type_die>();
			// rewrite clean typename to the codeless symname, i.e. what dumpallocs would generate
			i_a->clean_typename = mangle_typename(make_pair("", canonical_key_for_type(created).second));
			auto add_type = [&types_we_created, &types_by_codeless_name](iterator_df<type_die> t) {
				auto name_pair = canonical_key_for_type(t);
				types_we_created.push_back(t);
				auto codeless_name = mangle_typename(make_pair("", name_pair.second));
				types_by_codeless_name.insert(make_pair(
					codeless_name, t));
			};
			for (auto i_t = all_created.begin(); i_t != all_created.end(); ++i_t)
			{
				add_type(*i_t);
			}
		}
		else
		{
			auto found_named_type = i_a->find_named_type(r, types_by_codeless_name);
			if (DECLARE_AS_ARRAY0(*i_a))
			{
				auto codeless_arr0_name = mangle_typename(make_pair("",
					string("__ARR_") + canonical_name_for_type(found_named_type)));
				auto found_arr0 = types_by_codeless_name.find(codeless_arr0_name);
				if (found_arr0 != types_by_codeless_name.end())
				{
					i_a->found_type = found_arr0->second;
				}
				else // create it
				{
					auto created = create_arr0_type_for_element_type(r, found_named_type);
					i_a->found_type = created.as_a<type_die>();
					assert(0 == strncmp(canonical_name_for_type(i_a->found_type).c_str(),
						"__ARR_", 6));
					types_we_created.push_back(i_a->found_type);
				}
			}
			else i_a->found_type = found_named_type;
		}
	}
	return types_we_created;
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
