/* This is a simple dwarfpp program which generates a C file
 * recording data on a uniqued set of data types  allocated in a given executable.
 */
 
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <string>
#include <cctype>
#include <memory>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
// #include <regex> // broken in GNU libstdc++!
//#include <boost/filesystem.hpp>
#include <srk31/algorithm.hpp>
#include <srk31/ordinal.hpp>
#include <fileno.hpp>

#include "helpers.hpp"

using std::cin;
using std::cout;
using std::cerr;
using std::map;
using std::multimap;
using std::ios;
using std::ifstream;
using std::unique_ptr;
using boost::optional;
using std::ostringstream;
using namespace dwarf;
//using boost::filesystem::path;
using dwarf::core::root_die;
using dwarf::core::iterator_base;
using dwarf::core::iterator_df;
using dwarf::core::iterator_sibs;
using dwarf::core::type_die;
using dwarf::core::subprogram_die;
using dwarf::core::compile_unit_die;
using dwarf::core::pointer_type_die;
using dwarf::tool::abstract_c_compiler;

// regex usings
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::regex_constants::egrep;
using boost::match_default;
using boost::format_all;

typedef std::map< pair< string, unsigned long >, uniqued_name > allocsites_relation_t;

int main(int argc, char **argv)
{
	/* We read from stdin lines such as those output by dumpallocs,
	 * prefixed by their filename. Actually they will have been 
	 * stored in .allocsites files. */ 
	std::shared_ptr<ifstream> p_in;
	if (argc > 1) 
	{
		p_in = std::make_shared<ifstream>(argv[1]);
		if (!*p_in) 
		{
			cerr << "Could not open file " << argv[1] << endl;
			return 1;
		}
	}
	std::istream& in = p_in ? *p_in : cin;
	
	allocsites_relation_t allocsites_relation;
	
	/* We want the helper to make a root_die for us, based on the first 
	 * allocsite. How? Read them all, then merge the synthetics and 
	 * rewrite. */
	vector<allocsite> allocsites_to_add = read_allocsites(in);
	cerr << "Found " << allocsites_to_add.size() << " allocation sites" << endl;
	unique_ptr<root_die> p_root;

	if (allocsites_to_add.size() > 0)
	{
		pair< unique_ptr<root_die>, unique_ptr<ifstream> > pair = make_root_die_and_merge_synthetics(allocsites_to_add);
		unique_ptr<root_die> p_root = std::move(pair.first);
		
		multimap<string, iterator_df<type_die> > types_by_codeless_name;
		get_types_by_codeless_uniqtype_name(types_by_codeless_name,
			p_root->begin(), p_root->end());

		for (auto i_alloc = allocsites_to_add.begin(); i_alloc != allocsites_to_add.end(); ++i_alloc)
		{
			string type_symname = i_alloc->clean_typename;
			string sourcefile = i_alloc->sourcefile;
			string objname = i_alloc->objname;
			unsigned file_addr = i_alloc->file_addr;

			iterator_df<compile_unit_die> found_cu;
			optional<string> found_sourcefile_path;
			iterator_df<type_die> found_type;
			iterator_df<type_die> second_chance_type;
			/* Find a CU such that 
			 - one of its source files is named sourcefile, taken relative to comp_dir if necessary;
			 - that file defines a type of the name we want
			 */

			// look for a CU embodying this source file 
			std::vector<iterator_df<compile_unit_die> > embodying_cus;
			auto cus = p_root->begin().children();
			for (iterator_sibs<compile_unit_die> i_cu = cus.first;
				 i_cu != cus.second; ++i_cu)
			{
				if (i_cu->get_name() && i_cu->get_comp_dir())
				{
					auto cu_die_name = *i_cu->get_name();
					auto cu_comp_dir = *i_cu->get_comp_dir();

	// 				auto seq = i_cu.children_here().subseq_of<type_die>();
	// 				for (auto i = seq.first; i != seq.second; ++i)
	// 				{
	// 					auto t = i.base().base(); // FIXME
	// 					if (t.name_here())
	// 					{
	// 						if (t.is_a<core::base_type_die>())
	// 						{
	// 							const char *c_normalized_name;
	// 							// add the C-canonical name for now. (FIXME: avoid c-specificity!)
	// 							const char **c_equiv_class = abstract_c_compiler::get_equivalence_class_ptr(
	// 								t.name_here()->c_str());
	// 							if (c_equiv_class)
	// 							{
	// 								c_normalized_name = c_equiv_class[0];
	// 								named_toplevel_types.insert(
	// 									make_pair(
	// 										c_normalized_name,
	// 										t
	// 									)
	// 								);
	// 							}
	// 							// also add the language-independent canonical name
	// 							named_toplevel_types.insert(
	// 								make_pair(
	// 									name_for_base_type(t),
	// 									t
	// 								)
	// 							);
	// 						}
	// 						else
	// 						{
	// 							named_toplevel_types.insert(make_pair(*name_for_type_die(t), t));
	// 						}
	// 					}
	// 				}

					for (unsigned i_srcfile = 1; i_srcfile <= i_cu->source_file_count(); i_srcfile++)
					{
						/* Does this source file have a matching name? */
						string current_sourcepath;
						string cu_srcfile_mayberelative = i_cu->source_file_name(i_srcfile);
						//cerr << "CU " << *i_cu->get_name() << " sourcefile " << i_srcfile << " is " <<
						//	cu_srcfile_mayberelative << endl;
						//if (!path(cu_srcfile_mayberelative).has_root_directory())
						if (cu_srcfile_mayberelative.length() > 0 && cu_srcfile_mayberelative.at(0) != '/')
						{ 
							current_sourcepath = cu_comp_dir + '/' + cu_srcfile_mayberelative;
						}
						else current_sourcepath = /*path(*/cu_srcfile_mayberelative/*)*/;

						// FIXME: smarter search
						// FIXME: look around a bit, since sizeof isn't enough to keep DIE in the object file
						if (current_sourcepath == /*path(*/sourcefile/*)*/)
						{ 
							// YES this CU embodies the source file, so we can search for the type
							embodying_cus.push_back(i_cu);

							// HACK: how is void getting in here? I suppose it does come out in the allocsites
							if (type_symname.size() > 0 && type_symname != "__uniqtype__void")
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
					<< " in CUs (found " << embodying_cus.size() << ":";
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

			uniqued_name name_used = canonical_key_from_type(found_type);

			// add to the allocsites table too
			// recall: this is the mapping from allocsites to uniqtype addrs
			// the uniqtype addrs are given as idents, so we just have to use the same name
			allocsites_relation.insert(
				make_pair(
					make_pair(objname, file_addr),
					name_used
				)
			);
		} // end for allocsite
	}	
	
	cout << "struct allocsite_entry\n\
{ \n\
	void *next; \n\
	void *prev; \n\
	void *allocsite; \n\
	struct uniqtype *uniqtype; \n\
};\n";

	// extern-declare the uniqtypes
	for (auto i_site = allocsites_relation.begin(); i_site != allocsites_relation.end(); ++i_site)
	{
		cout << "extern struct uniqtype " << mangle_typename(i_site->second) << ";" << endl;
	}

	cout << "struct allocsite_entry allocsites[] = {" << endl;
	for (auto i_site = allocsites_relation.begin(); i_site != allocsites_relation.end(); ++i_site)
	{
		if (i_site != allocsites_relation.begin()) cout << ",";
		
		cout << "\n\t/* allocsite info for " << i_site->first.first << "+"
			<< std::hex << "0x" << i_site->first.second << std::dec << " */";
		cout << "\n\t{ (void*)0, (void*)0, "
			<< "(char*) " << "0" // will fix up at load time
			<< " + 0x" << std::hex << i_site->first.second << std::dec << "UL, " 
			<< "&" << mangle_typename(i_site->second)
			<< " }";
	}
	// output a null terminator entry
	if (allocsites_relation.size() > 0) cout << ",";
	cout << "\n\t{ (void*)0, (void*)0, (void*)0, (struct uniqtype *)0 }";
	
	// close the list
	cout << "\n};\n";
	
	return 0;
}	
