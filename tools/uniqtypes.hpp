#ifndef DUMPALLOCS_UNIQTYPES_HPP_
#define DUMPALLOCS_UNIQTYPES_HPP_

#include <sstream>
#include <fstream>
#include <memory>
#include <dwarfpp/lib.hpp>
#include <srk31/rotate.hpp>
#include <cstdint>
#include <iomanip>
#include "helpers.hpp"

// this encodes only the set of types, not the relations between them!
struct master_relation_t : public std::map< uniqued_name, dwarf::core::iterator_df<dwarf::core::type_die> >
{
	//using map::map;
	template<typename... Args>
	master_relation_t(Args&&... args): map(std::forward<Args>(args)...) {}
};

uniqued_name add_type(dwarf::core::iterator_df<dwarf::core::type_die> t, master_relation_t& r);
std::pair<bool, uniqued_name> add_type_if_absent(dwarf::core::iterator_df<dwarf::core::type_die> t, master_relation_t& r);
std::pair<bool, uniqued_name> transitively_add_type(dwarf::core::iterator_df<dwarf::core::type_die> t, master_relation_t& r);

void make_exhaustive_master_relation(master_relation_t& r, 
	dwarf::core::iterator_df<> begin, 
	dwarf::core::iterator_df<> end);

void write_master_relation(master_relation_t& r, dwarf::core::root_die& root, 
	std::ostream& out, std::ostream& err, bool emit_void, 
	std::set<std::string>& names_emitted,
	std::map<std::string, std::set< dwarf::core::iterator_df<dwarf::core::type_die> > >& types_by_name);

#endif
