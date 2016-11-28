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

	map<dwarf::core::iterator_df<dwarf::core::type_die>, set< string > > aliases;
};

uniqued_name add_type(dwarf::core::iterator_df<dwarf::core::type_die> t, master_relation_t& r);
std::pair<bool, uniqued_name> add_type_if_absent(dwarf::core::iterator_df<dwarf::core::type_die> t, master_relation_t& r);
std::pair<bool, uniqued_name> add_concrete_type_if_absent(dwarf::core::iterator_df<dwarf::core::type_die> t, master_relation_t& r);
std::pair<bool, uniqued_name> transitively_add_type(dwarf::core::iterator_df<dwarf::core::type_die> t, master_relation_t& r);
void add_alias_if_absent(
	const std::string& s, 
	dwarf::core::iterator_df<dwarf::core::type_die> concrete_t, 
	master_relation_t& r
);

void make_exhaustive_master_relation(master_relation_t& r, 
	dwarf::core::iterator_df<> begin, 
	dwarf::core::iterator_df<> end);

void write_master_relation(master_relation_t& r, dwarf::core::root_die& root, 
	std::ostream& out, std::ostream& err, bool emit_void, bool emit_struct_def, 
	std::set<std::string>& names_emitted,
	std::map<std::string, std::set< dwarf::core::iterator_df<dwarf::core::type_die> > >& types_by_name,
	bool emit_codeless_aliases,
	bool emit_subobject_names = true);

void write_uniqtype_open_void(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    opt<const string&> comment_str = opt<const string&>()
	);
void write_uniqtype_open_array(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    unsigned nelems,
    opt<const string&> comment_str = opt<const string&>()
	);
void write_uniqtype_open_flex_array(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    opt<const string&> comment_str = opt<const string&>()
	);
void write_uniqtype_open_address(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    unsigned indir_level,
    bool is_generic,
    unsigned log_min_align,
    opt<const string&> comment_str = opt<const string&>()
	);
void write_uniqtype_open_base(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    unsigned enc,
    unsigned log_bit_size,
    signed bit_size_delta,
    unsigned log_bit_off,
    signed bit_off_delta,
    opt<const string&> comment_str = opt<const string&>()
	);
void write_uniqtype_open_subrange(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
	signed min,
	signed max,
    opt<const string&> comment_str = opt<const string&>()
	);
void write_uniqtype_open_enumeration(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    opt<const string&> comment_str = opt<const string&>()
	);
void write_uniqtype_open_composite(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    unsigned nmemb,
    bool not_simultaneous,
    opt<const string&> comment_str = opt<const string&>()
	);
void write_uniqtype_open_subprogram(std::ostream& o,
    const string& mangled_typename,
    const string& unmangled_typename,
    unsigned pos_maxoff,
    unsigned narg,
    unsigned nret,
    bool is_va,
    unsigned cc,
    opt<const string&> comment_str = opt<const string&>()
	);

void write_uniqtype_related_array_element_type(std::ostream& o,
    opt<const string&> maybe_mangled_typename = opt<const string&>(),
	opt<const string&> comment_str = opt<const string&>()
    );
void write_uniqtype_related_pointee_type(std::ostream& o,
    opt<const string&> maybe_mangled_typename = opt<const string&>(),
	opt<const string&> comment_str = opt<const string&>()
    );
void write_uniqtype_related_subprogram_argument_type(std::ostream& o,
    opt<const string&> maybe_mangled_typename = opt<const string&>(),
	opt<const string&> comment_str = opt<const string&>()
    );
void write_uniqtype_related_subprogram_return_type(std::ostream& o,
	bool is_first,
    opt<const string&> maybe_mangled_typename = opt<const string&>(),
	opt<const string&> comment_str = opt<const string&>()
    );
void write_uniqtype_related_contained_member_type(std::ostream& o,
    bool is_first,
	unsigned offset,
    opt<const string&> maybe_mangled_typename = opt<const string&>(),
	opt<const string&> comment_str = opt<const string&>()
    );
void write_uniqtype_related_signedness_complement_type(std::ostream& o,
    opt<const string&> maybe_mangled_typename = opt<const string&>(),
	opt<const string&> comment_str = opt<const string&>()
    );
void write_uniqtype_related_dummy(std::ostream& o,
	opt<const string&> comment_str = opt<const string&>()
    );
	
void write_uniqtype_close(std::ostream& o,
	const string& mangled_name,
	opt<unsigned> n_contained = opt<unsigned>());

#endif
