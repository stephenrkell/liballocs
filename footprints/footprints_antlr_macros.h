#ifndef __FOOTPRINTS_ANTLR_MACROS_H__
#define __FOOTPRINTS_ANTLR_MACROS_H__

/* Stolen from libantlr3cxx and very roughly converted to C */

#define GET_TEXT(node) (node)->getText((node))
#define TO_STRING(node) (node)->toString((node))
#define GET_TYPE(node) (node)->getType((node))
#define GET_PARENT(node) (node)->getParent((node))
#define GET_CHILD_COUNT(node) (node)->getChildCount((node))
#define TO_STRING_TREE(node) (node)->toStringTree((node))
static inline ANTLR3_BASE_TREE *get_child_(ANTLR3_BASE_TREE *n, int i)
{
	ANTLR3_BASE_TREE *child = (ANTLR3_BASE_TREE *)(n->getChild(n, i));
	if (child) ((ANTLR3_COMMON_TREE*)(child->super))->parent = (ANTLR3_COMMON_TREE*)(n->super);
	return child;
}
#define GET_CHILD(node, i) (get_child_((node), (i)))
#define TOKEN(tokname) tokname
#define GET_FACTORY(node) (((ANTLR3_BASE_TREE*) (node)->super)->factory)
#define ASSIGN_AS_COND(name, value)	  \
	(((name) = (value)) == (name))
#define FOR_ALL_CHILDREN(t) unsigned i = 0;	  \
	FOR_BODY(t)
#define FOR_REMAINING_CHILDREN(t) unsigned i = next_child_to_bind;	  \
	FOR_BODY(t)
#define FOR_BODY(t)	  \
	ANTLR3_BASE_TREE *__tree_head_pointer = (ANTLR3_BASE_TREE *)(t); /* because our tree may well alias 'n' */ \
	unsigned childcount; \
	const char *text __attribute__((unused)) = 0; \
	ANTLR3_BASE_TREE *n = 0; \
	for (childcount = GET_CHILD_COUNT(__tree_head_pointer), \
		     n = ((childcount > 0) ? (ANTLR3_BASE_TREE*)(GET_CHILD(__tree_head_pointer, 0)) : 0), \
		     text = (n != 0 && ((GET_TEXT(n)) != 0)) ? CCP(GET_TEXT(n)) : "(null)"; \
	     i < childcount && (n = (ANTLR3_BASE_TREE*)(GET_CHILD(__tree_head_pointer, i)), true) && \
		     (( text = ((n != 0 && ((GET_TEXT(n)) != 0)) ? CCP(GET_TEXT(n)) : "(null)") ), true); \
	     i++)
#define CHECK_TOKEN(node, token, tokenname)	  \
	assert(GET_TYPE(node) == token);
#define INIT int next_child_to_bind __attribute__(( unused )) = 0
#define BIND2(node, name) ANTLR3_BASE_TREE *(name) __attribute__((unused)) = (ANTLR3_BASE_TREE*)(GET_CHILD(node, next_child_to_bind++));
#define BIND3(node, name, token) ANTLR3_BASE_TREE *(name) __attribute__((unused)) = (ANTLR3_BASE_TREE*)(GET_CHILD(node, next_child_to_bind++)); \
	assert((name) != 0); \
	CHECK_TOKEN(name, token, #token) \

#define SELECT_NOT(token) if (GET_TYPE(n) == (token)) continue
#define SELECT_ONLY(token) if (GET_TYPE(n) != (token)) continue
#define CCP(p) ((p) ? (char*)((p->chars)) : "(no text)")

/* end plagiarism */

#endif
