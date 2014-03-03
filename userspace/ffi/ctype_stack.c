#include "cparser.h"
#include "ctype_stack.h"

/* ctype stack module used by cparser.
 * ctype stack is organized by stack frames */

#define MAX_STACK_SIZE 100
#define cts_peek(id) (&(cts->stack[id]))

static cp_ctstk *cts;


static inline int cp_ctstk_grow_frame(int size)
{
	cp_ctype_entry *new_st;

	assert(cts->size + size < MAX_STACK_SIZE);

	new_st = realloc(cts->stack, (cts->size+size)*sizeof(cp_ctype_entry));
	if (new_st)
		cts->stack = new_st;
	else
		cp_error("failed to grow stack size!");

	cts->size += size;

	return size;
}

#define DEFAULT_STACK_SIZE 20
static inline void cp_ctstk_init_frame(cp_ctstk *ncts)
{
	memset(ncts, 0, sizeof(cp_ctstk));
	ncts->size = DEFAULT_STACK_SIZE;
	ncts->top = 0;
	ncts->stack = malloc(sizeof(cp_ctype_entry)*DEFAULT_STACK_SIZE);
}

static inline void cp_ctstk_free_frame(cp_ctstk *octs)
{
	if (!octs)
		return;
	if (octs->stack)
		free(octs->stack);
	free(octs);
}

static inline void cp_ctstk_auto_grow()
{
	if (cp_ctstk_free_space() < 1)
		cp_ctstk_grow_frame(cts->size);
}

int cp_ctstk_top()
{
	return cts->top;
}

void cp_ctstk_incr_top()
{
	cp_ctstk_auto_grow();
	cts->top++;
}

cp_ctype_entry *cp_ctstk_get_top()
{
	return cts_peek(cp_ctstk_top());
}

cp_ctype_entry *cp_ctstk_get(int idx)
{
	return cts_peek(idx);
}

struct cp_ctype *cp_ctstk_get_ctype(int idx)
{
	return &(cts_peek(idx)->ct);
}

void cp_ctstk_reset(int to_top)
{
	cts->top = to_top;
}

cp_ctstk* cp_ctstk_prev_frame()
{
	return cts->prev;
}

int cp_ctstk_is_global_frame(cp_ctstk *check_cts)
{
	return check_cts->prev == NULL;
}

void cp_ctstk_new_frame()
{
	cp_ctstk *new_cst;

	new_cst = malloc(sizeof(cp_ctstk));
	if (!new_cst)
		cp_error("failed to allocate memory for ctype stack\n");
	cp_ctstk_init_frame(new_cst);
	new_cst->prev = cts;
	cts = new_cst;
}

void cp_ctstk_pop_frame()
{
	cp_ctstk *cur_st = cts;

	if (cts->prev) {
		cts = cts->prev;
		cp_ctstk_free_frame(cur_st);
	} else {
		cp_ctstk_reset(0);
	}
}

void cp_ctstk_dump_stack()
{
	int i;
	struct cp_ctype *ct;

	printf("---------------------------\n");
	printf("start of ctype stack (%d) dump: \n", cp_ctstk_top());
	for (i = 0; i < cp_ctstk_top(); i++) {
		ct = cp_ctstk_get_ctype(i);
		printf("[%d] -> cp_ctype: %d, sym_type: %d, pointer: %d "
			"symbol_id: %d, name: %s\n",
			i, ct->type,
			csym_type(ct_ffi_cs(ct)), ct->pointers, ct->ffi_cs_id,
			cts_peek(i)->name);
	}
}

int cp_ctstk_free_space()
{
	return (cts->size - cts->top - 1);
}

void cp_ctstk_init()
{
	cts = NULL;
	cp_ctstk_new_frame();
}

void cp_ctstk_free()
{
	while (!cp_ctstk_is_global_frame(cts))
		cp_ctstk_pop_frame();
	cp_ctstk_free_frame(cts);
}
