#ifndef __KTAP_CP_CTSTK_H__
#define __KTAP_CP_CTSTK_H__

/* stack to help maintain state during parsing */
typedef struct cp_ctstk {
	int size;
	int top;
	cp_ctype_entry *stack;
	struct cp_ctstk *prev;
} cp_ctstk;

int cp_ctstk_top();
cp_ctype_entry *cp_ctstk_get_top();
cp_ctype_entry *cp_ctstk_get(int idx);
struct cp_ctype *cp_ctstk_get_ctype(int idx);
void cp_ctstk_incr_top();
void cp_ctstk_reset(int to_top);

cp_ctstk* cp_ctstk_prev_frame();
int cp_ctstk_is_global_frame(cp_ctstk *check_cts);
void cp_ctstk_new_frame();
void cp_ctstk_pop_frame();
void cp_ctstk_dump_stack();
int cp_ctstk_free_space();

void cp_ctstk_init();
void cp_ctstk_free();
#endif
