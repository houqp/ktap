#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ktap_types.h"
#include "ktap_opcodes.h"
#include "../../userspace/ktapc.h"
#include "cparser.h"
#include "ctype_stack.h"

void ffi_cparser_init(void);
void ffi_cparser_free(void);
int ffi_parse_cdef(const char *s);

static cp_csymbol_state *csym_state;

#define cs_nr (csym_state->cs_nr)
#define cs_arr_size (csym_state->cs_arr_size)
#define cs_arr (csym_state->cs_arr)


#define DO_TEST(name) do {					\
	ffi_cparser_init();					\
	int ret;						\
	printf("[*] start "#name" test...  ");			\
	ret = test_##name();					\
	if (ret)						\
		fprintf(stderr, "\n[!] "#name" test failed.\n");\
	else							\
		printf(" passed.\n");				\
	ffi_cparser_free();					\
} while (0)

#define assert_csym_arr_type(cs_arr, n, t) do {			\
	csymbol *ncs;						\
	ncs = &cs_arr[n];					\
	assert(ncs->type == t);					\
} while (0)

#define assert_fret_type(fcs, t) do {				\
	csymbol *ncs;						\
	ncs = &cs_arr[fcs->ret_id];				\
	assert(ncs->type == t);					\
} while (0)

#define assert_farg_type(fcs, n, t) do {			\
	csymbol *ncs;						\
	ncs = &cs_arr[fcs->arg_ids[n]];				\
	assert(ncs->type == t);					\
} while (0)

#define assert_stmb_type(stcs, n, t) do {			\
	csymbol *ncs;						\
	ncs = &cs_arr[csymst_mb_id(stcs, n)];	\
	assert(ncs->type == t);					\
} while (0)



/* mock find_kernel_symbol */
unsigned long find_kernel_symbol(const char *symbol)
{
	return 0xdeadbeef;
}

int lookup_csymbol_id_by_name(char *name)
{
	int i;

	for (i = 0; i < cs_nr; i++) {
		if (!strcmp(name, cs_arr[i].name)) {
			return i;
		}
	}

	return -1;
}

int test_func_sched_clock()
{
	int idx;
	csymbol *cs;
	csymbol_func *fcs;

	ffi_parse_cdef("unsigned long long sched_clock();");

	csym_state = ctype_get_csym_state();
	assert(cs_arr);

	idx = lookup_csymbol_id_by_name("sched_clock");
	assert(idx >= 0);
	cs = &cs_arr[idx];
	assert(cs->type == FFI_FUNC);

	fcs = csym_func(cs);

	/* check return type */
	assert_fret_type(fcs, FFI_UINT64);

	/* check arguments */
	assert(fcs->arg_nr == 0);

	return 0;
}

int test_func_funct_module()
{
	int idx;
	csymbol *cs;
	csymbol_func *fcs;

	ffi_parse_cdef("void funct_void();");
	ffi_parse_cdef("int funct_int1(unsigned char a, char b, unsigned short c, "
			"short d);");
	ffi_parse_cdef("long long funct_int2(unsigned int a, int b, "
			"unsigned long c, long d, unsigned long long e, "
			"long long f, long long g);");
	ffi_parse_cdef("void *funct_pointer1(char *a);");

	csym_state = ctype_get_csym_state();
	assert(cs_arr);

	/* check funct_void function */
	idx = lookup_csymbol_id_by_name("funct_void");
	assert(idx >= 0);
	cs = &cs_arr[idx];
	assert(cs->type == FFI_FUNC);
	fcs = csym_func(cs);

	/* check return type */
	assert_fret_type(fcs, FFI_VOID);

	/* check arguments */
	assert(fcs->arg_nr == 0);



	/* check funct_int1 function */
	idx = lookup_csymbol_id_by_name("funct_int1");
	assert(idx >= 0);
	cs = &cs_arr[idx];
	assert(cs);
	assert(cs->type == FFI_FUNC);
	fcs = csym_func(cs);

	/* check return type */
	assert_fret_type(fcs, FFI_INT32);

	/* check arguments */
	assert(fcs->arg_nr == 4);
	assert_farg_type(fcs, 0, FFI_UINT8);
	assert_farg_type(fcs, 1, FFI_INT8);
	assert_farg_type(fcs, 2, FFI_UINT16);
	assert_farg_type(fcs, 3, FFI_INT16);



	/* check funct_int2 function */
	idx = lookup_csymbol_id_by_name("funct_int2");
	assert(idx >= 0);
	cs = &cs_arr[idx];
	assert(cs);
	assert(cs->type == FFI_FUNC);
	fcs = csym_func(cs);

	/* check return type */
	assert_fret_type(fcs, FFI_INT64);

	/* check arguments */
	assert(fcs->arg_nr == 7);
	assert_farg_type(fcs, 0, FFI_UINT32);
	assert_farg_type(fcs, 1, FFI_INT32);
	assert_farg_type(fcs, 2, FFI_UINT64);
	assert_farg_type(fcs, 3, FFI_INT64);
	assert_farg_type(fcs, 4, FFI_UINT64);
	assert_farg_type(fcs, 5, FFI_INT64);
	assert_farg_type(fcs, 6, FFI_INT64);



	/* check funct_pointer1 function */
	idx = lookup_csymbol_id_by_name("funct_pointer1");
	assert(idx >= 0);
	cs = &cs_arr[idx];
	assert(cs);
	assert(cs->type == FFI_FUNC);
	fcs = csym_func(cs);

	/* check return type */
	assert_fret_type(fcs, FFI_PTR);

	/* check arguments */
	assert(fcs->arg_nr == 1);
	assert_farg_type(fcs, 0, FFI_PTR);
	/*@TODO check pointer dereference type  18.11 2013 (houqp)*/

	return 0;
}

int test_struct_timespec()
{
	int idx;
	csymbol *cs;
	csymbol_struct *stcs;

	ffi_parse_cdef("struct timespec { long ts_sec; long ts_nsec; };");

	csym_state = ctype_get_csym_state();
	assert(cs_arr);

	idx = lookup_csymbol_id_by_name("struct timespec");
	assert(idx >= 0);
	cs = &cs_arr[idx];
	assert(cs);
	assert(cs->type == FFI_STRUCT);

	stcs = csym_struct(cs);
	assert(stcs->memb_nr == 2);

	return 0;
}

int test_func_time_to_tm()
{
	int idx;
	csymbol *cs, *arg_cs;
	csymbol_struct *stcs;
	csymbol_func *fcs;

	ffi_parse_cdef("typedef long time_t;");
	ffi_parse_cdef("struct tm { "
			"int tm_sec;"
			"int tm_min;"
			"int tm_hour;"
			"int tm_mday;"
			"int tm_mon;"
			"long tm_year;"
			"int tm_wday;"
			"int tm_yday;"
		"};");
	ffi_parse_cdef("void time_to_tm(time_t totalsecs, int offset, struct tm *result);");

	csym_state = ctype_get_csym_state();
	assert(cs_arr);

	idx = lookup_csymbol_id_by_name("struct tm");
	assert(idx >= 0);
	cs = cp_id_to_csym(idx);
	assert(cs);
	assert(cs->type == FFI_STRUCT);

	stcs = csym_struct(cs);
	assert(stcs->memb_nr == 8);


	idx = lookup_csymbol_id_by_name("time_to_tm");
	assert(idx >= 0);
	cs = cp_id_to_csym(idx);
	assert(cs);
	assert(cs->type == FFI_FUNC);

	fcs = csym_func(cs);
	assert(csymf_arg_nr(fcs) == 3);
	/* check first argument */
	assert_farg_type(fcs, 0, FFI_INT64);

	/* check second argument */
	assert_farg_type(fcs, 1, FFI_INT32);
	/* check third argument */
	assert_farg_type(fcs, 2, FFI_PTR);
	arg_cs = cp_csymf_arg(fcs, 2);
	assert(!strcmp(csym_name(arg_cs), "struct tm *"));
	assert(csym_ptr_deref_id(arg_cs) ==
			lookup_csymbol_id_by_name("struct tm"));

	return 0;
}

int test_pointer_symbols()
{
	csymbol_func *fcs_foo, *fcs_bar;

	/* int pointer symbol should be resolved to the same id */
	ffi_parse_cdef("void foo(int *a);");
	ffi_parse_cdef("int *bar(void);");

	csym_state = ctype_get_csym_state();
	assert(cs_arr);

	fcs_foo = csym_func(cp_id_to_csym(lookup_csymbol_id_by_name("foo")));
	fcs_bar = csym_func(cp_id_to_csym(lookup_csymbol_id_by_name("bar")));

	assert(csymf_arg_ids(fcs_foo)[0] == csymf_ret_id(fcs_bar));
	assert(cp_csymf_arg(fcs_foo, 0) == cp_csymf_ret(fcs_bar));

	return 0;
}

int test_var_arg_function()
{
	csymbol_func *fcs;

	ffi_parse_cdef("int printk(char *fmt, ...);");

	fcs = csym_func(cp_id_to_csym(lookup_csymbol_id_by_name("printk")));

	/* var arg function needs void * type argument type checking */
	assert(lookup_csymbol_id_by_name("void *") >= 0);

	assert_fret_type(fcs, FFI_INT32);
	assert_farg_type(fcs, 0, FFI_PTR);
	assert(fcs->has_var_arg);

	return 0;
}

int test_function_pointer()
{
	int idx;
	csymbol *cs;
	csymbol *dfcs;
	csymbol_func *fcs;

	ffi_parse_cdef("int *(*foo_ptr)(char bar);");

	idx = lookup_csymbol_id_by_name("foo_ptr");
	assert(idx >= 0);

	cs = cp_id_to_csym(idx);
	assert(cs);
	assert(csym_type(cs) == FFI_PTR);

	/* check function prototype for function pointer */
	dfcs = cp_id_to_csym(csym_ptr_deref_id(cs));
	assert(csym_type(dfcs) == FFI_FUNC);
	fcs = csym_func(dfcs);

	assert(fcs->arg_nr == 1);
	assert_fret_type(fcs, FFI_PTR);
	assert_farg_type(fcs, 0, FFI_INT8);

	return 0;
}

int test_function_pointer_as_member()
{
	int idx;
	csymbol *cs;
	csymbol_struct *stcs;
	csymbol *dfcs;
	csymbol_func *fcs;

	ffi_parse_cdef("struct func_st { char a; void (*foo)(int bar); };");

	idx = lookup_csymbol_id_by_name("struct func_st");
	assert(idx >= 0);

	cs = cp_id_to_csym(idx);
	assert(cs);
	assert(cs->type == FFI_STRUCT);

	stcs = csym_struct(cs);
	assert(stcs->memb_nr == 2);

	/* first member is char */
	assert_stmb_type(stcs, 0, FFI_INT8);
	/* second member is function pointer */
	assert_stmb_type(stcs, 1, FFI_PTR);

	/* check function prototype for function pointer */
	dfcs = cp_id_to_csym(csym_ptr_deref_id(
				cp_id_to_csym(csymst_mb_id(stcs, 1))));
	assert(csym_type(dfcs) == FFI_FUNC);
	fcs = csym_func(dfcs);

	assert(fcs->arg_nr == 1);
	assert_fret_type(fcs, FFI_VOID);
	assert_farg_type(fcs, 0, FFI_INT32);

	return 0;
}

/* this test should force ctype_stack to grow it's size */
int test_large_struct()
{
	int memb_nr, i, idx;
	char *st_def, *ptr;
	csymbol_struct *stcs;

	memb_nr = cp_ctstk_free_space()+2;

#define ST_STR_PREFIX "struct large_test_st {"
#define ST_STR_MEMB "int a;"
#define ST_STR_POSTFIX "};"
	st_def = malloc(strlen(ST_STR_PREFIX)
			+memb_nr*strlen(ST_STR_MEMB)
			+strlen(ST_STR_POSTFIX));
	ptr = st_def;
	strcpy(ptr, ST_STR_PREFIX);
	ptr += strlen(ST_STR_PREFIX);
	for (i = 0; i < memb_nr; i++, ptr+=strlen(ST_STR_MEMB))
		strcpy(ptr, ST_STR_MEMB);
	strcpy(ptr, ST_STR_POSTFIX);

	ffi_parse_cdef(st_def);
	idx = lookup_csymbol_id_by_name("struct large_test_st");
	stcs = csym_struct(cp_id_to_csym(idx));

	assert(csymst_mb_nr(stcs) == memb_nr);

	free(st_def);

	return 0;
}

int main (int argc, char *argv[])
{
	DO_TEST(func_sched_clock);
	DO_TEST(func_funct_module);
	DO_TEST(struct_timespec);
	DO_TEST(func_time_to_tm);
	DO_TEST(pointer_symbols);
	DO_TEST(var_arg_function);
	DO_TEST(function_pointer);
	DO_TEST(function_pointer_as_member);
	DO_TEST(large_struct);
	return 0;
}
