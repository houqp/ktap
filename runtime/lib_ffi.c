/*
 * lib_ffi.c - FFI library
 *
 * This file is part of ktap by Jovi Zhangwei.
 *
 * Copyright (C) 2012-2013 Jovi Zhangwei <jovi.zhangwei@gmail.com>.
 *
 * ktap is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * ktap is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "../include/ktap_types.h"
#include "../include/ktap_ffi.h"
#include "ktap.h"
#include "kp_vm.h"


static int kplib_ffi_new(ktap_state *ks)
{
	int n = kp_arg_nr(ks), array_size;
	csymbol_id cs_id;
	ktap_cdata *cd;

	if (unlikely(n != 2)) {
		/* this is not likely to happen since ffi.new arguments are
		 * generated by compiler */
		set_nil(ks->top++);
		kp_error(ks, "wrong number of arguments\n");
		return 1;
	}

	kp_arg_check(ks, 1, KTAP_TYPE_NUMBER);
	kp_arg_check(ks, 2, KTAP_TYPE_NUMBER);

	cs_id = nvalue(kp_arg(ks, 1));
	array_size = nvalue(kp_arg(ks, 2));

	if (unlikely(cs_id > max_csym_id(ks)))
		kp_error(ks, "invalid csymbol id\n");

	kp_verbose_printf(ks, "ffi.new symbol %s with length %d\n",
			id_to_csym(ks, cs_id)->name, array_size);

	cd = kp_cdata_new_ptr(ks, NULL, array_size, cs_id, 1);
	set_cdata(ks->top, cd);
	incr_top(ks);

	return 1;
}

static int kplib_ffi_free(ktap_state *ks)
{
	int n = kp_arg_nr(ks);
	ktap_cdata *cd;

	if (n != 1) {
		set_nil(ks->top++);
		kp_error(ks, "wrong number of arguments\n");
		return 1;
	}

	kp_arg_check(ks, 1, KTAP_TYPE_CDATA);

	cd = cdvalue(kp_arg(ks, 1));

	if (cd_type(ks, cd) != FFI_PTR)
		kp_error(ks, "could free pointer cdata only\n");

	kp_cdata_free_ptr(ks, cd);

	return 0;
}

static int kplib_ffi_sizeof(ktap_state *ks)
{
	/*@TODO finish this  08.11 2013 (houqp)*/
	return 0;
}

static const ktap_Reg ffi_funcs[] = {
	{"sizeof", kplib_ffi_sizeof},
	{"new", kplib_ffi_new},
	{"free", kplib_ffi_free},
	{NULL}
};

int kp_init_ffilib(ktap_state *ks)
{
	return kp_register_lib(ks, "ffi", ffi_funcs);
}
