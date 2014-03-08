obj-m += ktap_ffi_test.o

all: funct_mod cparser_test

funct_mod:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

INC=../../include
U_DIR=../../userspace
RUNTIME=../../runtime
U_FFI_DIR=$(U_DIR)/ffi
CPARSER_FILES=cparser.o ctype.o ffi_type.o ctype_stack.o
KTAPC_CFLAGS = -Wall -O2

cparser.o: $(U_FFI_DIR)/cparser.c $(INC)/*
	$(QUIET_CC)$(CC) -DCONFIG_KTAP_FFI -o $@ -c $<

ctype.o: $(U_FFI_DIR)/ctype.c $(INC)/*
	$(QUIET_CC)$(CC) -DCONFIG_KTAP_FFI -o $@ -c $<

ctype_stack.o: $(U_FFI_DIR)/ctype_stack.c $(INC)/*
	$(QUIET_CC)$(CC) -DCONFIG_KTAP_FFI -o $@ -c $<

ffi_type.o: $(RUNTIME)/ffi/ffi_type.c $(INC)/*
	$(QUIET_CC)$(CC) -DCONFIG_KTAP_FFI -o $@ -c $<

cparser_test: cparser_test.c $(CPARSER_FILES) $(INC)/*
	$(QUIET_CC)$(CC) -DCONFIG_KTAP_FFI -I$(INC) -I$(U_FFI_DIR) \
		$(KTAPC_CFLAGS) \
		-o $@ $< $(CPARSER_FILES)

load:
	insmod ktap_ffi_test.ko

unload:
	rmmod ktap_ffi_test

test_cparser: all
	@echo "testing cparser:"
	./cparser_test

test: all test_cparser
	@echo "testing ffi module:"
	rmmod ktap_ffi_test > /dev/null 2>&1 || true
	insmod ktap_ffi_test.ko
	../../ktap ffi_test.kp
	rmmod ktap_ffi_test.ko
	@echo "[*] all ffi tests passed."

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf cparser_test
