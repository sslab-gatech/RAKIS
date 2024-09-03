RAKIS_DIR=../..
BUILD_DIR=build

# TODO: compile with integeroverflow sanitizer

CC := wllvm
CFLAGS := -DRAKIS_VERIFICATION=1 -DDEBUG=1 -MMD -std=c11 -g -O1 \
					-Xclang -disable-llvm-passes -D__NO_STRING_INLINES  -D_FORTIFY_SOURCE=0 -U__OPTIMIZE__ -D_GNU_SOURCE=1

CFLAGS_SYM := -DRAKIS_SYMBOLIC=1 $(CFLAGS)

KLEE_UCLIBC_PATH = $(abspath klee-uclibc)
KLEE_PATH = $(abspath klee)
KLEE_BUILD = $(KLEE_PATH)/build
KLEE_BIN = $(KLEE_BUILD)/bin/klee

LLVM_11_CONFIG_BIN = /usr/bin/llvm-config-11
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-11
export LLVM_CXX_NAME=clang++-11
export LLVM_LINK_NAME=llvm-link-11
export LLVM_AR_NAME=llvm-ar-11
SRCS_SYM = $(RAKIS_DIR)/sec/verification/main.c \
			 $(RAKIS_DIR)/sec/verification/ping_reply_server.c \
			 $(RAKIS_DIR)/trusted/libos/xsk.c \
			 $(RAKIS_DIR)/trusted/libos/netif.c \
			 $(RAKIS_DIR)/trusted/libos/pktbpool.c \
			 $(RAKIS_DIR)/trusted/rakis_memcpy.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/pbuf.c \
			 $(RAKIS_DIR)/trusted/pal/initialization_data_checker.c \
			 $(RAKIS_DIR)/trusted/pal/io_uring.c \
			 $(RAKIS_DIR)/trusted/libos/pktq.c

SRCS += $(SRCS_SYM) \
				$(RAKIS_DIR)/untrusted/host_init.c

INCS = -I $(RAKIS_DIR)/include
INCS_SYM = $(INCS) -I $(KLEE_PATH)/include

OBJS := $(patsubst $(RAKIS_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))
OBJS_SYM := $(patsubst $(RAKIS_DIR)/%.c, $(BUILD_DIR)/%-sym.o, $(SRCS))
DEPS := $(OBJS:.o=.d)
DEPS_SYM := $(OBJS_SYM:.o=.d)

NPROCS := $(shell nproc)

.PHONY: all
all: rakis-concrete rakis-sym.bc

rakis-concrete: $(OBJS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $^
	sudo setcap cap_net_raw,cap_bpf+p $@

rakis-sym.bc: $(OBJS_SYM)
	$(CC) $(CFLAGS_SYM) -Wl,--unresolved-symbols=ignore-all $(INCS_SYM) -o $@ $^
	extract-bc -o $@ $@

.PHONY: run
run: rakis-sym.bc
	$(KLEE_BIN) --libc=uclibc --runtime-build=Release --posix-runtime \
		--max-memory=30000 $^

$(BUILD_DIR)/%.o: $(RAKIS_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCS) -o $@ -c $<

$(BUILD_DIR)/%-sym.o: $(RAKIS_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS_SYM) $(INCS_SYM) -o $@ -c $<

klee:
	@echo "---------------------------------------------------------------------------"
	@echo "---------- Make sure you have all dependencies of KLEE if this script fails"
	@echo "---------- Check this: https://klee.github.io/build-llvm11/"
	@echo "---------------------------------------------------------------------------"
	git clone https://github.com/klee/klee-uclibc.git $(KLEE_UCLIBC_PATH)
	cd $(KLEE_UCLIBC_PATH) && git checkout klee_0_9_29 && ./configure --make-llvm-lib \
		--with-llvm-config=$(LLVM_11_CONFIG_BIN) && make -j$(NPROCS)
	git clone https://github.com/klee/klee.git $(KLEE_PATH) && \
		cd $(KLEE_PATH) && git checkout v2.3

	mkdir $(KLEE_BUILD) && cd $(KLEE_BUILD) && \
		cmake -DCMAKE_BUILD_TYPE=Release KLEE_RUNTIME_BUILD_TYPE=Release \
		-DENABLE_SOLVER_Z3=ON -DENABLE_POSIX_RUNTIME=ON -DENABLE_KLEE_UCLIBC=ON\
		-DKLEE_UCLIBC_PATH=$(KLEE_UCLIBC_PATH) -DUSE_CMAKE_FIND_PACKAGE_LLVM=FALSE \
		-DLLVM_CONFIG_BINARY=$(LLVM_11_CONFIG_BIN) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON\
		../ && make -j$(NPROCS)

.PHONY: clean-all
clean-all: clean-rakis clean-klee clean-klee-out

.PHONY: clean-rakis
clean-rakis:
	rm -rf $(BUILD_DIR) rakis-concrete rakis-sym.bc

.PHONY: clean-klee
clean-klee:
	rm -rf  $(KLEE_PATH) $(KLEE_UCLIBC_PATH)

.PHONY: clean-klee-out
clean-klee-out:
	rm -rf klee-last  klee-out-*

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
-include $(DEPS_SYM)
endif
