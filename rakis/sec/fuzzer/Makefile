RAKIS_DIR=../..
BUILD_DIR=build

CC := /home/mansour/rakis/rakis/sec/fuzzer/AFLplusplus/afl-clang-fast
CFLAGS := -DRAKIS_FUZZ=1 -fsanitize=address -fsanitize=undefined -g

AFLPLUSPLUS_PATH = $(abspath AFLplusplus)
AFLPLUSPLUS_BIN = $(AFLPLUSPLUS_PATH)/afl-fuzz

SRCS = $(RAKIS_DIR)/sec/fuzzer/main.c \
       $(RAKIS_DIR)/sec/fuzzer/fuzz_sockets.c \
			 $(RAKIS_DIR)/trusted/libos/pktbpool.c \
			 $(RAKIS_DIR)/trusted/libos/netif.c \
			 $(RAKIS_DIR)/trusted/libos/pktq.c \
			 $(RAKIS_DIR)/trusted/libos/stack/stack.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/pbuf.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/sockets.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/udp.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/inet_chksum.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/netif.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/err.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/ethernet.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/mem.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/raw.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/ipv4/etharp.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/ipv4/ip4.c \
			 $(RAKIS_DIR)/trusted/libos/stack/lwip/ipv4/ip4_addr.c

INCS = -I $(RAKIS_DIR)/include

OBJS := $(patsubst $(RAKIS_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))
DEPS := $(OBJS:.o=.d)

NPROCS := $(shell nproc)

.PHONY: all
all: rakis-fuzz

rakis-fuzz: $(OBJS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $^

.PHONY: run
run: rakis-fuzz
	@echo "Running rakis-fuzz"
	$(AFLPLUSPLUS_BIN) -M master_rakis_fuzz -i testcases/ -o fuzz_output -- ./rakis-fuzz &\
		$(AFLPLUSPLUS_BIN) -S slave_rakis -i testcases/ -o fuzz_output/ -- ./rakis-fuzz

$(BUILD_DIR)/%.o: $(RAKIS_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCS) -o $@ -c $<

afl++:
	@echo "---------------------------------------------------------------------------"
	@echo "---------- Make sure you have all dependencies of AFL++ if this script fails"
	@echo "---------- Check this: https://github.com/AFLplusplus/AFLplusplus"
	@echo "---------------------------------------------------------------------------"
	git clone https://github.com/AFLplusplus/AFLplusplus $(AFLPLUSPLUS_PATH)
	cd $(AFLPLUSPLUS_PATH) && git checkout stable && make all

.PHONY: clean-all
clean-all: clean-rakis clean-afl++ clean-afl++-out

.PHONY: clean-rakis
clean-rakis:
	rm -rf $(BUILD_DIR) rakis-fuzz

.PHONY: clean-afl++
clean-afl++:
	rm -rf AFLplusplus/

.PHONY: clean-afl++-out
clean-afl++-out:
	rm -rf fuzz_output

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif
