ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
CFLAGS = -Wall -Wextra

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
CFLAGS += -g
else
GRAMINE_LOG_LEVEL = error
CFLAGS += -O3
endif

UNIXBENCH_REPO = https://github.com/kdlucas/byte-unixbench.git
UNIXBENCH_SRC = unix-benchmark

.PHONY: all
all: fstime fstime.manifest
ifeq ($(SGX),1)
all: fstime.manifest.sgx fstime.sig fstime.token
endif

EUROSYS_EXP_BLOCK_SIZE ?= 2048

$(UNIXBENCH_SRC)/UnixBench/pgms/fstime:
	git clone $(UNIXBENCH_REPO) $(UNIXBENCH_SRC) && cd $(UNIXBENCH_SRC)/UnixBench && \
		git checkout a07fcc0 && git apply ../../fstime.patch && make

fstime: $(UNIXBENCH_SRC)/UnixBench/pgms/fstime
	cp $< $@
	ln -sf /media/xfs/eurosys25-reviewer/dummy0 dummy0
	ln -sf /media/xfs/eurosys25-reviewer/dummy1 dummy1

fstime.manifest: fstime.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		$< $@

fstime.sig fstime.manifest.sgx: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: fstime.manifest fstime
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

fstime.token: fstime.sig
	gramine-sgx-get-token \
		--output $@ --sig $<

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest fstime dummy*

.PHONY: distclean
distclean: clean
	$(RM) -r $(UNIXBENCH_SRC)

eurosys-reproduce-fstime-%-sgx: export SGX=1

eurosys-reproduce-fstime-gramine-%: export PATH := $(HOME)/.local/gramine/bin:$(PATH)
eurosys-reproduce-fstime-gramine-%: export PYTHONPATH := $(HOME)/.local/gramine/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-fstime-gramine-%: export PKG_CONFIG_PATH := $(HOME)/.local/gramine/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
eurosys-reproduce-fstime-gramine-%: export SETTING := Gramine

eurosys-reproduce-fstime-rakis-%: export PATH := $(HOME)/.local/rakis/bin:$(PATH)
eurosys-reproduce-fstime-rakis-%: export PYTHONPATH := $(HOME)/.local/rakis/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-fstime-rakis-%: export PKG_CONFIG_PATH := $(HOME)/.local/rakis/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
eurosys-reproduce-fstime-rakis-%: export SETTING := Rakis

eurosys-reproduce-fstime-native: export NATIVE=1
eurosys-reproduce-fstime-native: export PATH := $(HOME)/.local/rakis/bin:$(PATH)
eurosys-reproduce-fstime-native: export PYTHONPATH := $(HOME)/.local/rakis/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-fstime-native: export PKG_CONFIG_PATH := $(HOME)/.local/rakis/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)

eurosys-reproduce-fstime-%: clean
	$(MAKE) eurosys-reproduce-run-fstime

eurosys-reproduce-run-fstime: all
ifeq ($(NATIVE),1)
	@echo "\n******************************************"
	@echo "[*] Running fstime in NATIVE setting..."
	./fstime -w -t 10 -b $(EUROSYS_EXP_BLOCK_SIZE)

else ifeq ($(SGX),1)
	@echo "\n******************************************"
	@echo "[*] Running fstime in $(SETTING)-SGX setting..."
	gramine-sgx ./fstime -w -t 10 -b $(EUROSYS_EXP_BLOCK_SIZE)

else
	@echo "\n******************************************"
	@echo "[*] Running fstime in $(SETTING)-Direct setting..."
	gramine-direct ./fstime -w -t 10 -b $(EUROSYS_EXP_BLOCK_SIZE)
endif
