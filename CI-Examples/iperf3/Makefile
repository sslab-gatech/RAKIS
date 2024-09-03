CC=clang
LLC=llc
CFLAGS = -O3 -std=gnu11 -Wall -Wextra
LDLIBS = -lxdp

IPERF_REPO = https://github.com/esnet/iperf.git
IPERF_TAG = 3.13
IPERF_LOCAL = iperf
IPERF_BIN = $(IPERF_LOCAL)/src/iperf3
IPERF_CONFIG = $(IPERF_LOCAL)/src/iperf_config.h


ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
BPF_CFLAGS = -D__TARGET_ARCH_$(ARCH)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
CFLAGS += -g
else
GRAMINE_LOG_LEVEL = error
CFLAGS += -O3
endif

.PHONY: all build-iperf custom-conf config-iperf checkout-iperf clean distclean
all: rakis-profiler iperf3.manifest
ifeq ($(SGX),1)
all: iperf3.manifest.sgx iperf3.sig iperf3.token
endif

rakis-profiler: build-iperf
	@file $(IPERF_BIN) > /dev/null && echo "iperf compiled successfully"
	cp $(IPERF_BIN) .

build-iperf: custom-conf
	make -C $(IPERF_LOCAL) -j50;

custom-conf: config-iperf
	sed -i 's/#define HAVE_DLFCN_H 1/#undef HAVE_DLFCN_H/g' $(IPERF_CONFIG); \
	sed -i 's/#define HAVE_FLOWLABEL 1/#undef HAVE_FLOWLABEL/g' $(IPERF_CONFIG); \
	sed -i 's/#define HAVE_SENDFILE 1/#undef HAVE_SENDFILE/g' $(IPERF_CONFIG); \
	sed -i 's/#define HAVE_SO_MAX_PACING_RATE 1/#undef HAVE_SO_MAX_PACING_RATE/g' $(IPERF_CONFIG); \
	sed -i 's/#define HAVE_TCP_CONGESTION 1/#undef HAVE_TCP_CONGESTION/g' $(IPERF_CONFIG);
	sed -i 's/#define HAVE_TCP_USER_TIMEOUT 1/#undef HAVE_TCP_USER_TIMEOUT/g' $(IPERF_CONFIG);
	sed -i 's/#define HAVE_SSL 1/#undef HAVE_SSL/g' $(IPERF_CONFIG);
	sed -i 's/#define HAVE_TCP_INFO_SND_WND 1/#undef HAVE_TCP_INFO_SND_WND/g' $(IPERF_CONFIG);
	sed -i -e '$$a#define ENABLE_TCP_INFO 0' $(IPERF_CONFIG);

config-iperf: checkout-iperf
	cd $(IPERF_LOCAL); \
		./config.status || ./configure --disable-shared;

checkout-iperf: clone-iperf
		(cd $(IPERF_LOCAL); git checkout . && git checkout "$(IPERF_TAG)" && \
			git apply ../iperf3_tcp_info.patch || true)

clone-iperf:
	(git clone "$(IPERF_REPO)" $(IPERF_LOCAL) || true)

iperf3.manifest: iperf3.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		$< $@

iperf3.sig iperf3.manifest.sgx: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: iperf3.manifest rakis-profiler
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

iperf3.token: iperf3.sig
	gramine-sgx-get-token \
		--output $@ --sig $<

clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest iperf3
	$(MAKE) -C $(IPERF_LOCAL) clean || true

distclean: clean
	$(RM) -r $(IPERF_LOCAL)

eurosys-reproduce-server-%-sgx: export SGX=1

eurosys-reproduce-server-gramine-%: export PATH := $(HOME)/.local/gramine/bin:$(PATH)
eurosys-reproduce-server-gramine-%: export PYTHONPATH := $(HOME)/.local/gramine/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-server-gramine-%: export PKG_CONFIG_PATH := $(HOME)/.local/gramine/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
eurosys-reproduce-server-gramine-%: export SETTING := Gramine

eurosys-reproduce-server-rakis-%: export PATH := $(HOME)/.local/rakis/bin:$(PATH)
eurosys-reproduce-server-rakis-%: export PYTHONPATH := $(HOME)/.local/rakis/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-server-rakis-%: export PKG_CONFIG_PATH := $(HOME)/.local/rakis/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
eurosys-reproduce-server-rakis-%: export SETTING := Rakis

eurosys-reproduce-server-native: export NATIVE=1
eurosys-reproduce-server-native: export PATH := $(HOME)/.local/rakis/bin:$(PATH)
eurosys-reproduce-server-native: export PYTHONPATH := $(HOME)/.local/rakis/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-server-native: export PKG_CONFIG_PATH := $(HOME)/.local/rakis/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)

eurosys-reproduce-server-%: clean
	$(MAKE) eurosys-reproduce-run-server

eurosys-reproduce-run-server: all
ifeq ($(NATIVE),1)
	@echo "\n******************************************"
	@echo "[*] Running iperf3 in NATIVE setting..."
	./iperf3 -s -p 57344 -4 -V -B 10.50.0.1 --forceflush

else ifeq ($(SGX),1)
	@echo "\n******************************************"
	@echo "[*] Running iperf3 in $(SETTING)-SGX setting..."
	gramine-sgx ./iperf3 -s -p 57344 -4 -V -B 10.50.0.1 --forceflush

else
	@echo "\n******************************************"
	@echo "[*] Running iperf3 in $(SETTING)-Direct setting..."
	gramine-direct ./iperf3 -s -p 57344 -4 -V -B 10.50.0.1 --forceflush
endif
