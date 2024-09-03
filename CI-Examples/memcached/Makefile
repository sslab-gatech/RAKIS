ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

LIBEVENT_GIT = https://github.com/libevent/libevent.git
LIBEVENT_SRC = libevent-src
LIBEVENT_INS = libevent-install

MEMCACHED_SRC_AR ?= memcached-1.5.21.tar.gz
MEMCACHED_SRC = memcached-src
MEMCACHED_MIRRORS ?= \
    https://memcached.org/files \
    https://packages.gramineproject.io/distfiles
MEMCACHED_SHA256 ?= e3d10c06db755b220f43d26d3b68d15ebf737a69c7663529b504ab047efe92f4

LIBMEMCACHED_SRC_AR ?= libmemcached-1.0.18.tar.gz
LIBMEMCACHED_SRC = libmemcached-src
LIBMEMCACHED_MIRRORS ?= \
		https://launchpad.net/libmemcached/1.0/1.0.18/+download/
LIBMEMCACHED_SHA256 = e22c0bb032fde08f53de9ffbc5a128233041d9f33b5de022c0978a2149885f82
LIBMEMCACHED_INS = libmemcached-install

EUROSYS_EXP_NUM_THREADS ?= 4

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: memcached memcached.manifest memaslap
ifeq ($(SGX),1)
all: memcached.manifest.sgx memcached.sig memaslap
endif

$(MEMCACHED_SRC)/configure:
	../common_tools/download --output memcached.tar.gz --sha256 $(MEMCACHED_SHA256) \
		$(foreach mirror,$(MEMCACHED_MIRRORS),--url $(mirror)/$(MEMCACHED_SRC_AR))
	mkdir $(MEMCACHED_SRC)
	tar -C $(MEMCACHED_SRC) --strip-components=1 -xf memcached.tar.gz

$(LIBEVENT_SRC):
	git clone $(LIBEVENT_GIT) $(LIBEVENT_SRC) && cd $(LIBEVENT_SRC) && \
		git checkout release-2.1.7-rc

$(LIBEVENT_INS)/lib: $(LIBEVENT_SRC)
	cd $(LIBEVENT_SRC) && ./autogen.sh && ./configure --prefix=$(ROOT_DIR)/$(LIBEVENT_INS)
	sed -e '/_EPOLL/s/^/\/\//' -i $(LIBEVENT_SRC)/config.h
	make install -C $(LIBEVENT_SRC)

$(MEMCACHED_SRC)/memcached: $(MEMCACHED_SRC)/configure $(LIBEVENT_INS)/lib
	cd $(MEMCACHED_SRC) && \
		CFLAGS="-Wno-deprecated-declarations -fcommon" ./configure --with-libevent=$(ROOT_DIR)/$(LIBEVENT_INS)/lib
	$(MAKE) -C $(MEMCACHED_SRC)

memcached.manifest: memcached.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dlibevent_dir=$(ROOT_DIR)/$(LIBEVENT_INS)/lib/ \
		$< > $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
memcached.manifest.sgx memcached.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: memcached.manifest memcached
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

$(LIBMEMCACHED_SRC)/configure:
	../common_tools/download --output libmemcached.tar.gz --sha256 $(LIBMEMCACHED_SHA256) \
		$(foreach mirror,$(LIBMEMCACHED_MIRRORS),--url $(mirror)/$(LIBMEMCACHED_SRC_AR))
	mkdir $(LIBMEMCACHED_SRC)
	tar -C $(LIBMEMCACHED_SRC) --strip-components=1 -xf libmemcached.tar.gz

$(LIBMEMCACHED_INS)/bin/memaslap: $(LIBMEMCACHED_SRC)/configure
	cd $(LIBMEMCACHED_SRC) && \
		CXXFLAGS="-fpermissive -fcommon -Wl,--allow-multiple-definition" \
						 ./configure --prefix=$(ROOT_DIR)/$(LIBMEMCACHED_INS) \
						 --enable-memaslap --disable-memflush \
		&& make install

# for simplicity, copy memcached executable into our root directory
memcached: $(MEMCACHED_SRC)/memcached
	cp $< $@

memaslap: $(LIBMEMCACHED_INS)/bin/memaslap
	cp $< $@

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest memcached .lck memaslap

.PHONY: distclean
distclean: clean
	$(RM) -r $(MEMCACHED_SRC) memcached.tar.gz $(LIBEVENT_SRC) $(LIBEVENT_INS)\
		$(LIBMEMCACHED_SRC) $(LIBMEMCACHED_INS) libmemcached.tar.gz

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

eurosys-reproduce-server-%: export LD_LIBRARY_PATH := $(LIBEVENT_INS)/lib
eurosys-reproduce-server-%: clean
	$(MAKE) eurosys-reproduce-run-server

eurosys-reproduce-run-server: all
ifeq ($(NATIVE),1)
	@echo "\n******************************************"
	@echo "[*] Running memcached in NATIVE setting..."
	./memcached -u nobody -U 57344 -l 10.50.1.1 -p 57344 -A -k -t $(EUROSYS_EXP_NUM_THREADS)

else ifeq ($(SGX),1)
	@echo "\n******************************************"
	@echo "[*] Running memcached in $(SETTING)-SGX setting..."
	gramine-sgx ./memcached -u nobody -U 57344 -l 10.50.1.1 -p 57344 -A -k -t $(EUROSYS_EXP_NUM_THREADS)

else
	@echo "\n******************************************"
	@echo "[*] Running memcached in $(SETTING)-Direct setting..."
	gramine-direct ./memcached -u nobody -U 57344 -l 10.50.1.1 -p 57344 -A -k -t $(EUROSYS_EXP_NUM_THREADS)
endif
