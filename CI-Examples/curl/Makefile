ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

CURL_SRC = curl-src
CURL_INS = curl-ins

OPENSSL_SRC = openssl-src
OPENSSL_INS = openssl-ins

NGTCP2_SRC = ngtcp2-src
NGTCP2_INS = ngtcp2-ins

NGHTTP3_SRC = nghttp3-src
NGHTTP3_INS = nghttp3-ins

NGHTTP2_SRC = nghttp2-src
NGHTTP2_INS = nghttp2-ins

JANSSON_SRC = jansson-src
JANSSON_INS = jansson-ins

EUROSYS_EXP_DOWNLOAD_SIZE ?= 1G

.PHONY: all
all: curl curl.manifest nghttpx
ifeq ($(SGX),1)
all: curl.manifest.sgx curl.sig curl.token nghttpx
endif

curl.manifest: curl.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dlibcurl_dir=$(ROOT_DIR)/$(CURL_INS)/lib/ \
		-Dlibssl_dir=$(ROOT_DIR)/$(OPENSSL_INS)/lib64/ \
		-Dlibnghttp3_dir=$(ROOT_DIR)/$(NGHTTP3_INS)/lib/ \
		-Dlibngtcp2_dir=$(ROOT_DIR)/$(NGTCP2_INS)/lib/ \
		$< > $@

curl.manifest.sgx curl.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: curl.manifest curl
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

curl.token: curl.sig
	gramine-sgx-get-token \
		--output curl.token --sig curl.sig

$(OPENSSL_INS)/lib64/:
	git clone --depth 1 -b openssl-3.0.9+quic \
		https://github.com/quictls/openssl $(OPENSSL_SRC) && \
		cd $(OPENSSL_SRC) && ./config enable-tls1_3 \
		--prefix=$(ROOT_DIR)/$(OPENSSL_INS) && make install

$(NGHTTP3_INS)/lib:
	git clone -b v0.12.0 https://github.com/ngtcp2/nghttp3 $(NGHTTP3_SRC) && \
		cd $(NGHTTP3_SRC) && autoreconf -i && ./configure --prefix=$(ROOT_DIR)/$(NGHTTP3_INS) --enable-lib-only && \
		make install

$(NGTCP2_INS)/lib: $(OPENSSL_INS)/lib64/ $(NGHTTP3_INS)/lib
	git clone -b v0.16.0 https://github.com/ngtcp2/ngtcp2 $(NGTCP2_SRC) && \
		cd $(NGTCP2_SRC) && autoreconf -i && \
		PKG_CONFIG_PATH=$(ROOT_DIR)/$(NGHTTP3_INS)/lib/pkgconfig:$(ROOT_DIR)/$(OPENSSL_INS)/lib64/pkgconfig \
		LDFLAGS="-Wl,-rpath,$(ROOT_DIR)/$(OPENSSL_INS)/lib64" \
		./configure --prefix=$(ROOT_DIR)/$(NGTCP2_INS) --enable-lib-only && \
		make install

$(CURL_INS)/bin/curl: $(NGTCP2_INS)/lib
	git clone https://github.com/curl/curl $(CURL_SRC) && \
		cd $(CURL_SRC) && git checkout 1eca27f && \
		autoreconf -fi && LDFLAGS="-Wl,-rpath,$(ROOT_DIR)/$(OPENSSL_INS)/lib64" \
		./configure --with-openssl=$(ROOT_DIR)/$(OPENSSL_INS) \
		--with-nghttp3=$(ROOT_DIR)/$(NGHTTP3_INS) --with-ngtcp2=$(ROOT_DIR)/$(NGTCP2_INS) \
		--prefix=$(ROOT_DIR)/$(CURL_INS) && \
		make install

$(JANSSON_INS)/lib:
	git clone https://github.com/akheron/jansson.git $(JANSSON_SRC) && \
		cd $(JANSSON_SRC) && git checkout 2.10 && \
		mkdir build && cd build && cmake ../ -DCMAKE_INSTALL_PREFIX=$(ROOT_DIR)/$(JANSSON_INS) && \
		make install

$(NGHTTP2_INS)/bin/nghttpx: $(NGTCP2_INS)/lib $(JANSSON_INS)/lib
	git clone https://github.com/nghttp2/nghttp2.git $(NGHTTP2_SRC) && \
		cd $(NGHTTP2_SRC) && git checkout e7f5940 && \
		autoreconf -fi && \
		PKG_CONFIG_PATH=$(ROOT_DIR)/$(NGHTTP3_INS)/lib/pkgconfig:$(ROOT_DIR)/$(OPENSSL_INS)/lib64/pkgconfig:$(ROOT_DIR)/$(JANSSON_INS)/lib/pkgconfig:$(ROOT_DIR)/$(NGTCP2_INS)/lib/pkgconfig \
		LDFLAGS="-Wl,-rpath,$(ROOT_DIR)/$(OPENSSL_INS)/lib64" \
		CFLAGS=-I$(ROOT_DIR)/$(OPENSSL_INS)/include \
		./configure --enable-maintainer-mode --prefix=$(ROOT_DIR)/$(NGHTTP2_INS) \
		--disable-shared --enable-app --enable-http3 --without-jemalloc \
		--without-libxml2 --without-systemd && \
		make install

curl: $(CURL_INS)/bin/curl
	cp $< $@
	touch out

nghttpx: $(NGHTTP2_INS)/bin/nghttpx
	cp $< $@

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest curl .lck nghttpx out

.PHONY: distclean
distclean: clean
	$(RM) -r $(CURL_SRC) $(CURL_INS) \
		$(OPENSSL_SRC) $(OPENSSL_INS) $(NGTCP2_SRC) \
		$(NGTCP2_INS) $(NGHTTP3_SRC) $(NGHTTP3_INS) \
		$(NGHTTP2_SRC) $(NGHTTP2_INS) $(JANSSON_SRC) $(JANSSON_INS)


eurosys-reproduce-curl-%-sgx: export SGX := 1

eurosys-reproduce-curl-gramine-%: export PATH := $(HOME)/.local/gramine/bin:$(PATH)
eurosys-reproduce-curl-gramine-%: export PYTHONPATH := $(HOME)/.local/gramine/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-curl-gramine-%: export PKG_CONFIG_PATH := $(HOME)/.local/gramine/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
eurosys-reproduce-curl-gramine-%: export SETTING := Gramine

eurosys-reproduce-curl-rakis-%: export PATH := $(HOME)/.local/rakis/bin:$(PATH)
eurosys-reproduce-curl-rakis-%: export PYTHONPATH := $(HOME)/.local/rakis/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-curl-rakis-%: export PKG_CONFIG_PATH := $(HOME)/.local/rakis/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
eurosys-reproduce-curl-rakis-%: export SETTING := Rakis

eurosys-reproduce-curl-native: export NATIVE := 1
eurosys-reproduce-curl-native: export PATH := $(HOME)/.local/rakis/bin:$(PATH)
eurosys-reproduce-curl-native: export PYTHONPATH := $(HOME)/.local/rakis/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-curl-native: export PKG_CONFIG_PATH := $(HOME)/.local/rakis/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)

eurosys-reproduce-curl-%: clean
	$(MAKE) eurosys-reproduce-run-curl

eurosys-reproduce-run-curl: all
ifeq ($(NATIVE),1)
	@echo "\n******************************************"
	@echo "[*] Running curl in NATIVE setting..."
	./curl --http3-only https://10.50.0.2:9443/dump$(EUROSYS_EXP_DOWNLOAD_SIZE) --insecure -o out -w "@curl-format.txt" -Z

else ifeq ($(SGX),1)
	@echo "\n******************************************"
	@echo "[*] Running Curl in $(SETTING)-SGX setting..."
	gramine-sgx ./curl --http3-only https://10.50.0.2:9443/dump$(EUROSYS_EXP_DOWNLOAD_SIZE) --insecure -o out -w "@curl-format.txt" -Z

else
	@echo "\n******************************************"
	@echo "[*] Running Curl in $(SETTING)-Direct setting..."
	gramine-direct ./curl --http3-only https://10.50.0.2:9443/dump$(EUROSYS_EXP_DOWNLOAD_SIZE) --insecure -o out -w "@curl-format.txt" -Z
endif
