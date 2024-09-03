ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

MCRYPT_SRC = mcrypt-src
MCRYPT_BUFFSIZE ?= 1024
EUROSYS_EXP_BLOCK_SIZE ?= 1024

.PHONY: all
all: mcrypt mcrypt.manifest
ifeq ($(SGX),1)
all: mcrypt.manifest.sgx mcrypt.sig mcrypt.token
endif

mcrypt.manifest: mcrypt.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

mcrypt.manifest.sgx mcrypt.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: mcrypt.manifest mcrypt
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

mcrypt.token: mcrypt.sig
	gramine-sgx-get-token \
		--output mcrypt.token --sig mcrypt.sig

.PHONY: setbufsize
setbufsize: $(MCRYPT_SRC)
	echo "Setting MCrypt buffer size to $(MCRYPT_BUFFSIZE)"
	sed -i '/BUFFER_SIZE/ s/[^[:blank:]]\{2,\}$$/$(MCRYPT_BUFFSIZE)/' $(MCRYPT_SRC)/src/defines.h

$(MCRYPT_SRC):
	wget -O $(MCRYPT_SRC).tar.gz https://sourceforge.net/projects/mcrypt/files/MCrypt/Production/mcrypt-2.6.4.tar.gz/download
	mkdir $(MCRYPT_SRC)
	tar -C $(MCRYPT_SRC) --strip-components=1 -xf $(MCRYPT_SRC).tar.gz
	sed '564,575{s/^/\/\//}' -i $(MCRYPT_SRC)/src/mcrypt.c
	cd $(MCRYPT_SRC) && ./configure

$(MCRYPT_SRC)/src/mcrypt: $(MCRYPT_SRC) $(MCRYPT_SRC)/src/defines.h
	cd $(MCRYPT_SRC) && make

mcrypt: $(MCRYPT_SRC)/src/mcrypt
	cp $< $@

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest .lck mcrypt

.PHONY: distclean
distclean: clean
	$(RM) -r $(MCRYPT_SRC) $(MCRYPT_SRC).tar.gz

eurosys-reproduce-mcrypt-%-sgx: export SGX=1

eurosys-reproduce-mcrypt-gramine-%: export PATH := $(HOME)/.local/gramine/bin:$(PATH)
eurosys-reproduce-mcrypt-gramine-%: export PYTHONPATH := $(HOME)/.local/gramine/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-mcrypt-gramine-%: export PKG_CONFIG_PATH := $(HOME)/.local/gramine/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
eurosys-reproduce-mcrypt-gramine-%: export SETTING := Gramine

eurosys-reproduce-mcrypt-rakis-%: export PATH := $(HOME)/.local/rakis/bin:$(PATH)
eurosys-reproduce-mcrypt-rakis-%: export PYTHONPATH := $(HOME)/.local/rakis/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-mcrypt-rakis-%: export PKG_CONFIG_PATH := $(HOME)/.local/rakis/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
eurosys-reproduce-mcrypt-rakis-%: export SETTING := Rakis

eurosys-reproduce-mcrypt-native: export NATIVE=1
eurosys-reproduce-mcrypt-native: export PATH := $(HOME)/.local/rakis/bin:$(PATH)
eurosys-reproduce-mcrypt-native: export PYTHONPATH := $(HOME)/.local/rakis/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-mcrypt-native: export PKG_CONFIG_PATH := $(HOME)/.local/rakis/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)

eurosys-reproduce-mcrypt-%: clean
	## mcrypt multiplies the provided buffer size by the crypto block size (16)
	## so we divide by 16 here of the user provided size
	$(MAKE) setbufsize MCRYPT_BUFFSIZE=$$(( $(EUROSYS_EXP_BLOCK_SIZE) / 16 ))
	$(MAKE) eurosys-reproduce-run-mcrypt

eurosys-reproduce-run-mcrypt: all
ifeq ($(NATIVE),1)
	@echo "\n******************************************"
	@echo "[*] Running mcrypt in NATIVE setting..."
	./mcrypt /media/xfs/eurosys25-reviewer/dump  -k "SDfsdfsdf" -t

else ifeq ($(SGX),1)
	@echo "\n******************************************"
	@echo "[*] Running mcrypt in $(SETTING)-SGX setting..."
	gramine-sgx ./mcrypt dump -k "SDfsdfsdf" -t

else
	@echo "\n******************************************"
	@echo "[*] Running mcrypt in $(SETTING)-Direct setting..."
	gramine-direct ./mcrypt dump -k "SDfsdfsdf" -t
endif
