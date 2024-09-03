# Build Redis as follows:
#
# - make               -- create non-SGX no-debug-log manifest
# - make SGX=1         -- create SGX no-debug-log manifest
# - make SGX=1 DEBUG=1 -- create SGX debug-log manifest
#
# Any of these invocations clones Redis' git repository and builds Redis in
# default configuration and in the latest-to-date (6.0.5) version.
#
# By default, Redis uses poll/epoll mechanism of Linux. To build Redis with
# select, use `make USE_SELECT=1`. For correct re-builds, always clean up
# Redis source code beforehand via `make distclean`.
#
# Use `make clean` to remove Gramine-generated files and `make distclean` to
# additionally remove the cloned Redis git repository.

################################# CONSTANTS ###################################

# directory with arch-specific libraries, used by Redis
# the below path works for Debian/Ubuntu; for CentOS/RHEL/Fedora, you should
# overwrite this default like this: `ARCH_LIBDIR=/lib64 make`
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SRCDIR = src
COMMIT = 6.0.5
TAR_SHA256 = f7ded6c27d48c20bc78e797046c79b6bc411121f0c2d7eead9fea50d6b0b6290

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: redis-server redis-server.manifest redis-benchmark
ifeq ($(SGX),1)
all: redis-server.manifest.sgx redis-server.sig redis-benchmark
endif

############################## REDIS EXECUTABLE ###############################

# Redis is built as usual, without any changes to the build process (except to
# test select syscall instead of poll/epoll). The source is downloaded from the
# GitHub repo (6.0.5 tag) and built via `make`. The result of this build process
# is the final executable "src/redis-server".

$(SRCDIR)/Makefile:
	../common_tools/download --output redis.tar.gz \
		--sha256 $(TAR_SHA256) \
		--url https://github.com/antirez/redis/archive/$(COMMIT).tar.gz \
		--url https://packages.gramineproject.io/distfiles/redis-$(COMMIT).tar.gz
	mkdir $(SRCDIR)
	tar -C $(SRCDIR) --strip-components=1 -xf redis.tar.gz

ifeq ($(USE_SELECT),1)
$(SRCDIR)/src/redis-server: $(SRCDIR)/Makefile
	sed -i 's|#define HAVE_EPOLL 1|/* no HAVE_EPOLL */|g' src/src/config.h
	$(MAKE) -C $(SRCDIR)
else
$(SRCDIR)/src/redis-server: $(SRCDIR)/Makefile
	$(MAKE) -C $(SRCDIR)
endif

################################ REDIS MANIFEST ###############################

# The template file is a Jinja2 template and contains almost all necessary
# information to run Redis under Gramine / Gramine-SGX. We create
# redis-server.manifest (to be run under non-SGX Gramine) by replacing variables
# in the template file using the "gramine-manifest" script.

redis-server.manifest: redis-server.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

# Manifest for Gramine-SGX requires special "gramine-sgx-sign" procedure. This
# procedure measures all Redis trusted files, adds the measurement to the
# resulting manifest.sgx file (among other, less important SGX options) and
# creates redis-server.sig (SIGSTRUCT object).

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
redis-server.sig redis-server.manifest.sgx: sgx_outputs
	@:

.INTERMEDIATE: sgx_outputs
sgx_outputs: redis-server.manifest $(SRCDIR)/src/redis-server
	gramine-sgx-sign \
		--manifest redis-server.manifest \
		--output redis-server.manifest.sgx

########################### COPIES OF EXECUTABLES #############################

# Redis build process creates the final executable as src/redis-server. For
# simplicity, copy it into our root directory.

redis-server: $(SRCDIR)/src/redis-server
	cp $< $@

redis-benchmark: $(SRCDIR)/src/redis-benchmark
	cp $< $@

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest redis-server *.rdb redis-benchmark

.PHONY: distclean
distclean: clean
	$(RM) -r $(SRCDIR) redis.tar.gz

eurosys-reproduce-server-%-sgx: export SGX=1

eurosys-reproduce-server-gramine-%: export PATH := $(HOME)/.local/gramine/bin:$(PATH)
eurosys-reproduce-server-gramine-%: export PYTHONPATH := $(HOME)/.local/gramine/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-server-gramine-%: export PKG_CONFIG_PATH := $(HOME)/.local/gramine/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
eurosys-reproduce-server-gramine-%: export SETTING := Gramine

eurosys-reproduce-server-rakis-%: export PATH := $(HOME)/.local/rakis/bin:$(PATH)
eurosys-reproduce-server-rakis-%: export PYTHONPATH := $(HOME)/.local/rakis/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-server-rakis-%: export PKG_CONFIG_PATH := $(HOME)/.local/rakis/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
eurosys-reproduce-server-rakis-%: export SETTING := Rakis

eurosys-reproduce-server-native: export NATIVE = 1
eurosys-reproduce-server-native: export PATH := $(HOME)/.local/rakis/bin:$(PATH)
eurosys-reproduce-server-native: export PYTHONPATH := $(HOME)/.local/rakis/lib/python3.10/site-packages:$(PYTHONPATH)
eurosys-reproduce-server-native: export PKG_CONFIG_PATH := $(HOME)/.local/rakis/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)

eurosys-reproduce-server-%: export USE_SELECT = 1
eurosys-reproduce-server-%: export LD_LIBRARY_PATH := $(LIBEVENT_INS)/lib
eurosys-reproduce-server-%: clean
	$(MAKE) eurosys-reproduce-run-server

eurosys-reproduce-run-server: all
ifeq ($(NATIVE),1)
	@echo "\n******************************************"
	@echo "[*] Running redis in NATIVE setting..."
	./redis-server

else ifeq ($(SGX),1)
	@echo "\n******************************************"
	@echo "[*] Running redis in $(SETTING)-SGX setting..."
	gramine-sgx ./redis-server

else
	@echo "\n******************************************"
	@echo "[*] Running redis in $(SETTING)-Direct setting..."
	gramine-direct ./redis-server
endif
