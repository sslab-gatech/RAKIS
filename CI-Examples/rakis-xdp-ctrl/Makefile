CC = clang
LLC = llc
CFLAGS = -O3 -std=gnu11 -Wall -Wextra
LDLIBS = -lxdp

RAKIS_XDP_LOADER = rakis-xdp-def-ctrl
RAKIS_XDP_PROG = rakis-xdp-prog

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
BPF_CFLAGS = -D__TARGET_ARCH_$(ARCH)

.PHONY: all clean
all: $(RAKIS_XDP_LOADER) $(RAKIS_XDP_PROG)

$(RAKIS_XDP_LOADER): $(RAKIS_XDP_LOADER).c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

$(RAKIS_XDP_PROG): $(RAKIS_XDP_PROG).c
	$(CC) -S \
		-I /usr/include/x86_64-linux-gnu \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

clean:
	$(RM) $(RAKIS_XDP_LOADER) $(RAKIS_XDP_PROG)
