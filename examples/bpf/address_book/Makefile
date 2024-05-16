# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

SHELL := /bin/bash
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
LLVM_STRIP ?= llvm-strip

# Libs directories
LIBBPF_SRC := $(abspath ../../../libs/bpftool/libbpf/src)
BPFTOOL_SRC := $(abspath ../../../libs/bpftool/src)

# Output directory
OUTPUT := .output
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
LIBBPF_PKGCONFIG := $(abspath $(OUTPUT)/pkgconfig)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
VMLINUX_H := $(abspath $(OUTPUT)/vmlinux.h)

# Compiler and linker options
INCLUDES := -I$(OUTPUT) -I../../../libs/bpftool/libbpf/include/uapi
CFLAGS := -g -Wall -DLOG_USE_COLOR
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
ALL_LDFLAGS += -lrt -ldl -lpthread -lm

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell clang -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# hide output unless V=1
ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

APPS = address_book

####
# TARGETS
####

all: $(APPS)

# create folders
$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ):
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		INCLUDEDIR= LIBDIR= UAPIDIR= \
		install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

$(VMLINUX_H): $(BPFTOOL)
	$(call msg,VMLINUX,$@)
	$(Q) $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX_H) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q) clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q) llvm-strip -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q) $(BPFTOOL) gen skeleton $< > $@

# for each program in APPS, its corresponding object file (e.g., example.o)
# depends on the existence of a .skel.h file (e.g., example.skel.h).
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

# compile
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# link
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) $(LIBARGPARSE_OBJ) $(LIBLOG_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

clean-apps:
	$(call msg,CLEAN-APP)
	$(Q)rm -rf $(APPS)
	$(Q)rm -rf $(OUTPUT)/*.skel.h
	$(Q)rm -rf $(OUTPUT)/*.o

format:
	$(Q) clang-format --style LLVM -i *.c *.h

# delete failed targets
.DELETE_ON_ERROR:
