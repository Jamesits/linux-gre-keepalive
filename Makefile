# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

SRC_DIR = src
BUILD_DIR = build

XDP_C = $(wildcard $(SRC_DIR)/*.c)
XDP_OBJ = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(XDP_C))

USER_LIBS :=
EXTRA_DEPS :=

LLC ?= llc
CLANG ?= clang
CC ?= gcc

LIBBPF_DIR = libbpf/src/
OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
CFLAGS += -I../headers/
LDFLAGS ?= -L$(LIBBPF_DIR)

LIBS = -l:libbpf.a -lelf $(USER_LIBS)

BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I../headers/
BPF_CFLAGS += -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types
BPF_CFLAGS_EXTRA ?= -Werror -Wno-visibility
BPF_CFLAGS_USER ?=

ifeq ($(DEBUG), 1)
BPF_CFLAGS_USER += -DDEBUG
endif

all: llvm-check $(XDP_OBJ)

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	rm -rf $(BUILD_DIR)
	rm -f *~

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(BUILD_DIR): 
	mkdir -p $(BUILD_DIR)

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all; \
		mkdir -p build; DESTDIR=build $(MAKE) install_headers; \
	fi

$(XDP_OBJ): $(BUILD_DIR)/%.o: $(SRC_DIR)/%.c  $(BUILD_DIR) $(OBJECT_LIBBPF) Makefile $(EXTRA_DEPS)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) $(BPF_CFLAGS_EXTRA) $(BPF_CFLAGS_USER) \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
