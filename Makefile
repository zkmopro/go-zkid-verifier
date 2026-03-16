RUST_DIR := rust

UNAME_S  := $(shell uname -s)
UNAME_M  := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    DYLIB_EXT    := dylib
    LD_PATH_VAR  := DYLD_LIBRARY_PATH
    ifeq ($(UNAME_M),arm64)
        RUST_TARGET  := aarch64-apple-darwin
    else
        RUST_TARGET  := x86_64-apple-darwin
    endif
    RUST_OUT_DIR := $(RUST_DIR)/target/release
else
    DYLIB_EXT    := so
    LD_PATH_VAR  := LD_LIBRARY_PATH
    RUST_TARGET  := x86_64-unknown-linux-gnu
    RUST_OUT_DIR := $(RUST_DIR)/target/$(RUST_TARGET)/release
endif

LIB_DIR  := $(CURDIR)/lib/$(RUST_TARGET)
RUST_LIB := $(LIB_DIR)/libzk_verifier.a
BASE_DIR ?= $(CURDIR)

.PHONY: all build test verify download-keys clean

all: build

$(RUST_LIB):
ifeq ($(UNAME_S),Darwin)
	cd $(RUST_DIR) && cargo build --release
else
	cd $(RUST_DIR) && cargo build --release --target $(RUST_TARGET)
endif
	mkdir -p $(LIB_DIR)
	cp $(RUST_OUT_DIR)/libzk_verifier.a $(LIB_DIR)/
	cp $(shell find $(RUST_OUT_DIR)/build -name "libwitnesscalc_rs256.$(DYLIB_EXT)" -path "*/package/lib/*" | head -1) $(LIB_DIR)/

build: $(RUST_LIB)
	go build -o zk-verifier .

test: $(RUST_LIB)
	$(LD_PATH_VAR)=$(LIB_DIR) ZK_BASE_DIR=$(BASE_DIR) go test ./verifier/ -v

verify: $(RUST_LIB)
	$(LD_PATH_VAR)=$(LIB_DIR) RUST_LOG=info go run main.go

download-keys:
	bash scripts/download_keys.sh

clean:
	cd $(RUST_DIR) && cargo clean
	go clean ./...
	rm -f zk-verifier
