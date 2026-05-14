RUST_DIR := rust

UNAME_S  := $(shell uname -s)
UNAME_M  := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    DYLIB_EXT    := dylib
    LD_PATH_VAR  := DYLD_LIBRARY_PATH
    RUST_TARGET  := aarch64-apple-darwin
    RUST_OUT_DIR := $(RUST_DIR)/target/release
else
    DYLIB_EXT    := so
    LD_PATH_VAR  := LD_LIBRARY_PATH
    RUST_TARGET  := x86_64-unknown-linux-gnu
    RUST_OUT_DIR := $(RUST_DIR)/target/$(RUST_TARGET)/release
endif

LIB_DIR  := $(CURDIR)/lib/$(RUST_TARGET)
BASE_DIR ?= $(CURDIR)

.PHONY: all build build-server build-verifier rust-lib test test-challenge \
        test-verifier test-linkverify verify serve download-keys proto clean

all: build

# Phony so cargo (not make) decides whether a rebuild is needed.
rust-lib:
ifeq ($(UNAME_S),Darwin)
	cd $(RUST_DIR) && cargo build --release
else
	cd $(RUST_DIR) && cargo build --release --target $(RUST_TARGET)
endif
	mkdir -p $(LIB_DIR)
	cp $(RUST_OUT_DIR)/libzk_verifier.a $(LIB_DIR)/
	find $(RUST_OUT_DIR)/build -name 'libwitnesscalc_userSigRS2048.a' -exec cp {} $(LIB_DIR)/ \;
	find $(RUST_OUT_DIR)/build -name 'libfr.a' -exec cp {} $(LIB_DIR)/ \;
	find $(RUST_OUT_DIR)/build -name 'libgmp.a' -exec cp {} $(LIB_DIR)/ \;

build-server: rust-lib
	go build -o zkid-server ./cmd/server

build-verifier: rust-lib
	go build -o zkid-verifier ./cmd/verifier

build: build-server build-verifier

test-challenge: rust-lib
	go test ./store/ ./challenge/ -v

test-verifier: rust-lib
	$(LD_PATH_VAR)=$(LIB_DIR) ZK_BASE_DIR=$(BASE_DIR) go test ./verifier/ -v

test-linkverify: rust-lib
	$(LD_PATH_VAR)=$(LIB_DIR) go test ./linkverify/ -v

test: test-challenge test-verifier test-linkverify

verify: build-verifier
	$(LD_PATH_VAR)=$(LIB_DIR) RUST_LOG=info ./zkid-verifier

serve: build-server
	$(LD_PATH_VAR)=$(LIB_DIR) ./zkid-server

download-keys:
	bash scripts/download_keys.sh

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       proto/zkid/v1/zkid.proto

clean:
	cd $(RUST_DIR) && cargo clean
	go clean ./...
	rm -rf $(LIB_DIR)
	rm -rf keys/
	rm -f zkid-server zkid-verifier
