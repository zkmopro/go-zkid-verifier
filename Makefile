RUST_DIR   := rust
RUST_LIB   := $(RUST_DIR)/target/release/libzk_verifier.a

DYLIB_DIR  := $(CURDIR)/lib

BASE_DIR   ?= $(CURDIR)

.PHONY: all build test verify download-keys clean

all: build

$(RUST_LIB):
	cd $(RUST_DIR) && cargo build --release

build: $(RUST_LIB)
	go build -o zk-verifier .

sign: build
	codesign --sign - --entitlements /tmp/entitlements.plist --force ./zk-verifier
	codesign --sign - --entitlements /tmp/entitlements.plist --force $(DYLIB_DIR)/libwitnesscalc_rs256.dylib

test: $(RUST_LIB)
	DYLD_LIBRARY_PATH=$(DYLIB_DIR) ZK_BASE_DIR=$(BASE_DIR) go test ./verifier/ -v

verify: $(RUST_LIB)
	DYLD_LIBRARY_PATH=$(DYLIB_DIR) RUST_LOG=info go run main.go

download-keys:
	bash scripts/download_keys.sh

clean:
	cd $(RUST_DIR) && cargo clean
	go clean ./...
	rm -f zk-verifier
