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
RUST_LIB := $(LIB_DIR)/libzk_verifier.a
BASE_DIR ?= $(CURDIR)

.PHONY: all build build-server build-verifier test test-challenge test-verifier \
        test-linkverify verify serve download-keys proto clean

all: build

$(RUST_LIB):
ifeq ($(UNAME_S),Darwin)
	cd $(RUST_DIR) && cargo build --release
else
	cd $(RUST_DIR) && cargo build --release --target $(RUST_TARGET)
endif
	mkdir -p $(LIB_DIR)
	cp $(RUST_OUT_DIR)/libzk_verifier.a $(LIB_DIR)/
	find $(RUST_OUT_DIR)/build -name 'libwitnesscalc_device_sig_rs2048.a' -exec cp {} $(LIB_DIR)/ \;
	find $(RUST_OUT_DIR)/build -name 'libfr.a' -exec cp {} $(LIB_DIR)/ \;
	find $(RUST_OUT_DIR)/build -name 'libgmp.a' -exec cp {} $(LIB_DIR)/ \;

build-server: $(RUST_LIB)
	go build -o zkid-server ./cmd/server

build-verifier: $(RUST_LIB)
	go build -o zkid-verifier ./cmd/verifier

build: build-server build-verifier

test-challenge: $(RUST_LIB)
	go test ./store/ ./challenge/ -v

test-verifier: $(RUST_LIB)
	$(LD_PATH_VAR)=$(LIB_DIR) ZK_BASE_DIR=$(BASE_DIR) go test ./verifier/ -v

test-linkverify: $(RUST_LIB)
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
	rm -f zkid-server zkid-verifier
