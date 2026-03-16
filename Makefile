RUST_DIR   := rust
RUST_LIB   := $(CURDIR)/lib/libzk_verifier.a

DYLIB_DIR  := $(CURDIR)/lib

BASE_DIR   ?= $(CURDIR)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    DYLIB_EXT   := dylib
    LD_PATH_VAR := DYLD_LIBRARY_PATH
else
    DYLIB_EXT   := so
    LD_PATH_VAR := LD_LIBRARY_PATH
endif

.PHONY: all build test verify download-keys clean

all: build

$(RUST_LIB):
	cd $(RUST_DIR) && cargo build --release
	mkdir -p $(CURDIR)/lib
	cp $(RUST_DIR)/target/release/libzk_verifier.a $(CURDIR)/lib/
	cp $(shell find $(RUST_DIR)/target/release/build -name "libwitnesscalc_rs256.$(DYLIB_EXT)" -path "*/package/lib/*" | head -1) $(CURDIR)/lib/

build: $(RUST_LIB)
	go build -o zk-verifier .

test: $(RUST_LIB)
	$(LD_PATH_VAR)=$(DYLIB_DIR) ZK_BASE_DIR=$(BASE_DIR) go test ./verifier/ -v

verify: $(RUST_LIB)
	$(LD_PATH_VAR)=$(DYLIB_DIR) RUST_LOG=info go run main.go

download-keys:
	bash scripts/download_keys.sh

clean:
	cd $(RUST_DIR) && cargo clean
	go clean ./...
	rm -f zk-verifier
