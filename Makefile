SHELL=/usr/bin/env bash

all: build
.PHONY: all

unexport GOFLAGS

GOCC?=go

CLEAN:=
BINS:=

## FFI

FFI_PATH:=extern/filecoin-ffi/
FFI_DEPS:=.install-filcrypto
FFI_DEPS:=$(addprefix $(FFI_PATH),$(FFI_DEPS))

$(FFI_DEPS): build/.filecoin-ffi-install ;

# dummy file that marks the last time the filecoin-ffi project was built
build/.filecoin-ffi-install: $(FFI_PATH)
	$(MAKE) -C $(FFI_PATH) $(FFI_DEPS:$(FFI_PATH)%=%)
	@touch $@

SUBMODULES+=$(FFI_PATH)
BUILD_DEPS+=build/.filecoin-ffi-install
CLEAN+=build/.filecoin-ffi-install

$(SUBMODULES): build/.update-submodules ;

# dummy file that marks the last time submodules were updated
build/.update-submodules:
	git submodule update --init --recursive
	touch $@

CLEAN+=build/.update-submodules

# build and install any upstream dependencies, e.g. filecoin-ffi
deps: $(BUILD_DEPS)
.PHONY: deps

MODULES+=$(FFI_PATH)
BUILD_DEPS+=build/.filecoin-ffi-install
CLEAN+=build/.filecoin-ffi-install


clean:
	rm -rf $(CLEAN) $(BINS)
	-$(MAKE) -C $(FFI_PATH) clean
.PHONY: clean

offline-wallet: $(BUILD_DEPS)
	rm -f offline-wallet
	$(GOCC) build $(GOFLAGS) -o offline-wallet ./cmd/
.PHONY: offline-wallet
BINS+=offline-wallet

build: offline-wallet
.PHONY: build