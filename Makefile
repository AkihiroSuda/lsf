# Portions from https://github.com/lima-vm/lima/blob/v0.11.3/Makefile (Apache License 2.0)

# Files are installed under $(DESTDIR)/$(PREFIX)
PREFIX ?= /usr/local
DEST := $(shell echo "$(DESTDIR)/$(PREFIX)" | sed 's:///*:/:g; s://*$$::')

GO ?= go

PACKAGE := github.com/AkihiroSuda/lsf

VERSION=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
VERSION_TRIMMED := $(VERSION:v%=%)

GO_BUILD := CGO_ENABLED=0 $(GO) build -ldflags="-s -w -X $(PACKAGE)/pkg/version.Version=$(VERSION)"

.PHONY: all
all: binaries

.PHONY: binaries
binaries: clean _output/bin/lsf
	
.PHONY: _output/bin/lsf
_output/bin/lsf:
	$(GO_BUILD) -o $@ ./cmd/lsf

.PHONY: clean
clean:
	rm -rf _output
