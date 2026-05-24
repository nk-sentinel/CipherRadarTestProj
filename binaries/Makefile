# Test fixtures: compiled binaries that exercise cradar's binary-scanning
# (Pass 3 / YARA-X) detectors. Each binary embeds specific crypto material
# in its .rodata segment so the YARA-X rules under
# scanner/yara-rules/*.yar (cradar repo) can be tested against realistic
# compiled artifacts.
#
# The built artifacts in dist/ are committed alongside this Makefile so
# that running cradar scans against this test project works out-of-the-box
# without requiring gcc. Run `make` only when you change a source file or
# want to regenerate from scratch.
#
# Built on:
#   gcc 13.x (Ubuntu 24.04 LTS)
#   x86_64 ELF
#
# Cross-platform fixtures (darwin/arm64, windows/amd64) are not in this
# Makefile yet; YARA rules in Sub-PR B match on bytes not OS, so a single
# linux/amd64 fixture covers most rule development. Add cross targets when
# rule coverage requires platform-specific signatures.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -fno-stack-protector -s
LDFLAGS ?=

SRCS    := $(wildcard src/*.c)
BINS    := $(patsubst src/%.c,dist/%,$(SRCS))

.PHONY: all clean list

all: $(BINS)

dist/%: src/%.c
	@mkdir -p dist
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	@echo "built $@ ($(shell stat -c%s $@) bytes)"

clean:
	rm -rf dist/

# Convenience: print what each fixture is for.
list:
	@for f in $(SRCS); do \
	  printf "%-25s " "$$(basename $$f .c)"; \
	  head -3 $$f | tail -1 | sed 's@^ \* @@'; \
	done
