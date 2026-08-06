# Detect an LLVM config binary: prefer the versioned one, fall back to generic.
LLVM_CONFIG ?= $(firstword \
    $(shell command -v llvm-config-20 2>/dev/null) \
    $(shell command -v llvm-config    2>/dev/null))
export LLVM_CONFIG

.PHONY: all clean test

all:
	@if [ -n "$(LLVM_CONFIG)" ]; then \
		echo "Building clang-ast-parser with $(LLVM_CONFIG)"; \
		$(MAKE) -C clang-ast-parser LLVM_CONFIG="$(LLVM_CONFIG)"; \
	else \
		echo "Warning: no llvm-config found; skipping clang-ast-parser." \
		     "Install llvm-dev (or llvm-20-dev) to enable C++ allocsite support."; \
	fi

clean:
	$(MAKE) -C clang-ast-parser clean 2>/dev/null || true

test:
	@if [ -n "$(LLVM_CONFIG)" ]; then \
		$(MAKE) -C clang-ast-parser test LLVM_CONFIG="$(LLVM_CONFIG)"; \
	else \
		echo "Warning: no llvm-config found; skipping clang-ast-parser tests."; \
	fi
