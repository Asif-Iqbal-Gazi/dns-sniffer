# Compiler and Package Config
cc = gcc
PKG = libpcap

# Directories
SRC_DIR = src
BIN_DIR = bin
INCLUDE_DIR = include

# Source Files
SRC_CURRENT = $(SRC_DIR)/dns_spoofer.c
SRC_STATIC = $(SRC_DIR)/dns_spoofer_static.c

# Output Binaries
BIN_CURRENT = $(BIN_DIR)/dns_spoofer
BIN_STATIC = $(BIN_DIR)/dns_spoofer_static

# Compilation Flags
CFLAGS = -Wall -Wextra -Werror -Wold-style-definition -pedantic -std=gnu11 -ggdb $(shell pkg-config --cflags $(PKG)) -I$(INCLUDE_DIR)
LDFLAGS = $(shell pkg-config --libs $(PKG))

# Common header file
COMMON_HEADERS = $(INCLUDE_DIR)/dns_protocol.h

# Default Traget - Builds both executables
all: $(BIN_STATIC) $(BIN_CURRENT)

# Rule for creating the bin directory
$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Build Rules:
$(BIN_STATIC) : $(SRC_STATIC) $(COMMON_HEADERS) | $(BIN_DIR)
	@echo "Compiling $(SRC_STATIC) to $(BIN_STATIC)"
	$(cc) $(CFLAGS) $(SRC_STATIC) -o $(BIN_STATIC) $(LDFLAGS)

$(BIN_CURRENT) : $(SRC_CURRENT)
	@echo "Compiling $(SRC_CURRENT) to $(BIN_CURRENT)"
	$(cc) $(CFLAGS) $(SRC_CURRENT) -o $(BIN_CURRENT) $(LDFLAGS)

# Clean Target
clean:
	@echo "Cleaning compiled bianries..."
	rm -f $(BIN_STATIC) $(BIN_CURRENT)
	-rmdir $(BIN_DIR) 2>/dev/null || true

.PHONY: all clean
