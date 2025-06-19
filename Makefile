cc = gcc
PKG = libpcap

CFLAGS = -Wall -Wextra -Werror -Wold-style-definition -pedantic -std=gnu11 -ggdb `pkg-config --cflags $(PKG)` -Iinclude
LDFLAGS = `pkg-config --libs $(PKG)`

SRC_DIR = src
BIN_DIR = bin
TARGET = $(BIN_DIR)/dns_sniffer

SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(SRC)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
