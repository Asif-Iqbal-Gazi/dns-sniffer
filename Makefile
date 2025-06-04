cc = gcc
PKG = libpcap

CFLAGS = -Wall -Wextra -Werror -Wold-style-definition -pedantic -std=c11 -ggdb `pkg-config --cflags $(PKG)`
LDFLAGS = `pkg-config --libs $(PKG)`

TARGET = dns_sniffer
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
