CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c99 -g
LDFLAGS =

SRC_DIR = src
BUILD_DIR = build

SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/dns.c \
       $(SRC_DIR)/tcp.c \
       $(SRC_DIR)/tls.c \
       $(SRC_DIR)/tls_record.c \
       $(SRC_DIR)/tls_hello.c \
       $(SRC_DIR)/tls_parse.c \
       $(SRC_DIR)/tls_cert.c \
       $(SRC_DIR)/sha256.c \
       $(SRC_DIR)/bignum.c \
       $(SRC_DIR)/p256.c \
       $(SRC_DIR)/rsa.c \
       $(SRC_DIR)/http.c

OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
TARGET = $(BUILD_DIR)/tcp2http

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
