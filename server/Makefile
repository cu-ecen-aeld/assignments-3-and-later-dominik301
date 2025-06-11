# Makefile for server/aesdsocket

# Variables
CC ?= $(CROSS_COMPILE)gcc
CFLAGS := -Wall -Werror
TARGET := aesdsocket
SRCS := aesdsocket.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean

# Default target
all: $(TARGET)

# Link step
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Compile step
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f $(TARGET) *.o
