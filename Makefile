# Compiler
CC      := cc
CFLAGS  := -std=c99 -Wall -Wextra -O3 -MMD -MP
LDFLAGS :=

# Directories
SRC_DIR   := src
BUILD_DIR := build
BIN_DIR   := bin

# Final executable
TARGET := $(BIN_DIR)/zonefast

# Automatically find all source files
SRCS := $(wildcard $(SRC_DIR)/*.c)

# Convert src/foo.c → build/foo.o
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Default target
all: $(TARGET)

# Link step
$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Compile step
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

.PHONY: all clean

# Include auto-generated dependency files
-include $(OBJS:.o=.d)

