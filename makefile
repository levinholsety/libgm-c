SRC_ROOT = src/main/
INC_DIRS = include/
BIN_DIR = bin/

CC = gcc
CFLAGS = -std=c11 -fPIC
LDFLAGS = -shared -s -Llib
LIBS = -lcrypto
BIN_NAME = gm
MAJOR_VERSION = 1
MINOR_VERSION = 0

SRC_DIRS = $(SRC_ROOT)

include Shared.mk