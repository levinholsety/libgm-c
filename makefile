SRC_DIR=src/main/
SRC_DIRS=$(SRC_DIR)
INC_DIR=include/
BIN_DIR=bin/

CC=gcc
CFLAGS=-std=c11 -fPIC -c
LDFLAGS=-shared -s -Llib
LIBS=-lcrypto
BIN_NAME=gm
MAJOR_VERSION=1
MINOR_VERSION=0

include makefile.shared