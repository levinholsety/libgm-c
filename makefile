SRC_DIR=src/main/
INC_DIR=include/
LIB_DIR=lib/
OBJ_DIR=obj/
BIN_DIR=bin/

CC=gcc
CFLAGS=-std=c11 -fPIC
LDFLAGS=-shared -s -L$(LIB_DIR)
LIBS=-lcrypto

ifeq ($(OS),Windows_NT)
	VALID_OS=1
	OS_OBJ_DIR=$(OBJ_DIR)win32/
	LIB_NAME=libgm.dll
else ifeq ($(shell uname),Linux)
	VALID_OS=1
	OS_OBJ_DIR=$(OBJ_DIR)linux/
	SO_NAME=libgm.so
	SO_NAME_A=$(SO_NAME).1
	LDFLAGS+= -Wl,-soname,$(SO_NAME_A)
	LIB_NAME=$(SO_NAME_A).0.0
endif

OBJECT_NAMES=sm2.o sm3.o sm4.o
OBJECTS=$(addprefix $(OS_OBJ_DIR),$(OBJECT_NAMES))

.PHONY:all
ifdef VALID_OS
all:$(BIN_DIR)$(LIB_NAME)
	@echo Completed.
else
all:
	@echo Unknown operating system.
endif

$(BIN_DIR)$(LIB_NAME):$(OBJECTS) | $(BIN_DIR)
	@echo Linking library $(LIB_NAME)...
	@$(CC) $(LDFLAGS) -o$(BIN_DIR)$(LIB_NAME) $(OBJECTS) $(LIBS)

$(OBJECTS):$(OS_OBJ_DIR)%.o:$(SRC_DIR)%.c $(INC_DIR)%.h $(INC_DIR)gm.h | $(OS_OBJ_DIR)
	@echo Compiling $<...
	@$(CC) $(CFLAGS) -c -o$@ $< -I$(INC_DIR)

$(OS_OBJ_DIR):
	@echo Creating directory $(OS_OBJ_DIR)...
	@mkdir -p $(OS_OBJ_DIR)

$(BIN_DIR):
	@echo Creating directory $(BIN_DIR)...
	@mkdir -p $(BIN_DIR)

FILES=$(wildcard $(BIN_DIR)$(LIB_NAME) $(OBJECTS))
DIRS=$(wildcard $(BIN_DIR) $(OS_OBJ_DIR))

.PHONY:clean
clean:
	@$(foreach FILE,$(FILES),\
	echo Removing file $(FILE)...;\
	rm -f $(FILE);\
	)
	@$(foreach DIR,$(DIRS),\
	echo Removing directory $(DIR)...;\
	rmdir -p --ignore-fail-on-non-empty $(DIR);\
	)