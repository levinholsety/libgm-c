ifeq ($(OS), Windows_NT)

BIN_FILE = $(BIN_DIR)$(BIN_NAME).dll
OBJ_DIR = obj/win32/

else ifeq ($(shell uname), Linux)

SO_NAME = lib$(BIN_NAME).so
SO_NAME_MAJOR = $(SO_NAME).$(MAJOR_VERSION)
LDFLAGS += -Wl,-soname,$(SO_NAME_MAJOR)
BIN_FILE = $(BIN_DIR)$(SO_NAME_MAJOR).$(MINOR_VERSION)
OBJ_DIR = obj/linux/

else

UNSUPPORTED_OS = 1

endif

include Common.mk