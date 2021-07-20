SRC_ROOT = src/main
INC_DIRS = include
OBJ_ROOT = obj
BIN_ROOT = bin
BIN_NAME = gm
MAJOR_VERSION = 1
MINOR_VERSION = 0

CC = gcc
CFLAGS = -std=c11 -fPIC
LDFLAGS = -shared -s -Llib
LIBS = -lcrypto

get_src_dirs = $(if $(wildcard $(1)/*.c),$(1)) $(foreach path,$(wildcard $(1)/*),$(call get_src_dirs,$(path)))
src_dirs = $(call get_src_dirs,$(SRC_ROOT))
src_files = $(foreach dir,$(src_dirs),$(wildcard $(dir)/*.c))

ifeq ($(OS),Windows_NT)
obj_dir = $(OBJ_ROOT)/win32
bin_dir = $(BIN_ROOT)/win32
bin_file = $(bin_dir)/$(BIN_NAME).dll
else ifeq ($(shell uname),Linux)
obj_dir = $(OBJ_ROOT)/linux
bin_dir = $(BIN_ROOT)/linux
LDFLAGS += -Wl,-soname,lib$(BIN_NAME).so.$(MAJOR_VERSION)
bin_file = $(bin_dir)/lib$(BIN_NAME).so.$(MAJOR_VERSION).$(MINOR_VERSION)
endif

obj_dirs = $(patsubst $(SRC_ROOT)%,$(obj_dir)%,$(src_dirs))
obj_files = $(patsubst $(SRC_ROOT)%.c,$(obj_dir)%.o,$(src_files))

.PHONY:all clean

all:$(bin_file)

$(bin_file):$(obj_files)|$(bin_dir)
	@echo Linking $@...
	@$(CC) $(LDFLAGS) -o$@ $^ $(LIBS)

$(bin_dir):
	@echo Making directory $@...
	@mkdir -p $@

$(obj_files):$(obj_dir)%.o:$(SRC_ROOT)%.c|$(obj_dirs)
	@echo Compiling $<...
	@$(CC) -c $(CFLAGS) -o$@ $< $(foreach dir,$(INC_DIRS),-I$(dir))

$(obj_dirs):
	@echo Making directory $@...
	@mkdir -p $@

del_dirs = $(wildcard $(obj_dir) $(bin_dir))
del_roots = $(wildcard $(OBJ_ROOT) $(BIN_ROOT))

clean:
	@$(if $(del_dirs),$(foreach dir,$(del_dirs),echo Removing directory $(dir)...;) rm -rf $(del_dirs);)
	@$(if $(del_roots),$(foreach dir,$(del_roots),echo Removing directory $(dir)...;) rmdir -p --ignore-fail-on-non-empty $(del_roots);)