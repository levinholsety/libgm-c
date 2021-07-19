ifeq ($(OS), Windows_NT)

bin_file = $(BIN_DIR)$(BIN_NAME).dll
os_obj_dir = $(OBJ_DIR)win32/

else ifeq ($(shell uname), Linux)

so_name = lib$(BIN_NAME).so
so_name_major = $(so_name).$(MAJOR_VERSION)
LDFLAGS += -Wl,-soname,$(so_name_major)
bin_file = $(BIN_DIR)$(so_name_major).$(MINOR_VERSION)
os_obj_dir = $(OBJ_DIR)linux/

else

unsupported_os = 1

endif

include Common.mk