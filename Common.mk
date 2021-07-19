.PHONY: all clean

ifdef unsupported_os

all clean:
	@echo Unsupported operating system $(shell uname).

else

walk = $(if $(wildcard $(1)*), $(1) $(foreach path, $(wildcard $(1)*), $(call walk, $(path)/)))

inc = $(addprefix -I,$(INC_DIRS))
src_dirs = $(call walk, $(SRC_ROOT))
src_files = $(foreach dir, $(src_dirs), $(wildcard $(dir)*.c))
obj_dirs = $(patsubst $(SRC_ROOT)%, $(os_obj_dir)%, $(src_dirs))
obj_files = $(patsubst $(SRC_ROOT)%.c, $(os_obj_dir)%.o, $(src_files))
pre_dirs = $(obj_dirs)
pre_dirs += $(BIN_DIR)

all: $(bin_file)

$(bin_file): $(obj_files)
	@echo Linking library $@...
	@$(CC) $(LDFLAGS) -o$@ $^ $(LIBS)

$(obj_files): $(os_obj_dir)%.o: $(SRC_ROOT)%.c | $(pre_dirs)
	@echo Compiling $<...
	@$(CC) -c $(CFLAGS) -o$@ $< $(inc)

$(pre_dirs):
	@echo Creating directory $@...
	@mkdir -p $@

clean:
	@$(foreach file,$(wildcard $(bin_file) $(obj_files)),echo Removing file $(file)...;rm -f $(file);)
	@$(foreach dir,$(wildcard $(pre_dirs)),echo Removing directory $(dir)...;rmdir -p --ignore-fail-on-non-empty $(dir);)

endif
