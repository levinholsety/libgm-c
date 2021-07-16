.PHONY: all clean

ifdef UNSUPPORTED_OS

all clean:
	@echo Unsupported operating system $(shell uname).

else

INC = $(addprefix -I,$(INC_DIRS))
SRC_FILES = $(foreach DIR, $(SRC_DIRS), $(wildcard $(DIR)*.c))
OBJ_DIRS = $(patsubst $(SRC_ROOT)%, $(OBJ_DIR)%, $(SRC_DIRS))
OBJ_FILES = $(patsubst $(SRC_ROOT)%.c, $(OBJ_DIR)%.o, $(SRC_FILES))
PRE_DIRS = $(OBJ_DIRS)
PRE_DIRS += $(BIN_DIR)

all: $(BIN_FILE)

$(BIN_FILE): $(OBJ_FILES)
	@echo Linking library $@...
	@$(CC) $(LDFLAGS) -o$@ $^ $(LIBS)

$(OBJ_FILES): $(OBJ_DIR)%.o: $(SRC_ROOT)%.c | $(PRE_DIRS)
	@echo Compiling $<...
	@$(CC) -c $(CFLAGS) -o$@ $< $(INC)

$(PRE_DIRS):
	@echo Creating directory $@...
	@mkdir -p $@

clean:
	@$(foreach FILE,$(wildcard $(BIN_FILE) $(OBJ_FILES)),echo Removing file $(FILE)...;rm -f $(FILE);)
	@$(foreach DIR,$(wildcard $(PRE_DIRS)),echo Removing directory $(DIR)...;rmdir -p --ignore-fail-on-non-empty $(DIR);)

endif
