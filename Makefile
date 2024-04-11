lib_name=gm
build_dir=build
lib_dir=${build_dir}/lib
bin_dir=${build_dir}/bin
src_dir=src
src_files=common.c sm2.c sm3.c sm4.c

CFLAGS=-Iinclude -I${OPENSSL}/include -fPIC -Wall
test_cflags=-Iinclude -I${OPENSSL}/include -Wall

ifeq "$(OS)" "Windows_NT"
os=windows
lib_file_name=${lib_name}.dll
bin_file_ext=.exe
LDFLAGS=-shared -L${OPENSSL}/bin -lcrypto
test_ldflags=-L${OPENSSL}/bin -lcrypto
else ifeq ($(shell uname),Linux)
os=linux
lib_file_name=lib${lib_name}.so
CFLAGS+= -fvisibility=hidden
LDFLAGS=-shared -L${OPENSSL}/lib64 -lcrypto
test_ldflags=-L${OPENSSL}/lib64 -lcrypto
else ifeq ($(shell uname),Darwin)
os=darwin
lib_file_name=lib${lib_name}.dylib
CFLAGS+= -fvisibility=hidden
LDFLAGS=-dynamiclib -L${OPENSSL}/lib -lcrypto
test_ldflags=-L${OPENSSL}/lib -lcrypto
endif

.PHONY: build build_test clean

build:
	@echo "Building shared library..."
	@mkdir -p ${lib_dir}
	gcc -o${lib_dir}/${lib_file_name} ${CFLAGS} $(addprefix ${src_dir}/,${src_files}) ${LDFLAGS}
	@echo "Ok"

build_test:
	@echo "Building test..."
	@mkdir -p ${bin_dir}
	gcc -o${bin_dir}/test${bin_file_ext} ${test_cflags} $(addprefix ${src_dir}/,common.c sm2.c sm3.c sm4.c test.c) ${test_ldflags}
	@echo "Ok"

clean:
	@echo "Cleaning..."
	@rm -rf ${build_dir}
	@echo "Ok"