win32:bin/libgm.dll

bin/libgm.dll:include/gm.h include/sm2.h src/main/sm2.c include/sm3.h src/main/sm3.c include/sm4.h src/main/sm4.c
	gcc -std=c11 -shared -fPIC -s -o./bin/libgm.dll -Iinclude src/main/*.c -Llib -lcrypto
