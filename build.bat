@echo off
gcc -fPIC -shared -olibgm.dll -DDLL_EXPORT sm2.c sm3.c sm4.c -L. -lcrypto
