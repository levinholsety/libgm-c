@echo off
gcc -fPIC -shared -olibgm.dll sm2.c sm3.c sm4.c -lcrypto
