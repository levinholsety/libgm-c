@echo off
gcc sm4_test.c sm4.c test.c -o sm4_test.exe -lcrypto
sm4_test.exe
del sm4_test.exe
