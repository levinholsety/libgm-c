@echo off
gcc sm3_test.c sm3.c test.c -o sm3_test.exe -lcrypto
sm3_test.exe
del sm3_test.exe
