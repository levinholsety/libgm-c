@echo off
gcc sm2_test.c sm2.c test.c -o sm2_test.exe -lcrypto
sm2_test.exe
del sm2_test.exe
