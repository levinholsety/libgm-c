@echo off
gcc sm3_test.c test.c -o sm3_test.exe -L. -lgm
sm3_test.exe
del sm3_test.exe
