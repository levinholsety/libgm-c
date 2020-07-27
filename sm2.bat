@echo off
gcc sm2_test.c test.c -o sm2_test.exe -L. -lgm
sm2_test.exe
del sm2_test.exe
