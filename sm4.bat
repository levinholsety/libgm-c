@echo off
gcc sm4_test.c test.c -osm4_test.exe -L. -lcrypto -lgm
sm4_test.exe
del sm4_test.exe
