#include "test.h"

const unsigned char data[27] = "abcdefghijklmnopqrstuvwxyz";

void print_hex(const unsigned char *data, size_t size)
{
    printf("[%d]", size);
    for (size_t i = 0; i < size; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void print_str(const char *str)
{
    printf("[%d]%s\n", strlen(str), str);
}
