#include "test.h"

const unsigned char data[27] = "abcdefghijklmnopqrstuvwxyz";

void print_hex(const char *name, const unsigned char *data, size_t size)
{
    printf("%s=[%d]", name, size);
    for (size_t i = 0; i < size; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void print_str(const char *name, const char *str)
{
    printf("%s=[%d]%s\n", name, strlen(str), str);
}
