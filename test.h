#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

    extern const unsigned char data[27];

    void print_hex(const unsigned char *data, size_t size);
    void print_str(const char *str);
#ifdef __cplusplus
}
#endif