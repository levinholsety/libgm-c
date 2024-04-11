#include "common.h"
#include "openssl/err.h"
#include <string.h>

typedef int CIPHER_MODE;

unsigned long get_error(char *buf)
{
    unsigned long err = ERR_get_error();
    if (err == 0)
    {
        return 0;
    }
    ERR_error_string(err, buf);
    return err;
}

unsigned char *mem_new(unsigned char **data, size_t len)
{
    if ((*data = malloc(len)))
    {
        memset(*data, 0, len);
        return *data;
    }
    return NULL;
}

void mem_free(unsigned char **data)
{
    if (*data)
    {
        free(*data);
        *data = NULL;
    }
}