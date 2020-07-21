#include "sm3.h"
#include "test.h"

int main()
{
    int mdlen;
    unsigned char *md = malloc(32);
    GM_SM3_digest(md, &mdlen, data, sizeof(data));
    print_hex(md, mdlen);
    free(md);
}