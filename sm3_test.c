#include "sm3.h"
#include "test.h"

int main()
{
    unsigned char md[32];
    GM_SM3_digest(md, data, sizeof(data));
    print_hex("sm3hash", md, 32);
}