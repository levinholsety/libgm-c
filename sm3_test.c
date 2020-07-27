#include "sm3.h"
#include "test.h"

int main()
{
    GM_SM3_MD md;
    GM_SM3_digest(md, data, sizeof(data));
    print_hex("sm3hash", md, sizeof(md));
}