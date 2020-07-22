#include "openssl/evp.h"

#ifdef __cplusplus
extern "C"
{
#endif
    typedef unsigned char GM_SM3_MD[32];
    EVP_MD_CTX *GM_SM3_new();
    void GM_SM3_free(EVP_MD_CTX *ctx);
    int GM_SM3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen);
    int GM_SM3_final(EVP_MD_CTX *ctx, GM_SM3_MD md);
    int GM_SM3_digest(GM_SM3_MD md, const void *in, size_t inlen);
#ifdef __cplusplus
}
#endif