#include "openssl/evp.h"
#include "api.h"

typedef unsigned char GM_SM3_MD[32];

#ifdef __cplusplus
extern "C"
{
#endif
    API_DECLSPEC EVP_MD_CTX *GM_SM3_new();
    API_DECLSPEC void GM_SM3_free(EVP_MD_CTX *ctx);
    API_DECLSPEC int GM_SM3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen);
    API_DECLSPEC int GM_SM3_final(EVP_MD_CTX *ctx, GM_SM3_MD md);
    API_DECLSPEC int GM_SM3_digest(GM_SM3_MD md, const void *in, size_t inlen);
#ifdef __cplusplus
}
#endif