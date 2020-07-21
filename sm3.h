#include "openssl/evp.h"

#ifdef __cplusplus
extern "C"
{
#endif
    void GM_SM3_free(EVP_MD_CTX *ctx);
    EVP_MD_CTX *GM_SM3_new();
    int GM_SM3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen);
    int GM_SM3_final(EVP_MD_CTX *ctx, unsigned char *out, unsigned int *outlen);
    int GM_SM3_digest(unsigned char *out, unsigned int *outlen, const void *in, size_t inlen);
#ifdef __cplusplus
}
#endif