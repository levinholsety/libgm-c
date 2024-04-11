#include "common.h"
#include "openssl/evp.h"

#define SM3_MD_SIZE 32

#ifdef __cplusplus
extern "C"
{
#endif
    EXPORT int sm3_digest(unsigned char *md, unsigned int *md_len, const unsigned char *in, size_t in_len);
    EXPORT EVP_MD_CTX *sm3_md_ctx_new();
    EXPORT void sm3_md_ctx_free(EVP_MD_CTX *ctx);
    EXPORT int sm3_md_update(EVP_MD_CTX *ctx, const unsigned char *in, size_t in_len);
    EXPORT int sm3_md_final(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *md_len);
#ifdef __cplusplus
}
#endif