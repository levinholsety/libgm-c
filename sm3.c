#include "sm3.h"

EVP_MD_CTX *GM_SM3_new()
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sm3());
    return ctx;
}

void GM_SM3_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_free(ctx);
}

int GM_SM3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
    return EVP_DigestUpdate(ctx, in, inlen);
}

int GM_SM3_final(EVP_MD_CTX *ctx, unsigned char *out, unsigned int *outlen)
{
    return EVP_DigestFinal(ctx, out, outlen);
}

int GM_SM3_digest(unsigned char *out, unsigned int *outlen, const void *in, size_t inlen)
{
    EVP_MD_CTX *ctx = GM_SM3_new();
    if (!GM_SM3_update(ctx, in, inlen))
    {
        GM_SM3_free(ctx);
        return 0;
    }
    if (!GM_SM3_final(ctx, out, outlen))
    {
        GM_SM3_free(ctx);
        return 0;
    }
    GM_SM3_free(ctx);
    return 1;
}
