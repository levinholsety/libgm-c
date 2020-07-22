#include "sm3.h"

EVP_MD_CTX *GM_SM3_new()
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return NULL;
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sm3(), NULL))
    {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
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

int GM_SM3_final(EVP_MD_CTX *ctx, GM_SM3_MD md)
{
    return EVP_DigestFinal_ex(ctx, md, NULL);
}

int GM_SM3_digest(GM_SM3_MD md, const void *in, size_t inlen)
{
    EVP_MD_CTX *ctx = GM_SM3_new();
    if (!ctx)
    {
        return 0;
    }
    if (!GM_SM3_update(ctx, in, inlen))
    {
        GM_SM3_free(ctx);
        return 0;
    }
    if (!GM_SM3_final(ctx, md))
    {
        GM_SM3_free(ctx);
        return 0;
    }
    GM_SM3_free(ctx);
    return 1;
}
