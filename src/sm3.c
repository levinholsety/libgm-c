#include "sm3.h"

EVP_MD_CTX *GM_SM3_new()
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx != NULL)
    {
        if (EVP_DigestInit_ex(ctx, EVP_sm3(), NULL) <= 0)
        {
            EVP_MD_CTX_free(ctx);
            ctx = NULL;
        }
    }
    return ctx;
}

void GM_SM3_free(EVP_MD_CTX *ctx)
{
    if (ctx != NULL)
    {
        EVP_MD_CTX_free(ctx);
    }
}

RESULT GM_SM3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
    return EVP_DigestUpdate(ctx, in, inlen) > 0;
}

RESULT GM_SM3_final(EVP_MD_CTX *ctx, GM_SM3_MD md)
{
    return EVP_DigestFinal_ex(ctx, md, NULL) > 0;
}

RESULT GM_SM3_digest(GM_SM3_MD md, const void *in, size_t inlen)
{
    RESULT result   = RESULT_FAILURE;
    EVP_MD_CTX *ctx = GM_SM3_new();
    if (ctx != NULL)
    {
        if (GM_SM3_update(ctx, in, inlen) > 0 &&
            GM_SM3_final(ctx, md))
        {
            result = RESULT_SUCCESS;
        }
        GM_SM3_free(ctx);
    }
    return result;
}
