#include "sm3.h"

EVP_MD_CTX *sm3_md_ctx_new()
{
    EVP_MD_CTX *ctx = NULL;
    int success =
        (ctx = EVP_MD_CTX_new()) &&
        EVP_DigestInit(ctx, EVP_sm3());
    if (!success)
    {
        sm3_md_ctx_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

void sm3_md_ctx_free(EVP_MD_CTX *ctx)
{
    if (ctx)
    {
        EVP_MD_CTX_free(ctx);
        ctx = NULL;
    }
}

int sm3_md_update(EVP_MD_CTX *ctx, const unsigned char *in, size_t in_len)
{
    return ctx && in &&
           EVP_DigestUpdate(ctx, in, in_len);
}

int sm3_md_final(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *md_len)
{
    return ctx && md && md_len &&
           EVP_DigestFinal(ctx, md, md_len);
}

int sm3_digest(unsigned char *md, unsigned int *md_len, const unsigned char *in, size_t in_len)
{
    if (!md || !md_len || !in)
        return 0;
    EVP_MD_CTX *ctx = NULL;
    int success =
        (ctx = sm3_md_ctx_new()) &&
        sm3_md_update(ctx, in, in_len) &&
        sm3_md_final(ctx, md, md_len);
    if (ctx)
    {
        sm3_md_ctx_free(ctx);
        ctx = NULL;
    }
    return success;
}
