#include "sm3.h"
#include "openssl/evp.h"

int GM_SM3_digest(unsigned char *md, const void *data, size_t data_len)
{
    int ok          = FAILURE;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx)
    {
        unsigned int md_len;
        if (EVP_DigestInit_ex(ctx, EVP_sm3(), NULL) == SUCCESS &&
            EVP_DigestUpdate(ctx, data, data_len) == SUCCESS &&
            EVP_DigestFinal_ex(ctx, md, &md_len) == SUCCESS &&
            md_len == 32)
        {
            ok = SUCCESS;
        }
        EVP_MD_CTX_free(ctx);
        ctx = NULL;
    }
    return ok;
}

int GM_SM3_digest_file(unsigned char *md, FILE *file)
{
    int ok          = FAILURE;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx)
    {
        if (EVP_DigestInit_ex(ctx, EVP_sm3(), NULL) == SUCCESS)
        {
            unsigned char buf[0x2000];
            size_t buf_len;
            int update_ok = SUCCESS;
            while ((buf_len = fread(buf, 1, sizeof(buf), file)) > 0)
            {
                if (EVP_DigestUpdate(ctx, buf, buf_len) != SUCCESS)
                {
                    update_ok = FAILURE;
                    break;
                }
            }
            unsigned int md_len;
            if (update_ok &&
                EVP_DigestFinal_ex(ctx, md, &md_len) == SUCCESS &&
                md_len == 32)
            {
                ok = SUCCESS;
            }
        }
        EVP_MD_CTX_free(ctx);
        ctx = NULL;
    }
    return ok;
}