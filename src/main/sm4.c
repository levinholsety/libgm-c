#include "sm4.h"
#include "openssl/evp.h"

int GM_SM4_crypt(unsigned char *out, int *out_len, const unsigned char *in, int in_len, const unsigned char *key, const unsigned char *iv, int enc)
{
    int ok              = FAILURE;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx)
    {
        int len1 = 0;
        int len2 = 0;
        if (EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv, enc) == SUCCESS &&
            EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7) == SUCCESS &&
            EVP_CipherUpdate(ctx, out, &len1, in, in_len) == SUCCESS &&
            EVP_CipherFinal_ex(ctx, out + len1, &len2) == SUCCESS)
        {
            *out_len = len1 + len2;
            ok       = SUCCESS;
        }
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    return ok;
}

int GM_SM4_crypt_file(FILE *dst, FILE *src, const unsigned char *key, const unsigned char *iv, int enc)
{
    int ok              = FAILURE;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx)
    {
        if (EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv, enc) == SUCCESS)
        {
            EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
            unsigned char buf_in[0x2000];
            unsigned char buf_out[0x2000 + 16];
            int buf_in_len;
            int buf_out_len;
            int update_ok = SUCCESS;
            while ((buf_in_len = fread(buf_in, 1, sizeof(buf_in), src)) > 0)
            {
                if (!(EVP_CipherUpdate(ctx, buf_out, &buf_out_len, buf_in, buf_in_len) == SUCCESS &&
                      fwrite(buf_out, buf_out_len, 1, dst) > 0))
                {
                    update_ok = FAILURE;
                    break;
                }
            }
            if (update_ok &&
                EVP_CipherFinal_ex(ctx, buf_out, &buf_out_len) == SUCCESS &&
                fwrite(buf_out, buf_out_len, 1, dst) > 0)
            {
                ok = SUCCESS;
            }
        }
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    return ok;
}