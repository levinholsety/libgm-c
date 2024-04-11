#include "sm4.h"
#include "string.h"

int sm4_generate_key(unsigned char *key)
{
    if (!key)
        return 0;
    BIGNUM *rnd = NULL;
    int success =
        (rnd = BN_new()) &&
        BN_rand(rnd, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) &&
        BN_bn2bin(rnd, key);
    if (rnd)
    {
        BN_free(rnd);
        rnd = NULL;
    }
    return success;
}

EVP_CIPHER_CTX *sm4_cipher_ctx_new(int mode, const unsigned char *key, const unsigned char *iv, int enc)
{
    if (!key)
        return NULL;
    const EVP_CIPHER *cipher;
    switch (mode)
    {
    case EVP_CIPH_ECB_MODE:
        cipher = EVP_sm4_ecb();
        break;
    case EVP_CIPH_CBC_MODE:
        cipher = EVP_sm4_cbc();
        break;
    default:
        return NULL;
    }
    EVP_CIPHER_CTX *ctx = NULL;
    int success =
        (ctx = EVP_CIPHER_CTX_new()) &&
        EVP_CipherInit(ctx, cipher, key, iv, enc) &&
        EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    if (!success && ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

void sm4_cipher_ctx_free(EVP_CIPHER_CTX *ctx)
{
    if (ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
}

int sm4_cipher_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *out_len, const unsigned char *in, int in_len)
{
    return ctx && out && out_len && in &&
           EVP_CipherUpdate(ctx, out, out_len, in, in_len);
}

int sm4_cipher_final(EVP_CIPHER_CTX *ctx, unsigned char *out, int *out_len)
{
    return ctx && out && out_len &&
           EVP_CipherFinal(ctx, out, out_len);
}

int sm4_crypt(unsigned char *out, int *out_len, const unsigned char *in, int in_len, int mode, const unsigned char *key, const unsigned char *iv, int enc)
{
    if (!out || !out_len || !in || !key)
        return 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int update_len      = 0;
    int final_len       = 0;
    int success =
        (ctx = sm4_cipher_ctx_new(mode, key, iv, enc)) &&
        sm4_cipher_update(ctx, out, &update_len, in, in_len) &&
        sm4_cipher_final(ctx, out + update_len, &final_len) &&
        (*out_len = update_len + final_len);
    if (ctx)
    {
        sm4_cipher_ctx_free(ctx);
        ctx = NULL;
    }
    return success;
}
