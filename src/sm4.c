#include "sm4.h"

RESULT GM_SM4_rand_key(GM_SM4_KEY key, GM_SM4_IV iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return RESULT_FAILURE;
    }
    if (EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, NULL, NULL, 0) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return RESULT_FAILURE;
    }
    if (EVP_CIPHER_CTX_rand_key(ctx, key) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return RESULT_FAILURE;
    }
    if (EVP_CIPHER_CTX_rand_key(ctx, iv) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return RESULT_FAILURE;
    }
    return RESULT_SUCCESS;
}

EVP_CIPHER_CTX *GM_SM4_new(const GM_SM4_KEY key, const GM_SM4_IV iv, int enc)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return NULL;
    }
    if (EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv, enc) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    return ctx;
}

EVP_CIPHER_CTX *GM_SM4_new_encryptor(const GM_SM4_KEY key, const GM_SM4_IV iv)
{
    return GM_SM4_new(key, iv, 1);
}

EVP_CIPHER_CTX *GM_SM4_new_decryptor(const GM_SM4_KEY key, const GM_SM4_IV iv)
{
    return GM_SM4_new(key, iv, 0);
}

void GM_SM4_free(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}

RESULT GM_SM4_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen, const unsigned char *in, int inlen)
{
    return GM_result(EVP_CipherUpdate(ctx, out, outlen, in, inlen));
}

RESULT GM_SM4_final(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen)
{
    return GM_result(EVP_CipherFinal_ex(ctx, out, outlen));
}

RESULT GM_SM4_crypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv, int enc)
{
    if (out == NULL)
    {
        if (outlen != NULL)
        {
            *outlen = inlen + EVP_MAX_BLOCK_LENGTH;
        }
        return RESULT_SUCCESS;
    }
    EVP_CIPHER_CTX *ctx = GM_SM4_new(key, iv, enc);
    if (ctx == NULL)
    {
        return RESULT_FAILURE;
    }
    int len;
    if (GM_SM4_update(ctx, out, &len, in, inlen) != RESULT_SUCCESS)
    {
        GM_SM4_free(ctx);
        return RESULT_FAILURE;
    }
    *outlen = len;
    if (GM_SM4_final(ctx, out + len, &len) != RESULT_SUCCESS)
    {
        GM_SM4_free(ctx);
        return RESULT_FAILURE;
    }
    *outlen += len;
    GM_SM4_free(ctx);
    return RESULT_SUCCESS;
}

RESULT GM_SM4_encrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv)
{
    return GM_SM4_crypt(out, outlen, in, inlen, key, iv, 1);
}

RESULT GM_SM4_decrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv)
{
    return GM_SM4_crypt(out, outlen, in, inlen, key, iv, 0);
}