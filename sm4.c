#include "sm4.h"

int GM_SM4_rand_key(GM_SM4_KEY key, GM_SM4_IV iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return 0;
    }
    if (!EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, NULL, NULL, 0))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (!EVP_CIPHER_CTX_rand_key(ctx, key))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (!EVP_CIPHER_CTX_rand_key(ctx, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    return 1;
}

EVP_CIPHER_CTX *gm_sm4_new(const GM_SM4_KEY key, const GM_SM4_IV iv, int enc)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return NULL;
    }
    if (!EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv, enc))
    {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    return ctx;
}

EVP_CIPHER_CTX *GM_SM4_new_encryptor(const GM_SM4_KEY key, const GM_SM4_IV iv)
{
    return gm_sm4_new(key, iv, 1);
}

EVP_CIPHER_CTX *GM_SM4_new_decryptor(const GM_SM4_KEY key, const GM_SM4_IV iv)
{
    return gm_sm4_new(key, iv, 0);
}

void GM_SM4_free(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}

int GM_SM4_suggested_out_length(int inlen)
{
    return inlen + EVP_MAX_BLOCK_LENGTH;
}

int GM_SM4_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen, const unsigned char *in, int inlen)
{
    return EVP_CipherUpdate(ctx, out, outlen, in, inlen);
}

int GM_SM4_final(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen)
{
    return EVP_CipherFinal_ex(ctx, out, outlen);
}

int gm_sm4_crypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv, int enc)
{
    EVP_CIPHER_CTX *ctx = gm_sm4_new(key, iv, enc);
    int len;
    if (!GM_SM4_update(ctx, out, &len, in, inlen))
    {
        GM_SM4_free(ctx);
        return 0;
    }
    *outlen = len;
    if (!GM_SM4_final(ctx, out + len, &len))
    {
        GM_SM4_free(ctx);
        return 0;
    }
    *outlen += len;
    GM_SM4_free(ctx);
    return 1;
}

int GM_SM4_encrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv)
{
    return gm_sm4_crypt(out, outlen, in, inlen, key, iv, 1);
}

int GM_SM4_decrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv)
{
    return gm_sm4_crypt(out, outlen, in, inlen, key, iv, 0);
}