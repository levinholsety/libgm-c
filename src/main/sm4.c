#include "sm4.h"

int GM_SM4_rand_key(GM_SM4_KEY key, GM_SM4_IV iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 0;
    int result = (EVP_CipherInit_ex(ctx, EVP_sm4_cbc(), NULL, NULL, NULL, 0) > 0 &&
                  EVP_CIPHER_CTX_rand_key(ctx, key) > 0 &&
                  EVP_CIPHER_CTX_rand_key(ctx, iv) > 0);
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

EVP_CIPHER_CTX *GM_SM4_new(const GM_SM4_KEY key, const GM_SM4_IV iv, int enc)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return NULL;
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

int GM_SM4_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen, const unsigned char *in, int inlen)
{
    return EVP_CipherUpdate(ctx, out, outlen, in, inlen);
}

int GM_SM4_final(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen)
{
    return EVP_CipherFinal_ex(ctx, out, outlen);
}

int GM_SM4_crypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv, int enc)
{
    if (out == NULL)
    {
        if (outlen == NULL) return 0;
        *outlen = inlen + EVP_MAX_BLOCK_LENGTH;
        return 1;
    }
    int len1, len2;
    EVP_CIPHER_CTX *ctx = GM_SM4_new(key, iv, enc);
    if (ctx == NULL) return 0;
    int result = (GM_SM4_update(ctx, out, &len1, in, inlen) > 0 &&
                  GM_SM4_final(ctx, out + len1, &len2) > 0);
    if (result) *outlen = len1 + len2;
    GM_SM4_free(ctx);
    return result;
}

int GM_SM4_encrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv)
{
    return GM_SM4_crypt(out, outlen, in, inlen, key, iv, 1);
}

int GM_SM4_decrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv)
{
    return GM_SM4_crypt(out, outlen, in, inlen, key, iv, 0);
}