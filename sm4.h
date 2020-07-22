#include "openssl/evp.h"

#ifdef __cplusplus
extern "C"
{
#endif
    typedef unsigned char GM_SM4_KEY[16];
    typedef unsigned char GM_SM4_IV[16];
    int GM_SM4_rand_key(GM_SM4_KEY key, GM_SM4_IV iv);
    EVP_CIPHER_CTX *GM_SM4_new_encryptor(const GM_SM4_KEY key, const GM_SM4_IV);
    EVP_CIPHER_CTX *GM_SM4_new_decryptor(const GM_SM4_KEY key, const GM_SM4_IV);
    void GM_SM4_free(EVP_CIPHER_CTX *ctx);
    int GM_SM4_suggested_out_length(int inlen);
    int GM_SM4_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen, const unsigned char *in, int inlen);
    int GM_SM4_final(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen);
    int GM_SM4_encrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV);
    int GM_SM4_decrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV);
#ifdef __cplusplus
}
#endif