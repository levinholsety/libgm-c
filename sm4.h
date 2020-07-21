#include "openssl/evp.h"

#ifdef __cplusplus
extern "C"
{
#endif
    int GM_SM4_rand_key(unsigned char *key, unsigned char *iv);
    void GM_SM4_free(EVP_CIPHER_CTX *ctx);
    EVP_CIPHER_CTX *GM_SM4_new_encryptor(unsigned char *key, unsigned char *iv);
    EVP_CIPHER_CTX *GM_SM4_new_decryptor(unsigned char *key, unsigned char *iv);
    int GM_SM4_estimate_out_length(int inlen);
    int GM_SM4_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen, const unsigned char *in, int inlen);
    int GM_SM4_final(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen);
    int GM_SM4_encrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, unsigned char *key, unsigned char *iv);
    int GM_SM4_decrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, unsigned char *key, unsigned char *iv);
#ifdef __cplusplus
}
#endif