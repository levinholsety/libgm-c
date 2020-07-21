#include <string.h>
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/pem.h"

#ifdef __cplusplus
extern "C"
{
#endif
    void GM_SM2_free_key(EVP_PKEY *pkey);
    void GM_SM2_free(EVP_PKEY_CTX *ctx);
    EVP_PKEY *GM_SM2_new_key();
    EVP_PKEY *GM_SM2_import_key(const char *priv, const char *pub);
    char *GM_SM2_export_private(EVP_PKEY *pkey);
    char *GM_SM2_export_public(EVP_PKEY *pkey);
    EVP_PKEY_CTX *GM_SM2_new_encryptor(size_t *estoutlen, size_t inlen, EVP_PKEY *pkey);
    EVP_PKEY_CTX *GM_SM2_new_decryptor(size_t *estoutlen, size_t inlen, EVP_PKEY *pkey);
    EVP_PKEY_CTX *GM_SM2_new_signer(size_t *estoutlen, size_t inlen, EVP_PKEY *pkey);
    int GM_SM2_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
    int GM_SM2_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
    int GM_SM2_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *in, size_t inlen);
    int GM_SM2_verify(const unsigned char *sig, size_t siglen, const unsigned char *in, size_t inlen, EVP_PKEY *pkey);
#ifdef __cplusplus
}
#endif