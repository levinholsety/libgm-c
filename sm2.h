#include <string.h>
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/pem.h"

#ifdef __cplusplus
extern "C"
{
#endif
    EVP_PKEY *GM_SM2_new_key();
    EVP_PKEY *GM_SM2_import_key(const char *priv, const char *pub);
    void GM_SM2_free_key(EVP_PKEY *kp);
    char *GM_SM2_export_private(EVP_PKEY *kp);
    char *GM_SM2_export_public(EVP_PKEY *kp);
    int GM_SM2_encrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    int GM_SM2_decrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    int GM_SM2_sign(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    int GM_SM2_verify(const unsigned char *sig, size_t siglen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
#ifdef __cplusplus
}
#endif