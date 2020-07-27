#include <string.h>
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/pem.h"
#include "api.h"

#ifdef __cplusplus
extern "C"
{
#endif
    API_DECLSPEC EVP_PKEY *GM_SM2_new_key();
    API_DECLSPEC EVP_PKEY *GM_SM2_import_key(const char *priv, const char *pub);
    API_DECLSPEC void GM_SM2_free_key(EVP_PKEY *kp);
    API_DECLSPEC char *GM_SM2_export_private(EVP_PKEY *kp);
    API_DECLSPEC char *GM_SM2_export_public(EVP_PKEY *kp);
    API_DECLSPEC int GM_SM2_encrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    API_DECLSPEC int GM_SM2_decrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    API_DECLSPEC int GM_SM2_sign(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    API_DECLSPEC int GM_SM2_verify(const unsigned char *sig, size_t siglen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
#ifdef __cplusplus
}
#endif