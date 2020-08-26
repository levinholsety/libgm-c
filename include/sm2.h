#include "gm.h"
#include "openssl/evp.h"

#ifdef __cplusplus
extern "C"
{
#endif
    GM_API EVP_PKEY *GM_SM2_new_key();
    GM_API EVP_PKEY *GM_SM2_import_key(const char *priv, const char *pub);
    GM_API void GM_SM2_free_key(EVP_PKEY *kp);
    GM_API char *GM_SM2_export_private(EVP_PKEY *kp);
    GM_API char *GM_SM2_export_public(EVP_PKEY *kp);
    GM_API RESULT GM_SM2_encrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    GM_API RESULT GM_SM2_decrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    GM_API RESULT GM_SM2_sign(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    GM_API RESULT GM_SM2_verify(const unsigned char *sig, size_t siglen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
#ifdef __cplusplus
}
#endif