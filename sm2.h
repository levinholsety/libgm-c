#include "openssl/evp.h"

#ifdef DLL_EXPORT
#define API __declspec(dllexport)
#else
#define API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C"
{
#endif
    API EVP_PKEY *GM_SM2_new_key();
    API EVP_PKEY *GM_SM2_import_key(const char *priv, const char *pub);
    API void GM_SM2_free_key(EVP_PKEY *kp);
    API char *GM_SM2_export_private(EVP_PKEY *kp);
    API char *GM_SM2_export_public(EVP_PKEY *kp);
    API int GM_SM2_encrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    API int GM_SM2_decrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    API int GM_SM2_sign(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    API int GM_SM2_verify(const unsigned char *sig, size_t siglen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
#ifdef __cplusplus
}
#endif