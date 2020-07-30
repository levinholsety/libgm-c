#include "openssl/evp.h"

#ifdef DLL_EXPORT
#define API __declspec(dllexport)
#else
#define API __declspec(dllimport)
#endif

typedef unsigned char GM_SM3_MD[32];

#ifdef __cplusplus
extern "C"
{
#endif
    API EVP_MD_CTX *GM_SM3_new();
    API void GM_SM3_free(EVP_MD_CTX *ctx);
    API int GM_SM3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen);
    API int GM_SM3_final(EVP_MD_CTX *ctx, GM_SM3_MD md);
    API int GM_SM3_digest(GM_SM3_MD md, const void *in, size_t inlen);
#ifdef __cplusplus
}
#endif