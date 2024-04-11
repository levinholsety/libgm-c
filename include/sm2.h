#include "common.h"
#include "openssl/evp.h"

#define SM2_PUB_MAX_SIZE 65
#define SM2_PRI_MAX_SIZE 32
#define SM2_SIG_MAX_SIZE 72

// 签名上下文
typedef struct sm2_sig_ctx_st
{
    int is_pri;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx;
    EVP_MD_CTX *mctx;
} SM2_SIG_CTX;

#ifdef __cplusplus
extern "C"
{
#endif
    EXPORT int sm2_cipher_to_c1c3c2(unsigned char *out, int *out_len, const unsigned char *in, int in_len);
    EXPORT int sm2_sig_to_rs(unsigned char *out, int *out_len, const unsigned char *in, int in_len);
    EXPORT int sm2_key_pair_new(unsigned char *pub, size_t *pub_len, unsigned char *pri, size_t *pri_len);
    EXPORT int sm2_encrypt(unsigned char **out, size_t *out_len, const unsigned char *in, size_t in_len, const unsigned char *pub, size_t pub_len);
    EXPORT int sm2_decrypt(unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len, const unsigned char *pri, size_t pri_len);
    EXPORT int sm2_sign(unsigned char *sig, size_t *sig_len, const unsigned char *in, size_t in_len, const unsigned char *pri, size_t pri_len);
    EXPORT int sm2_verify(const unsigned char *sig, size_t sig_len, const unsigned char *in, size_t in_len, const unsigned char *pub, size_t pub_len);
    EXPORT SM2_SIG_CTX *sm2_sig_ctx_new(const unsigned char *key, size_t key_len, int is_pri);
    EXPORT void sm2_sig_ctx_free(SM2_SIG_CTX *ctx);
    EXPORT int sm2_sig_update(SM2_SIG_CTX *ctx, const unsigned char *in, size_t in_len);
    EXPORT int sm2_sig_sign(SM2_SIG_CTX *ctx, unsigned char *sig, size_t *sig_len);
    EXPORT int sm2_sig_verify(SM2_SIG_CTX *ctx, const unsigned char *sig, size_t sig_len);
#ifdef __cplusplus
}
#endif