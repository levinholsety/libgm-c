#include "common.h"
#include "openssl/evp.h"

#define SM4_MODE_ECB 1
#define SM4_MODE_CBC 2
#define SM4_BLOCK_SIZE 16
#define sm4_enc_max_size(size) size + SM4_BLOCK_SIZE
#define sm4_dec_max_size(size) size
#define sm4_encrypt_ecb(out, out_len, in, in_len, key) sm4_crypt(out, out_len, in, in_len, EVP_CIPH_ECB_MODE, key, NULL, 1)
#define sm4_decrypt_ecb(out, out_len, in, in_len, key) sm4_crypt(out, out_len, in, in_len, EVP_CIPH_ECB_MODE, key, NULL, 0)
#define sm4_encrypt_cbc(out, out_len, in, in_len, key, iv) sm4_crypt(out, out_len, in, in_len, EVP_CIPH_CBC_MODE, key, iv, 1)
#define sm4_decrypt_cbc(out, out_len, in, in_len, key, iv) sm4_crypt(out, out_len, in, in_len, EVP_CIPH_CBC_MODE, key, iv, 0)

#ifdef __cplusplus
extern "C"
{
#endif
    EXPORT int sm4_generate_key(unsigned char *key);
    EXPORT int sm4_crypt(unsigned char *out, int *out_len, const unsigned char *in, int in_len, int mode, const unsigned char *key, const unsigned char *iv, int enc);
    EXPORT EVP_CIPHER_CTX *sm4_cipher_ctx_new(int mode, const unsigned char *key, const unsigned char *iv, int enc);
    EXPORT void sm4_cipher_ctx_free(EVP_CIPHER_CTX *ctx);
    EXPORT int sm4_cipher_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *out_len, const unsigned char *in, int in_len);
    EXPORT int sm4_cipher_final(EVP_CIPHER_CTX *ctx, unsigned char *out, int *out_len);
#ifdef __cplusplus
}
#endif