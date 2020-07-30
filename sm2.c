#include "sm2.h"
#include "openssl/ec.h"
#include "openssl/pem.h"
#include <string.h>

void GM_SM2_free_key(EVP_PKEY *kp)
{
    EVP_PKEY_free(kp);
}

EVP_PKEY *GM_SM2_new_key()
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_paramgen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_sm2);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY *kp = NULL;
    EVP_PKEY_keygen(ctx, &kp);
    EVP_PKEY_CTX_free(ctx);
    return kp;
}

char *gm_sm2_pem_encode(EVP_PKEY *kp, int priv)
{
    EC_KEY *key = EVP_PKEY_get0_EC_KEY(kp);
    BIO *out    = BIO_new(BIO_s_mem());
    if (priv)
    {
        PEM_write_bio_ECPrivateKey(out, key, NULL, NULL, 0, NULL, NULL);
    }
    else
    {
        PEM_write_bio_EC_PUBKEY(out, key);
    }
    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(out, &mem);
    char *keystr = malloc(mem->length + 1);
    memcpy(keystr, mem->data, mem->length);
    keystr[mem->length] = 0;
    BIO_free(out);
    return keystr;
}

char *GM_SM2_export_private(EVP_PKEY *kp)
{
    return gm_sm2_pem_encode(kp, 1);
}

char *GM_SM2_export_public(EVP_PKEY *kp)
{
    return gm_sm2_pem_encode(kp, 0);
}

EVP_PKEY *GM_SM2_import_key(const char *priv, const char *pub)
{
    EVP_PKEY *kp = EVP_PKEY_new();
    if (priv)
    {
        BIO *in     = BIO_new_mem_buf(priv, strlen(priv));
        EC_KEY *key = NULL;
        PEM_read_bio_ECPrivateKey(in, &key, NULL, NULL);
        BIO_free(in);
        EVP_PKEY_set1_EC_KEY(kp, key);
    }
    if (pub)
    {
        BIO *in     = BIO_new_mem_buf(pub, strlen(pub));
        EC_KEY *key = NULL;
        PEM_read_bio_EC_PUBKEY(in, &key, NULL, NULL);
        BIO_free(in);
        EVP_PKEY_set1_EC_KEY(kp, key);
    }
    return kp;
}

EVP_PKEY_CTX *gm_sm2_new(EVP_PKEY *kp, int (*init)(EVP_PKEY_CTX *))
{
    if (!EVP_PKEY_set_alias_type(kp, EVP_PKEY_SM2))
    {
        return NULL;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(kp, NULL);
    if (!ctx)
    {
        return NULL;
    }
    if (init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

int gm_sm2_crypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp,
                 int (*init)(EVP_PKEY_CTX *),
                 int (*crypt)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t))
{
    EVP_PKEY_CTX *ctx = gm_sm2_new(kp, init);
    if (!ctx)
    {
        return 0;
    }
    if (crypt(ctx, NULL, outlen, NULL, inlen) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    *out    = malloc(*outlen);
    int ret = crypt(ctx, *out, outlen, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int GM_SM2_encrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp)
{
    return gm_sm2_crypt(out, outlen, in, inlen, kp, EVP_PKEY_encrypt_init, EVP_PKEY_encrypt);
}

int GM_SM2_decrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp)
{
    return gm_sm2_crypt(out, outlen, in, inlen, kp, EVP_PKEY_decrypt_init, EVP_PKEY_decrypt);
}

int GM_SM2_sign(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp)
{
    return gm_sm2_crypt(out, outlen, in, inlen, kp, EVP_PKEY_sign_init, EVP_PKEY_sign);
}

int GM_SM2_verify(const unsigned char *sig, size_t siglen, const unsigned char *in, size_t inlen, EVP_PKEY *kp)
{
    EVP_PKEY_CTX *ctx = gm_sm2_new(kp, EVP_PKEY_verify_init);
    if (!ctx)
    {
        return 0;
    }
    int verified = EVP_PKEY_verify(ctx, sig, siglen, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return verified;
}