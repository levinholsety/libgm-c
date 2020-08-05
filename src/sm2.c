#include "sm2.h"
#include "openssl/ec.h"
#include "openssl/pem.h"
#include <string.h>

EVP_PKEY *GM_SM2_new_key()
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL)
    {
        return NULL;
    }
    if (EVP_PKEY_paramgen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_sm2) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY *kp = NULL;
    if (EVP_PKEY_keygen(ctx, &kp) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return kp;
}

EVP_PKEY *GM_SM2_import_key(const char *priv, const char *pub)
{
    if (priv == NULL && pub == NULL)
    {
        return NULL;
    }
    EVP_PKEY *kp = EVP_PKEY_new();
    if (kp == NULL)
    {
        return NULL;
    }
    if (priv != NULL)
    {
        BIO *in = BIO_new_mem_buf(priv, strlen(priv));
        if (in == NULL)
        {
            EVP_PKEY_free(kp);
            return NULL;
        }
        EC_KEY *key = NULL;
        if (PEM_read_bio_ECPrivateKey(in, &key, NULL, NULL) == NULL)
        {
            EVP_PKEY_free(kp);
            return NULL;
        }
        BIO_free(in);
        if (EVP_PKEY_set1_EC_KEY(kp, key) <= 0)
        {
            EVP_PKEY_free(kp);
            return NULL;
        }
    }
    if (pub != NULL)
    {
        BIO *in = BIO_new_mem_buf(pub, strlen(pub));
        if (in == NULL)
        {
            EVP_PKEY_free(kp);
            return NULL;
        }
        EC_KEY *key = NULL;
        if (PEM_read_bio_EC_PUBKEY(in, &key, NULL, NULL) == NULL)
        {
            EVP_PKEY_free(kp);
            return NULL;
        }
        BIO_free(in);
        if (EVP_PKEY_set1_EC_KEY(kp, key) <= 0)
        {
            EVP_PKEY_free(kp);
            return NULL;
        }
    }
    return kp;
}

void GM_SM2_free_key(EVP_PKEY *kp)
{
    EVP_PKEY_free(kp);
}

RESULT GM_SM2_pem_encode(EVP_PKEY *kp, char **str, int priv)
{
    if (str == NULL)
    {
        return RESULT_FAILURE;
    }
    EC_KEY *key = EVP_PKEY_get0_EC_KEY(kp);
    if (key == NULL)
    {
        return RESULT_FAILURE;
    }
    BIO *out = BIO_new(BIO_s_mem());
    if (out == NULL)
    {
        return RESULT_FAILURE;
    }
    if ((priv ? PEM_write_bio_ECPrivateKey(out, key, NULL, NULL, 0, NULL, NULL) : PEM_write_bio_EC_PUBKEY(out, key)) <= 0)
    {
        BIO_free(out);
        return RESULT_FAILURE;
    }
    BUF_MEM *mem = NULL;
    if (BIO_get_mem_ptr(out, &mem) <= 0)
    {
        BIO_free(out);
        return RESULT_FAILURE;
    }
    *str = malloc(mem->length + 1);
    if (*str == NULL)
    {
        BIO_free(out);
        return RESULT_FAILURE;
    }
    memcpy(*str, mem->data, mem->length);
    *(*str + mem->length) = 0;
    BIO_free(out);
    return RESULT_SUCCESS;
}

RESULT GM_SM2_export_private(EVP_PKEY *kp, char **out)
{
    return GM_SM2_pem_encode(kp, out, 1);
}

RESULT GM_SM2_export_public(EVP_PKEY *kp, char **out)
{
    return GM_SM2_pem_encode(kp, out, 0);
}

EVP_PKEY_CTX *GM_SM2_new(EVP_PKEY *kp, int (*init)(EVP_PKEY_CTX *))
{
    if (EVP_PKEY_set_alias_type(kp, EVP_PKEY_SM2) <= 0)
    {
        return NULL;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(kp, NULL);
    if (ctx == NULL)
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

RESULT GM_SM2_crypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp,
                    int (*init)(EVP_PKEY_CTX *),
                    int (*crypt)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t))
{
    if (out == NULL || outlen == NULL)
    {
        return RESULT_FAILURE;
    }
    EVP_PKEY_CTX *ctx = GM_SM2_new(kp, init);
    if (ctx == NULL)
    {
        return RESULT_FAILURE;
    }
    if (crypt(ctx, NULL, outlen, NULL, inlen) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return RESULT_FAILURE;
    }
    *out = malloc(*outlen);
    if (*out == NULL)
    {
        EVP_PKEY_CTX_free(ctx);
        return RESULT_FAILURE;
    }
    if (crypt(ctx, *out, outlen, in, inlen) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return RESULT_FAILURE;
    }
    EVP_PKEY_CTX_free(ctx);
    return RESULT_SUCCESS;
}

RESULT GM_SM2_encrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp)
{
    return GM_SM2_crypt(out, outlen, in, inlen, kp, EVP_PKEY_encrypt_init, EVP_PKEY_encrypt);
}

RESULT GM_SM2_decrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp)
{
    return GM_SM2_crypt(out, outlen, in, inlen, kp, EVP_PKEY_decrypt_init, EVP_PKEY_decrypt);
}

RESULT GM_SM2_sign(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp)
{
    return GM_SM2_crypt(out, outlen, in, inlen, kp, EVP_PKEY_sign_init, EVP_PKEY_sign);
}

RESULT GM_SM2_verify(const unsigned char *sig, size_t siglen, const unsigned char *in, size_t inlen, EVP_PKEY *kp)
{
    EVP_PKEY_CTX *ctx = GM_SM2_new(kp, EVP_PKEY_verify_init);
    if (ctx == NULL)
    {
        return RESULT_ERROR;
    }
    int result = EVP_PKEY_verify(ctx, sig, siglen, in, inlen);
    if (result <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return RESULT_ERROR;
    }
    if (result == 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return RESULT_FAILURE;
    }
    EVP_PKEY_CTX_free(ctx);
    return RESULT_SUCCESS;
}