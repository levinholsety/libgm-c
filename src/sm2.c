#include "sm2.h"
#include "openssl/ec.h"
#include "openssl/pem.h"
#include <string.h>

EVP_PKEY *GM_SM2_new_key()
{
    EVP_PKEY_CTX *ctx;
    if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL)
    {
        return NULL;
    }
    EVP_PKEY *kp = NULL;
    if (EVP_PKEY_paramgen_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_sm2) > 0 &&
        EVP_PKEY_keygen_init(ctx) > 0 &&
        EVP_PKEY_keygen(ctx, &kp) > 0) {}
    EVP_PKEY_CTX_free(ctx);
    return kp;
}

RESULT import_private_key(EVP_PKEY *kp, const char *priv)
{
    RESULT result = RESULT_FAILURE;
    BIO *in;
    if ((in = BIO_new_mem_buf(priv, strlen(priv))) != NULL)
    {
        EC_KEY *key = NULL;
        if (PEM_read_bio_ECPrivateKey(in, &key, NULL, NULL) != NULL &&
            EVP_PKEY_set1_EC_KEY(kp, key) > 0)
        {
            result = RESULT_SUCCESS;
        }
        BIO_free(in);
    }
    return result;
}

RESULT import_public_key(EVP_PKEY *kp, const char *pub)
{
    RESULT result = RESULT_FAILURE;
    BIO *in;
    if ((in = BIO_new_mem_buf(pub, strlen(pub))) != NULL)
    {
        EC_KEY *key = NULL;
        if (PEM_read_bio_EC_PUBKEY(in, &key, NULL, NULL) != NULL &&
            EVP_PKEY_set1_EC_KEY(kp, key) > 0)
        {
            result = RESULT_SUCCESS;
        }
        BIO_free(in);
    }
    return result;
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
        if (import_private_key(kp, priv) <= 0)
        {
            EVP_PKEY_free(kp);
            return NULL;
        }
    }
    if (pub != NULL)
    {
        if (import_public_key(kp, pub) <= 0)
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

char *read_text_from_bio(BIO *buf)
{
    BUF_MEM *mem = NULL;
    if (BIO_get_mem_ptr(buf, &mem) > 0)
    {
        char *str;
        if ((str = malloc(mem->length + 1)) != NULL)
        {
            memcpy(str, mem->data, mem->length);
            *(str + mem->length) = 0;
            return str;
        }
    }
    return NULL;
}

char *encode_pem(EVP_PKEY *kp, int priv)
{
    char *result = NULL;
    BIO *buf;
    EC_KEY *key = EVP_PKEY_get0_EC_KEY(kp);
    if (key != NULL &&
        (buf = BIO_new(BIO_s_mem())) != NULL)
    {
        if ((priv ? PEM_write_bio_ECPrivateKey(buf, key, NULL, NULL, 0, NULL, NULL)
                  : PEM_write_bio_EC_PUBKEY(buf, key)) > 0)
        {
            result = read_text_from_bio(buf);
        }
        BIO_free(buf);
    }
    return result;
}

char *GM_SM2_export_private(EVP_PKEY *kp)
{
    return encode_pem(kp, 1);
}

char *GM_SM2_export_public(EVP_PKEY *kp)
{
    return encode_pem(kp, 0);
}

EVP_PKEY_CTX *GM_SM2_new(EVP_PKEY *kp, int (*init)(EVP_PKEY_CTX *))
{
    EVP_PKEY_CTX *ctx = NULL;
    if (EVP_PKEY_set_alias_type(kp, EVP_PKEY_SM2) > 0 &&
        (ctx = EVP_PKEY_CTX_new(kp, NULL)) != NULL)
    {
        if (init(ctx) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
        }
    }
    return ctx;
}

RESULT GM_SM2_crypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp,
                    int (*init)(EVP_PKEY_CTX *),
                    int (*GM_SM2_crypt)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t))
{
    RESULT result     = RESULT_FAILURE;
    EVP_PKEY_CTX *ctx = GM_SM2_new(kp, init);
    if (ctx != NULL)
    {
        if (GM_SM2_crypt(ctx, NULL, outlen, NULL, inlen) > 0 &&
            (*out = malloc(*outlen)) != NULL)
        {
            if (GM_SM2_crypt(ctx, *out, outlen, in, inlen) > 0)
            {
                result = RESULT_SUCCESS;
            }
            else
            {
                free(*out);
            }
        }
        EVP_PKEY_CTX_free(ctx);
    }
    return result;
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
    RESULT result     = RESULT_FAILURE;
    EVP_PKEY_CTX *ctx = GM_SM2_new(kp, EVP_PKEY_verify_init);
    if (ctx != NULL)
    {
        int verified = EVP_PKEY_verify(ctx, sig, siglen, in, inlen);
        if (verified > 0)
        {
            result = RESULT_SUCCESS;
        }
        else if (verified < 0)
        {
            result = RESULT_ERROR;
        }
        EVP_PKEY_CTX_free(ctx);
    }
    return result;
}