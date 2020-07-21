#include "sm2.h"

void GM_SM2_free_key(EVP_PKEY *pkey)
{
    EVP_PKEY_free(pkey);
}

EVP_PKEY *GM_SM2_new_key()
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_paramgen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_sm2);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

char *gm_sm2_pem_encode(EVP_PKEY *pkey, int priv)
{
    EC_KEY *key = EVP_PKEY_get0_EC_KEY(pkey);
    BIO *out = BIO_new(BIO_s_mem());
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
    char *keystr = malloc(mem->length);
    memcpy(keystr, mem->data, mem->length);
    BIO_free(out);
    return keystr;
}

char *GM_SM2_export_private(EVP_PKEY *pkey)
{
    return gm_sm2_pem_encode(pkey, 1);
}

char *GM_SM2_export_public(EVP_PKEY *pkey)
{
    return gm_sm2_pem_encode(pkey, 0);
}

EVP_PKEY *GM_SM2_import_key(const char *priv, const char *pub)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (priv)
    {
        BIO *in = BIO_new_mem_buf(priv, strlen(priv));
        EC_KEY *key = NULL;
        PEM_read_bio_ECPrivateKey(in, &key, NULL, NULL);
        BIO_free(in);
        EVP_PKEY_set1_EC_KEY(pkey, key);
    }
    if (pub)
    {
        BIO *in = BIO_new_mem_buf(pub, strlen(pub));
        EC_KEY *key = NULL;
        PEM_read_bio_EC_PUBKEY(in, &key, NULL, NULL);
        BIO_free(in);
        EVP_PKEY_set1_EC_KEY(pkey, key);
    }
    return pkey;
}

void GM_SM2_free(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY_CTX_free(ctx);
}

EVP_PKEY_CTX *gm_sm2_new(size_t *estoutlen, size_t inlen, EVP_PKEY *pkey,
                         int (*init)(EVP_PKEY_CTX *),
                         int (*estimate)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t))
{
    if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2))
    {
        return NULL;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
    {
        return NULL;
    }
    if (init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (estoutlen && estimate && estimate(ctx, NULL, estoutlen, NULL, inlen) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

EVP_PKEY_CTX *GM_SM2_new_encryptor(size_t *estoutlen, size_t inlen, EVP_PKEY *pkey)
{
    return gm_sm2_new(estoutlen, inlen, pkey, EVP_PKEY_encrypt_init, EVP_PKEY_encrypt);
}

int GM_SM2_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    return EVP_PKEY_encrypt(ctx, out, outlen, in, inlen);
}

EVP_PKEY_CTX *GM_SM2_new_decryptor(size_t *estoutlen, size_t inlen, EVP_PKEY *pkey)
{
    return gm_sm2_new(estoutlen, inlen, pkey, EVP_PKEY_decrypt_init, EVP_PKEY_decrypt);
}

int GM_SM2_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    return EVP_PKEY_decrypt(ctx, out, outlen, in, inlen);
}

EVP_PKEY_CTX *GM_SM2_new_signer(size_t *estoutlen, size_t inlen, EVP_PKEY *pkey)
{
    return gm_sm2_new(estoutlen, inlen, pkey, EVP_PKEY_sign_init, EVP_PKEY_sign);
}

int GM_SM2_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *in, size_t inlen)
{
    return EVP_PKEY_sign(ctx, sig, siglen, in, inlen);
}

int GM_SM2_verify(const unsigned char *sig, size_t siglen, const unsigned char *in, size_t inlen, EVP_PKEY *pkey)
{
    EVP_PKEY_CTX *ctx = gm_sm2_new(NULL, 0, pkey, EVP_PKEY_verify_init, NULL);
    if (!ctx)
    {
        return 0;
    }
    int verified = EVP_PKEY_verify(ctx, sig, siglen, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return verified;
}