#include "sm2.h"
#include "openssl/pem.h"
#include "string.h"

EC_KEY *GM_SM2_key_new()
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2);
    if (key)
    {
        if (EC_KEY_generate_key(key) != SUCCESS)
        {
            EC_KEY_free(key);
            key = NULL;
        }
    }
    return key;
}

void GM_SM2_key_free(EC_KEY *key)
{
    EC_KEY_free(key);
}

int GM_SM2_key_encode(char **pem, EC_KEY *key, int pri)
{
    int ok   = FAILURE;
    BIO *mem = BIO_new(BIO_s_mem());
    if (mem)
    {
        if ((pri ? PEM_write_bio_ECPrivateKey(mem, key, NULL, NULL, 0, NULL, NULL)
                 : PEM_write_bio_EC_PUBKEY(mem, key)) > 0)
        {
            BUF_MEM *buf = NULL;
            if (BIO_get_mem_ptr(mem, &buf) > 0)
            {
                *pem = malloc(buf->length + 1);
                if (*pem)
                {
                    memcpy(*pem, buf->data, buf->length);
                    (*pem)[buf->length] = 0;
                    ok                  = SUCCESS;
                }
                BUF_MEM_free(buf);
                buf = NULL;
            }
        }
        BIO_set_close(mem, BIO_NOCLOSE);
        BIO_free(mem);
        mem = NULL;
    }
    return ok;
}

int GM_SM2_key_decode(EC_KEY **key, const char *pem, int pri)
{
    int ok   = FAILURE;
    BIO *mem = BIO_new_mem_buf(pem, strlen(pem));
    if (mem)
    {
        if ((pri ? PEM_read_bio_ECPrivateKey(mem, key, NULL, NULL)
                 : PEM_read_bio_EC_PUBKEY(mem, key, NULL, NULL)) != NULL)
        {
            ok = SUCCESS;
        }
        BIO_set_close(mem, BIO_NOCLOSE);
        BIO_free(mem);
        mem = NULL;
    }
    return ok;
}

#define use_pkey(exp, key)                                              \
    do                                                                  \
    {                                                                   \
        EVP_PKEY *pkey = EVP_PKEY_new();                                \
        if (pkey)                                                       \
        {                                                               \
            if (EVP_PKEY_set1_EC_KEY(pkey, key) == SUCCESS &&           \
                EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) == SUCCESS) \
            {                                                           \
                EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);      \
                if (pctx)                                               \
                {                                                       \
                    exp                                                 \
                        EVP_PKEY_CTX_free(pctx);                        \
                    pctx = NULL;                                        \
                }                                                       \
            }                                                           \
            EVP_PKEY_free(pkey);                                        \
            pkey = NULL;                                                \
        }                                                               \
    } while (0)

int GM_SM2_crypt(unsigned char **out, size_t *out_len, const unsigned char *in, size_t in_len, EC_KEY *key, int enc)
{
    int ok = FAILURE;
    int (*init)(EVP_PKEY_CTX *);
    int (*crypt)(EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);
    if (enc)
    {
        init  = EVP_PKEY_encrypt_init;
        crypt = EVP_PKEY_encrypt;
    }
    else
    {
        init  = EVP_PKEY_decrypt_init;
        crypt = EVP_PKEY_decrypt;
    }
    use_pkey(
        if (init(pctx) == SUCCESS &&
            crypt(pctx, NULL, out_len, in, in_len) == SUCCESS) {
            *out = malloc(*out_len);
            if (*out != NULL &&
                crypt(pctx, *out, out_len, in, in_len) == SUCCESS)
            {
                ok = SUCCESS;
            }
            else
            {
                free(*out);
                *out = NULL;
            }
        },
        key);
    return ok;
}

#define use_md(exp, key, id)                            \
    use_pkey(                                           \
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();            \
        if (mctx) {                                     \
            if (EVP_PKEY_CTX_set1_id(pctx, id, 16) > 0) \
            {                                           \
                EVP_MD_CTX_set_pkey_ctx(mctx, pctx);    \
                exp                                     \
            }                                           \
            EVP_MD_CTX_free(mctx);                      \
            mctx = NULL;                                \
        },                                              \
        key)

int GM_SM2_sign(unsigned char **sig, size_t *sig_len, const unsigned char *data, size_t data_len, const unsigned char *id, EC_KEY *key)
{
    int ok = FAILURE;
    use_md(
        if (EVP_DigestSignInit(mctx, NULL, EVP_sm3(), NULL, pkey) == SUCCESS &&
            EVP_DigestSignUpdate(mctx, data, data_len) == SUCCESS &&
            EVP_DigestSignFinal(mctx, NULL, sig_len) == SUCCESS) {
            *sig = malloc(*sig_len);
            if (*sig)
            {
                if (EVP_DigestSignFinal(mctx, *sig, sig_len) == SUCCESS)
                {
                    ok = SUCCESS;
                }
                else
                {
                    free(*sig);
                    *sig = NULL;
                }
            }
        },
        key, id);
    return ok;
}

int GM_SM2_verify(const unsigned char *sig, size_t sig_len, const unsigned char *data, size_t data_len, unsigned char *id, EC_KEY *key)
{
    int ok = FAILURE;
    use_md(ok = EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey) == SUCCESS &&
                EVP_DigestVerifyUpdate(mctx, data, data_len) == SUCCESS &&
                EVP_DigestVerifyFinal(mctx, sig, sig_len) == SUCCESS;
           , key, id);
    return ok;
}
