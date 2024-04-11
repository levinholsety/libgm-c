#include "sm2.h"
#include "openssl/asn1.h"
#include "openssl/asn1t.h"
#include "openssl/ec.h"
#include "openssl/param_build.h"
#include <stdio.h>

typedef struct sm2_cipher_st
{
    BIGNUM *x_coordinate;
    BIGNUM *y_coordinate;
    ASN1_OCTET_STRING *hash;
    ASN1_OCTET_STRING *cipher_text;
} SM2_CIPHER;
DECLARE_ASN1_FUNCTIONS(SM2_CIPHER)
ASN1_SEQUENCE(SM2_CIPHER) = {
    ASN1_SIMPLE(SM2_CIPHER, x_coordinate, BIGNUM),
    ASN1_SIMPLE(SM2_CIPHER, y_coordinate, BIGNUM),
    ASN1_SIMPLE(SM2_CIPHER, hash, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SM2_CIPHER, cipher_text, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_CIPHER) IMPLEMENT_ASN1_FUNCTIONS(SM2_CIPHER);

typedef struct sm2_signature_st
{
    BIGNUM *r;
    BIGNUM *s;
} SM2_SIGNATURE;
DECLARE_ASN1_FUNCTIONS(SM2_SIGNATURE)
ASN1_SEQUENCE(SM2_SIGNATURE) = {
    ASN1_SIMPLE(SM2_SIGNATURE, r, BIGNUM),
    ASN1_SIMPLE(SM2_SIGNATURE, s, BIGNUM),
} ASN1_SEQUENCE_END(SM2_SIGNATURE) IMPLEMENT_ASN1_FUNCTIONS(SM2_SIGNATURE);

typedef struct sm2_enveloped_key_st
{
    ASN1_UTF8STRING *sym_alg_id;
    ASN1_OCTET_STRING *sym_encrypted_key;
    ASN1_OCTET_STRING *sm2_public_key;
    ASN1_OCTET_STRING *sm2_encrypted_private_key;
} SM2_ENVELOPED_KEY;

static int export_pub(unsigned char **pub, size_t *pub_len, BIGNUM *pri)
{
    if (!pub || !pub_len || !pri)
        return 0;
    EC_GROUP *group   = NULL;
    EC_POINT *pub_key = NULL;
    int success =
        (group = EC_GROUP_new_by_curve_name(NID_sm2)) &&
        (pub_key = EC_POINT_new(group)) &&
        EC_POINT_mul(group, pub_key, pri, NULL, NULL, NULL) &&
        (*pub_len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL)) &&
        (*pub = malloc(*pub_len)) &&
        EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, *pub, *pub_len, NULL);
    if (!success)
    {
        free(*pub);
        *pub = NULL;
    }
    if (pub_key)
    {
        EC_POINT_free(pub_key);
        pub_key = NULL;
    }
    if (group)
    {
        EC_GROUP_free(group);
        group = NULL;
    }
    return success;
}

int sm2_cipher_to_c1c3c2(unsigned char *out, int *out_len, const unsigned char *in, int in_len)
{
    if (!out || !out_len || !in)
        return 0;
    SM2_CIPHER *seq = NULL;
    int success =
        d2i_SM2_CIPHER(&seq, &in, in_len) &&
        BN_bn2bin(seq->x_coordinate, out) &&
        BN_bn2bin(seq->y_coordinate, out += BN_num_bytes(seq->x_coordinate)) &&
        memcpy(out += BN_num_bytes(seq->y_coordinate), seq->hash->data, seq->hash->length) &&
        memcpy(out += seq->hash->length, seq->cipher_text->data, seq->cipher_text->length) &&
        (*out_len = BN_num_bytes(seq->x_coordinate) + BN_num_bytes(seq->y_coordinate) + seq->hash->length + seq->cipher_text->length);
    if (seq)
    {
        SM2_CIPHER_free(seq);
        seq = NULL;
    }
    return success;
}

int sm2_sig_to_rs(unsigned char *out, int *out_len, const unsigned char *in, int in_len)
{
    if (!out || !out_len || !in)
        return 0;
    SM2_SIGNATURE *seq = NULL;
    int success =
        d2i_SM2_SIGNATURE(&seq, &in, in_len) &&
        BN_bn2bin(seq->r, out) &&
        BN_bn2bin(seq->s, out += BN_num_bytes(seq->r)) &&
        (*out_len = BN_num_bytes(seq->r) + BN_num_bytes(seq->s));
    if (seq)
    {
        SM2_SIGNATURE_free(seq);
        seq = NULL;
    }
    return success;
}

int sm2_key_pair_new(unsigned char *pub, size_t *pub_len, unsigned char *pri, size_t *pri_len)
{
    EVP_PKEY *pkey = EVP_EC_gen(SN_sm2);
    if (!pkey)
        return 0;
    int success = 1;
    if (pub && pub_len)
    {
        success = EVP_PKEY_get_octet_string_param(pkey, "pub", pub, *pub_len, pub_len);
    }
    if (success && pri && pri_len)
    {
        BIGNUM *pri_bn = NULL;
        success =
            EVP_PKEY_get_bn_param(pkey, "priv", &pri_bn) &&
            (*pri_len = BN_num_bytes(pri_bn)) &&
            BN_bn2bin(pri_bn, pri);
        if (pri_bn)
        {
            BN_free(pri_bn);
            pri_bn = NULL;
        }
    }
    if (pkey)
    {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    return success;
}

static EVP_PKEY *new_key(const unsigned char *key, size_t key_len, int is_pri)
{
    if (!key)
        return NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld)
    {
        return NULL;
    }
    int selection          = 0;
    OSSL_PARAM *params     = NULL;
    BIGNUM *pri_d          = NULL;
    size_t exp_pub_len     = 0;
    unsigned char *exp_pub = NULL;
    if (is_pri)
    {
        if ((pri_d = BN_bin2bn(key, key_len, NULL)) &&
            OSSL_PARAM_BLD_push_BN(bld, "priv", pri_d) &&
            export_pub(&exp_pub, &exp_pub_len, pri_d) &&
            OSSL_PARAM_BLD_push_octet_string(bld, "pub", exp_pub, exp_pub_len))
        {
            selection = EVP_PKEY_KEYPAIR;
        }
    }
    else
    {
        if (OSSL_PARAM_BLD_push_octet_string(bld, "pub", key, key_len))
        {
            selection = EVP_PKEY_PUBLIC_KEY;
        }
    }

    if (OSSL_PARAM_BLD_push_utf8_string(bld, "group", SN_sm2, 0))
    {
        params = OSSL_PARAM_BLD_to_param(bld);
    }
    if (exp_pub)
    {
        free(exp_pub);
        exp_pub = NULL;
    }
    if (pri_d)
    {
        BN_free(pri_d);
        pri_d = NULL;
    }
    OSSL_PARAM_BLD_free(bld);
    bld = NULL;
    if (!params)
    {
        return NULL;
    }
    EVP_PKEY *pkey    = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int success =
        (ctx = EVP_PKEY_CTX_new_from_name(NULL, SN_sm2, NULL)) &&
        EVP_PKEY_fromdata_init(ctx) &&
        EVP_PKEY_fromdata(ctx, &pkey, selection, params);
    if (!success)
    {
        pkey = NULL;
    }
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }
    OSSL_PARAM_free(params);
    params = NULL;
    return pkey;
}

int sm2_encrypt(unsigned char **out, size_t *out_len, const unsigned char *in, size_t in_len, const unsigned char *pub, size_t pub_len)
{
    if (!out || !out_len || !in || !pub)
        return 0;
    EVP_PKEY *pkey    = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int success =
        (pkey = new_key(pub, pub_len, 0)) &&
        (ctx = EVP_PKEY_CTX_new(pkey, NULL)) &&
        EVP_PKEY_encrypt_init(ctx) &&
        EVP_PKEY_encrypt(ctx, NULL, out_len, in, in_len) &&
        mem_new(out, *out_len) &&
        EVP_PKEY_encrypt(ctx, *out, out_len, in, in_len);
    if (!success)
    {
        mem_free(out);
    }
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }
    if (pkey)
    {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    return success;
}

int sm2_decrypt(unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len, const unsigned char *pri, size_t pri_len)
{
    if (!out || !out_len || !in || !pri)
        return 0;
    EVP_PKEY *pkey    = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int success =
        (pkey = new_key(pri, pri_len, 1)) &&
        (ctx = EVP_PKEY_CTX_new(pkey, NULL)) &&
        EVP_PKEY_decrypt_init(ctx) &&
        EVP_PKEY_decrypt(ctx, out, out_len, in, in_len);
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }
    if (pkey)
    {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    return success;
}

static unsigned char id[] = "1234567812345678";

SM2_SIG_CTX *sm2_sig_ctx_new(const unsigned char *key, size_t key_len, int is_pri)
{
    if (!key)
        return NULL;
    SM2_SIG_CTX *ctx = malloc(sizeof(SM2_SIG_CTX));
    if (!ctx)
        return NULL;
    ctx->is_pri = is_pri;
    int success =
        (ctx->pkey = new_key(key, key_len, is_pri)) &&
        (ctx->pctx = EVP_PKEY_CTX_new(ctx->pkey, NULL)) &&
        EVP_PKEY_CTX_set1_id(ctx->pctx, id, 16) &&
        (ctx->mctx = EVP_MD_CTX_new());
    if (!success)
    {
        sm2_sig_ctx_free(ctx);
        ctx = NULL;
    }
    EVP_MD_CTX_set_pkey_ctx(ctx->mctx, ctx->pctx);
    success = ctx->is_pri
                  ? EVP_DigestSignInit(ctx->mctx, NULL, EVP_sm3(), NULL, ctx->pkey)
                  : EVP_DigestVerifyInit(ctx->mctx, NULL, EVP_sm3(), NULL, ctx->pkey);
    if (!success)
    {
        sm2_sig_ctx_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

void sm2_sig_ctx_free(SM2_SIG_CTX *ctx)
{
    if (ctx)
    {
        if (ctx->mctx)
        {
            EVP_MD_CTX_free(ctx->mctx);
            ctx->mctx = NULL;
        }
        if (ctx->pctx)
        {
            EVP_PKEY_CTX_free(ctx->pctx);
            ctx->pctx = NULL;
        }
        if (ctx->pkey)
        {
            EVP_PKEY_free(ctx->pkey);
            ctx->pkey = NULL;
        }
        free(ctx);
        ctx = NULL;
    }
}

int sm2_sig_update(SM2_SIG_CTX *ctx, const unsigned char *in, size_t in_len)
{
    return ctx && in && ctx->is_pri
               ? EVP_DigestSignUpdate(ctx->mctx, in, in_len)
               : EVP_DigestVerifyUpdate(ctx->mctx, in, in_len);
}

int sm2_sig_sign(SM2_SIG_CTX *ctx, unsigned char *sig, size_t *sig_len)
{
    return ctx && sig && sig_len && ctx->is_pri &&
           EVP_DigestSignFinal(ctx->mctx, sig, sig_len);
}

int sm2_sig_verify(SM2_SIG_CTX *ctx, const unsigned char *sig, size_t sig_len)
{
    return ctx && sig && !ctx->is_pri &&
           EVP_DigestVerifyFinal(ctx->mctx, sig, sig_len);
}

int sm2_sign(unsigned char *sig, size_t *sig_len, const unsigned char *in, size_t in_len, const unsigned char *pri, size_t pri_len)
{
    if (!sig || !sig_len || !in || !pri)
        return 0;
    SM2_SIG_CTX *ctx = NULL;
    int success =
        (ctx = sm2_sig_ctx_new(pri, pri_len, 1)) &&
        sm2_sig_update(ctx, in, in_len) &&
        sm2_sig_sign(ctx, sig, sig_len);
    if (ctx)
    {
        sm2_sig_ctx_free(ctx);
        ctx = NULL;
    }
    return success;
}

int sm2_verify(const unsigned char *sig, size_t sig_len, const unsigned char *in, size_t in_len, const unsigned char *pub, size_t pub_len)
{
    if (!sig || !in || !pub)
        return 0;
    SM2_SIG_CTX *ctx = NULL;
    int success =
        (ctx = sm2_sig_ctx_new(pub, pub_len, 0)) &&
        sm2_sig_update(ctx, in, in_len) &&
        sm2_sig_verify(ctx, sig, sig_len);
    if (ctx)
    {
        sm2_sig_ctx_free(ctx);
        ctx = NULL;
    }
    return success;
}
