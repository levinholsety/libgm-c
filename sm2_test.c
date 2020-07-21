#include "sm2.h"
#include "test.h"

void generate_key(char **private_key, char **public_key)
{
    EVP_PKEY *key_pair = GM_SM2_new_key();
    *private_key = GM_SM2_export_private(key_pair);
    *public_key = GM_SM2_export_public(key_pair);
    GM_SM2_free_key(key_pair);
}

void encrypt(unsigned char **encdata, size_t *enclen, const unsigned char *data, size_t dlen, const char *public_key)
{
    EVP_PKEY *key_pair = GM_SM2_import_key(NULL, public_key);
    EVP_PKEY_CTX *ctx = GM_SM2_new_encryptor(enclen, dlen, key_pair);
    *encdata = malloc(*enclen);
    GM_SM2_encrypt(ctx, *encdata, enclen, data, dlen);
    GM_SM2_free(ctx);
    GM_SM2_free_key(key_pair);
}

void decrypt(unsigned char **decdata, size_t *declen, const unsigned char *data, size_t dlen, const char *private_key)
{
    EVP_PKEY *key_pair = GM_SM2_import_key(private_key, NULL);
    EVP_PKEY_CTX *ctx = GM_SM2_new_decryptor(declen, dlen, key_pair);
    *decdata = malloc(*declen);
    GM_SM2_decrypt(ctx, *decdata, declen, data, dlen);
    GM_SM2_free(ctx);
    GM_SM2_free_key(key_pair);
}

void sign(unsigned char **sig, size_t *siglen, const unsigned char *data, size_t dlen, const char *private_key)
{
    EVP_PKEY *key_pair = GM_SM2_import_key(private_key, NULL);
    EVP_PKEY_CTX *ctx = GM_SM2_new_signer(siglen, dlen, key_pair);
    *sig = malloc(*siglen);
    GM_SM2_sign(ctx, *sig, siglen, data, dlen);
    GM_SM2_free(ctx);
    GM_SM2_free_key(key_pair);
}

int verify(const unsigned char *sig, size_t siglen, const unsigned char *data, size_t dlen, const char *public_key)
{
    EVP_PKEY *key_pair = GM_SM2_import_key(NULL, public_key);
    int verified = GM_SM2_verify(sig, siglen, data, dlen, key_pair);
    GM_SM2_free_key(key_pair);
    return verified;
}

int main()
{
    char *private_key, *public_key;

    print_str("generate key");
    generate_key(&private_key, &public_key);
    print_str(private_key);
    print_str(public_key);

    print_str("encrypt data");
    size_t enclen;
    unsigned char *encdata;
    encrypt(&encdata, &enclen, data, sizeof(data), public_key);
    print_hex(encdata, enclen);

    print_str("decrypt data");
    size_t declen;
    unsigned char *decdata;
    decrypt(&decdata, &declen, encdata, enclen, private_key);
    free(encdata);
    print_str(decdata);
    free(decdata);

    print_str("sign data");
    size_t siglen;
    unsigned char *sig;
    sign(&sig, &siglen, data, sizeof(data), private_key);
    print_hex(sig, siglen);

    int verified = verify(sig, siglen, data, sizeof(data), public_key);
    free(sig);
    printf("%s\n", verified ? "verified" : "not verified");

    free(private_key);
    free(public_key);
}
