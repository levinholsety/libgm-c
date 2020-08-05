#include "hex.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include <assert.h>
#include <string.h>

const unsigned char data[27] = "abcdefghijklmnopqrstuvwxyz";

void print_hex(const char *name, const unsigned char *data, size_t size)
{
    printf("%s: [%d]", name, size);
    size_t i;
    for (i = 0; i < size; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_sm2()
{
    printf("Testing SM2:\n");

    EVP_PKEY *kp;
    char *private_key, *public_key;

    assert((kp = GM_SM2_new_key()) != NULL);
    assert(GM_SM2_export_private(kp, &private_key) == RESULT_SUCCESS);
    assert(GM_SM2_export_public(kp, &public_key) == RESULT_SUCCESS);
    GM_SM2_free_key(kp);
    printf("new_key(), export_private(), export_public() passed!\n");

    size_t enclen;
    unsigned char *encdata;
    assert((kp = GM_SM2_import_key(NULL, public_key)) != NULL);
    assert(GM_SM2_encrypt(&encdata, &enclen, data, sizeof(data), kp) == RESULT_SUCCESS);
    GM_SM2_free_key(kp);

    size_t declen;
    unsigned char *decdata;
    assert((kp = GM_SM2_import_key(private_key, NULL)) != NULL);
    assert(GM_SM2_decrypt(&decdata, &declen, encdata, enclen, kp) == RESULT_SUCCESS);
    GM_SM2_free_key(kp);
    free(encdata);
    assert(memcmp(data, decdata, declen) == 0);
    free(decdata);
    printf("import_key(), encrypt(), decrypt() passed!\n");

    size_t siglen;
    unsigned char *sig;
    assert((kp = GM_SM2_import_key(private_key, NULL)) != NULL);
    assert(GM_SM2_sign(&sig, &siglen, data, sizeof(data), kp) == RESULT_SUCCESS);
    GM_SM2_free_key(kp);
    printf("import_key(), sign() passed!\n");

    assert((kp = GM_SM2_import_key(NULL, public_key)) != NULL);
    assert(GM_SM2_verify(sig, siglen, data, sizeof(data), kp) == RESULT_SUCCESS);
    GM_SM2_free_key(kp);
    free(sig);
    printf("import_key(), verify() passed!\n");

    free(private_key);
    free(public_key);
}

const char SM3_HASH[] = "3a8c90ded60741c5283f0813ea2dece6672d8d6f32f3eb9820ed3ab2e6878a27";

void test_sm3()
{
    printf("Testing SM3:\n");

    GM_SM3_MD md;
    assert(GM_SM3_digest(md, data, sizeof(data)) == RESULT_SUCCESS);
    char str[65];
    HEX_encode(str, NULL, md, sizeof(GM_SM3_MD));
    assert(strcmp(SM3_HASH, str) == 0);
    printf("digest() passed!\n");
}

void test_sm4()
{
    printf("Testing SM4:\n");
    GM_SM4_KEY key = {0};
    GM_SM4_IV iv   = {0};
    assert(GM_SM4_rand_key(key, iv) == RESULT_SUCCESS);
    printf("rand_key() passed!\n");

    int dlen = sizeof(data);
    int enclen;
    assert(GM_SM4_encrypt(NULL, &enclen, NULL, dlen, NULL, NULL) == RESULT_SUCCESS);
    unsigned char *encdata = malloc(enclen);
    assert(encdata != NULL);
    assert(GM_SM4_encrypt(encdata, &enclen, data, dlen, key, iv) == RESULT_SUCCESS);
    printf("encrypt() passed!\n");

    int declen;
    assert(GM_SM4_decrypt(NULL, &declen, NULL, enclen, NULL, NULL) == RESULT_SUCCESS);
    unsigned char *decdata = malloc(declen);
    assert(GM_SM4_decrypt(decdata, &declen, encdata, enclen, key, iv) == RESULT_SUCCESS);
    free(encdata);
    assert(memcmp(data, decdata, dlen) == 0);
    free(decdata);
    printf("decrypt() passed!\n");
}

int main()
{
    test_sm2();
    test_sm3();
    test_sm4();
}