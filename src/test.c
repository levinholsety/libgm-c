#include "common.h"
#include "openssl/crypto.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include <stdio.h>
#include <string.h>

static const char data[] = "Hello World! My name is Hello, your name is World. 你好世界！我的名字是你好，你的名字是世界。床前明月光，疑似地上霜。举头望明月，低头思故乡。Hello World! My name is Hello, your name is World. 你好世界！我的名字是你好，你的名字是世界。床前明月光，疑似地上霜。举头望明月，低头思故乡。";

static void print_bin(const char *name, const unsigned char *data, int data_len)
{
    // int out_len = (data_len + 2) / 3 * 4;
    // unsigned char out[out_len];
    // out_len = EVP_EncodeBlock(out, data, data_len);
    // printf("%s: (%d Bytes) %.*s\n", name, data_len, out_len, out);
    printf("%s", name);
    printf(": (%d Bytes) ", data_len);
    for (int i = 0; i < data_len; i++)
    {
        printf("%02x", *data++);
    }
    printf("\n");
}

static int test_sm2()
{
    printf("========== SM2 Test ==========\n");
    size_t pub_len = SM2_PUB_MAX_SIZE;
    unsigned char pub[pub_len];
    size_t pri_len = SM2_PRI_MAX_SIZE;
    unsigned char pri[pri_len];
    if (!sm2_key_pair_new(pub, &pub_len, pri, &pri_len))
        return 0;
    print_bin("sm2-pub", pub, pub_len);
    print_bin("sm2-pri", pri, pri_len);
    int data_len       = strlen(data);
    size_t enc_len     = 0;
    unsigned char *enc = NULL;
    if (!sm2_encrypt(&enc, &enc_len, (unsigned char *)data, strlen(data), pub, pub_len))
    {
        mem_free(&enc);
        return 0;
    }
    print_bin("sm2-enc", enc, enc_len);
    int enc_raw_len = enc_len;
    unsigned char enc_raw[enc_raw_len];
    if (!sm2_cipher_to_c1c3c2(enc_raw, &enc_raw_len, enc, enc_len))
    {
        mem_free(&enc);
        return 0;
    }
    print_bin("sm2-c1c3c2", enc_raw, enc_raw_len);
    size_t dec_len = enc_len;
    unsigned char dec[dec_len];
    if (!sm2_decrypt(dec, &dec_len, enc, enc_len, pri, pri_len))
    {
        mem_free(&enc);
        return 0;
    }
    printf("sm2-dec: %.*s\n", (int)dec_len, dec);
    mem_free(&enc);
    size_t sig_len = SM2_SIG_MAX_SIZE;
    unsigned char sig[sig_len];
    if (!sm2_sign(sig, &sig_len, (const unsigned char *)data, data_len, pri, pri_len))
        return 0;
    print_bin("sm2-sig", sig, sig_len);
    int sig_raw_len = sig_len;
    unsigned char sig_raw[sig_raw_len];
    if (!sm2_sig_to_rs(sig_raw, &sig_raw_len, sig, sig_len))
        return 0;
    print_bin("sm2-sig-raw", sig_raw, sig_raw_len);
    if (sm2_verify(sig, sig_len, (unsigned char *)data, data_len, pub, pub_len))
        printf("sm2-ver: Ok\n");
    else
        printf("sm2-ver: Failed\n");
    return 1;
}

static int test_sm3()
{
    printf("========== SM3 Test ==========\n");
    unsigned char md[SM3_MD_SIZE];
    unsigned int md_len = sizeof(md);
    if (!sm3_digest(md, &md_len, (unsigned char *)data, strlen(data)))
        return 0;
    print_bin("sm3-md", md, md_len);
    return 1;
}

static int test_sm4()
{
    printf("========== SM4 Test ==========\n");
    unsigned char key[SM4_BLOCK_SIZE];
    if (!sm4_generate_key(key))
        return 0;
    print_bin("sm4-key", key, sizeof(key));
    unsigned char enc[sm4_enc_max_size(strlen(data))];
    int enc_len = 0;
    if (!sm4_encrypt_ecb(enc, &enc_len, (unsigned char *)data, strlen(data), key))
        return 0;
    print_bin("sm4-ecb-enc", enc, enc_len);
    unsigned char dec[sm4_dec_max_size(enc_len)];
    int dec_len = 0;
    if (!sm4_decrypt_ecb(dec, &dec_len, enc, enc_len, key))
        return 0;
    printf("sm4-ecb-dec: %.*s\n", dec_len, dec);
    unsigned char iv[SM4_BLOCK_SIZE];
    if (!sm4_generate_key(iv))
        return 0;
    print_bin("sm4-iv", iv, sizeof(iv));
    if (!sm4_encrypt_cbc(enc, &enc_len, (unsigned char *)data, strlen(data), key, iv))
        return 0;
    print_bin("sm4-cbc-enc", enc, enc_len);
    if (!sm4_decrypt_cbc(dec, &dec_len, enc, enc_len, key, iv))
        return 0;
    printf("sm4-cbc-dec: %.*s\n", dec_len, dec);
    return 1;
}

int main()
{
    print_bin("data", (unsigned char *)data, strlen(data));
    if (!test_sm2())
        printf("sm2 test failed\n");
    if (!test_sm3())
        printf("sm3 test failed\n");
    if (!test_sm4())
        printf("sm4 test failed\n");
    return 0;
}