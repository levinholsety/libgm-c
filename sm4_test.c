#include <string.h>
#include "openssl/buffer.h"
#include "sm4.h"
#include "test.h"

void cipher(BIO *out, BIO *in, EVP_CIPHER_CTX *ctx)
{
    int buflen = 0x1000, cipherbuflen;
    size_t readlen;
    unsigned char *buf = malloc(buflen), *cipherbuf = malloc(GM_SM4_suggested_out_length(buflen));
    while (BIO_read_ex(in, buf, buflen, &readlen) == 1)
    {
        GM_SM4_update(ctx, cipherbuf, &cipherbuflen, buf, readlen);
        BIO_write(out, cipherbuf, cipherbuflen);
    }
    free(buf);
    GM_SM4_final(ctx, cipherbuf, &cipherbuflen);
    BIO_write(out, cipherbuf, cipherbuflen);
    free(cipherbuf);
}

void copy(unsigned char **to, size_t *len, BIO *from)
{
    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(from, &mem);
    *len = mem->length;
    *to = malloc(*len);
    memcpy(*to, mem->data, *len);
}

void GM_SM4_test1()
{
    printf("sm4test1\n");
    EVP_CIPHER_CTX *ctx;
    BIO *in, *out;

    GM_SM4_KEY key = {0};
    GM_SM4_IV iv = {0};
    GM_SM4_rand_key(key, iv);
    print_hex("sm4key", key, sizeof(key));
    print_hex("sm4iv", iv, sizeof(iv));
    ctx = GM_SM4_new_encryptor(key, iv);
    out = BIO_new(BIO_s_mem());
    in = BIO_new_mem_buf(data, sizeof(data));
    cipher(out, in, ctx);
    BIO_free(in);
    size_t enclen;
    unsigned char *encdata;
    copy(&encdata, &enclen, out);
    BIO_free(out);
    GM_SM4_free(ctx);
    print_hex("sm4encdata", encdata, enclen);

    ctx = GM_SM4_new_decryptor(key, iv);
    out = BIO_new(BIO_s_mem());
    in = BIO_new_mem_buf(encdata, enclen);
    cipher(out, in, ctx);
    BIO_free(in);
    free(encdata);
    size_t declen;
    unsigned char *decdata;
    copy(&decdata, &declen, out);
    BIO_free(out);
    GM_SM4_free(ctx);
    print_str("sm4decdata", decdata);
    free(decdata);
}

void GM_SM4_test2()
{
    printf("sm4test2\n");
    GM_SM4_KEY key = {0};
    GM_SM4_IV iv = {0};
    GM_SM4_rand_key(key, iv);

    int dlen = sizeof(data);
    int enclen;
    unsigned char *encdata = malloc(GM_SM4_suggested_out_length(dlen));
    GM_SM4_encrypt(encdata, &enclen, data, dlen, key, iv);
    print_hex("sm4encdata", encdata, enclen);

    int declen;
    unsigned char *decdata = malloc(GM_SM4_suggested_out_length(enclen));
    GM_SM4_decrypt(decdata, &declen, encdata, enclen, key, iv);
    free(encdata);
    print_str("sm4decdata", decdata);
    free(decdata);
}

int main()
{
    GM_SM4_test1();
    GM_SM4_test2();
}
