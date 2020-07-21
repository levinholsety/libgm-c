#include <string.h>
#include "openssl/buffer.h"
#include "sm4.h"
#include "test.h"

void cipher(BIO *out, BIO *in, EVP_CIPHER_CTX *ctx)
{
    int buflen = 0x1000, cipherbuflen;
    size_t readlen;
    unsigned char *buf = malloc(buflen), *cipherbuf = malloc(GM_SM4_estimate_out_length(buflen));
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
    EVP_CIPHER_CTX *ctx;
    BIO *in, *out;

    unsigned char key[16] = {0}, iv[16] = {0};
    GM_SM4_rand_key(key, iv);
    print_hex(key, 16);
    print_hex(iv, 16);
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
    print_hex(encdata, enclen);

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
    print_str(decdata);
    free(decdata);
}

void GM_SM4_test2()
{
    unsigned char key[16] = {0}, iv[16] = {0};
    GM_SM4_rand_key(key, iv);

    int dlen = sizeof(data);
    int enclen;
    unsigned char *encdata = malloc(GM_SM4_estimate_out_length(dlen));
    GM_SM4_encrypt(encdata, &enclen, data, dlen, key, iv);
    printf("%d\n", enclen);
    print_hex(encdata, enclen);

    int declen;
    unsigned char *decdata = malloc(GM_SM4_estimate_out_length(enclen));
    GM_SM4_decrypt(decdata, &declen, encdata, enclen, key, iv);
    free(encdata);
    printf("%d\n", declen);
    print_str(decdata);
    free(decdata);
}

int main()
{
    GM_SM4_test1();
    GM_SM4_test2();
}
