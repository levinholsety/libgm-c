#include "sm2.h"
#include "test.h"

int main()
{
    EVP_PKEY *kp;
    kp = GM_SM2_new_key();
    char *private_key = GM_SM2_export_private(kp);
    char *public_key = GM_SM2_export_public(kp);
    GM_SM2_free_key(kp);
    print_str("sm2privatekey", private_key);
    print_str("sm2publickey", public_key);

    size_t enclen;
    unsigned char *encdata;
    kp = GM_SM2_import_key(NULL, public_key);
    GM_SM2_encrypt(&encdata, &enclen, data, sizeof(data), kp);
    GM_SM2_free_key(kp);
    print_hex("sm2encdata", encdata, enclen);

    size_t declen;
    unsigned char *decdata;
    kp = GM_SM2_import_key(private_key, NULL);
    GM_SM2_decrypt(&decdata, &declen, encdata, enclen, kp);
    GM_SM2_free_key(kp);
    free(encdata);
    print_str("sm2decdata", decdata);
    free(decdata);

    printf("sign data\n");
    size_t siglen;
    unsigned char *sig;
    kp = GM_SM2_import_key(private_key, NULL);
    GM_SM2_sign(&sig, &siglen, data, sizeof(data), kp);
    GM_SM2_free_key(kp);
    print_hex("sm2sig", sig, siglen);

    kp = GM_SM2_import_key(NULL, public_key);
    int verified = GM_SM2_verify(sig, siglen, data, sizeof(data), kp);
    GM_SM2_free_key(kp);
    free(sig);
    printf("%s\n", verified ? "verified" : "not verified");

    free(private_key);
    free(public_key);
}
