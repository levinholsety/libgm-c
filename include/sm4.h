#include "gm.h"
#include "stdio.h"

#define GM_SM4_encrypt(out, out_len, in, in_len, key, iv) GM_SM4_crypt(out, out_len, in, in_len, key, iv, 1)
#define GM_SM4_decrypt(out, out_len, in, in_len, key, iv) GM_SM4_crypt(out, out_len, in, in_len, key, iv, 0)
#define GM_SM4_encrypt_file(dst, src, key, iv) GM_SM4_crypt_file(dst, src, key, iv, 1)
#define GM_SM4_decrypt_file(dst, src, key, iv) GM_SM4_crypt_file(dst, src, key, iv, 0)

#ifdef __cplusplus
extern "C"
{
#endif
    // 加密或解密。
    // @param out [out] 加密后或解密后的数据。需要事先分配(in_len+16)个字节的内存空间。
    // @param out_len [out] 加密后或解密后的数据长度。
    // @param in [in] 需要加密或解密的数据。
    // @param in_len [in] 需要加密或解密的数据长度。
    // @param key [in] 密钥。长度为16个字节。
    // @param iv [in] 静态向量。长度为16个字节。
    // @param enc [in] 操作类型。1表示加密，0表示解密。
    // @return 成功返回1，失败返回0。
    int GM_SM4_crypt(unsigned char *out, int *out_len, const unsigned char *in, int in_len, const unsigned char *key, const unsigned char *iv, int enc);

    // 加密或解密文件。
    // @param dst [out] 加密后或解密后的文件。
    // @param src [in] 需要加密或解密的文件。
    // @param key [in] 密钥。长度为16个字节。
    // @param iv [in] 静态向量。长度为16个字节。
    // @param enc [in] 操作类型。1表示加密，0表示解密。
    // @return 成功返回1，失败返回0。
    int GM_SM4_crypt_file(FILE *dst, FILE *src, const unsigned char *key, const unsigned char *iv, int enc);
#ifdef __cplusplus
}
#endif