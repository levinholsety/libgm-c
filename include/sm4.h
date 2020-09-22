#include "gm.h"
#include "openssl/evp.h"

typedef unsigned char GM_SM4_KEY[16];
typedef unsigned char GM_SM4_IV[16];

#ifdef __cplusplus
extern "C"
{
#endif
    // 生成随机密钥和静态向量。
    // @param[out] key 密钥。
    // @param[out] iv 静态向量。
    // @return 成功返回1，失败返回0。
    GM_API int GM_SM4_rand_key(GM_SM4_KEY key, GM_SM4_IV iv);

    // 新建SM4加密器。
    // @param[in] key 密钥。
    // @param[in] iv 静态向量。
    // @return SM4加密器上下文。
    GM_API EVP_CIPHER_CTX *GM_SM4_new_encryptor(const GM_SM4_KEY key, const GM_SM4_IV iv);

    // 新建SM4解密器。
    // @param[in] key 密钥。
    // @param[in] iv 静态向量。
    // @return SM4解密器上下文。
    GM_API EVP_CIPHER_CTX *GM_SM4_new_decryptor(const GM_SM4_KEY key, const GM_SM4_IV iv);

    // 释放上下文拥有的资源。
    // @param[in] ctx SM4加密器或解密器的上下文。
    GM_API void GM_SM4_free(EVP_CIPHER_CTX *ctx);

    // 往上下文中更新数据进行加密/解密转换并获取转换后的数据。
    // @param[in] ctx 上下文。
    // @param[out] out 转换后的数据。
    // @param[out] outlen 转换后的数据的长度。
    // @param[in] in 本次更新的数据。
    // @param[in] inlen 本次更新的数据的长度。
    // @return 成功返回1，失败返回0。
    GM_API int GM_SM4_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen, const unsigned char *in, int inlen);

    // 执行最后一次加密/解密转换并获取转换后的数据。
    // @param[in] ctx 上下文。
    // @param[out] out 转换后的数据。
    // @param[out] outlen 转换后的数据的长度。
    // @return 成功返回1，失败返回0。
    GM_API int GM_SM4_final(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen);

    // 直接加密数据。
    // @param[out] out 加密后的数据。如果该参数为NULL，则函数只会评估加密后的数据的长度。
    // @param[out] outlen 加密后的数据的长度。
    // @param[in] in 需要加密的数据。
    // @param[in] inlen 需要加密的数据的长度。
    // @param[in] key 密钥。
    // @param[in] iv 静态向量。
    // @return 成功返回1，失败返回0。
    GM_API int GM_SM4_encrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv);

    // 直接解密数据。
    // @param[out] out 解密后的数据。如果该参数为NULL，则函数只会评估解密后的数据的长度。
    // @param[out] outlen 解密后的数据的长度。
    // @param[in] in 需要解密的数据。
    // @param[in] inlen 需要解密的数据的长度。
    // @param[in] key 密钥。
    // @param[in] iv 静态向量。
    // @return 成功返回1，失败返回0。
    GM_API int GM_SM4_decrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv);
#ifdef __cplusplus
}
#endif