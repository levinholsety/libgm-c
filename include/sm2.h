#include "gm.h"
#include "openssl/evp.h"

#ifdef __cplusplus
extern "C"
{
#endif
    // 新建SM2密钥。
    // @return SM2密钥。
    GM_API EVP_PKEY *GM_SM2_new_key();

    // 导入SM2密钥。
    // @param[in] priv SM2私钥PEM字符串。
    // @param[in] pub SM2公钥PEM字符串。
    // @return SM2密钥。
    GM_API EVP_PKEY *GM_SM2_import_key(const char *priv, const char *pub);

    // 释放SM2密钥拥有的资源。
    // @param[in] kp SM2密钥。
    GM_API void GM_SM2_free_key(EVP_PKEY *kp);

    // 从SM2密钥导出私钥。
    // @param[in] kp SM2密钥。
    // @return SM2私钥PEM字符串。
    GM_API char *GM_SM2_export_private(EVP_PKEY *kp);

    // 从SM2密钥导出公钥。
    // @param[in] kp SM2密钥。
    // @return SM2公钥PEM字符串。
    GM_API char *GM_SM2_export_public(EVP_PKEY *kp);

    // SM2加密。
    // @param[out] out 加密后的数据。
    // @param[out] outlen 加密后的数据的长度。
    // @param[in] in 需要加密的数据。
    // @param[in] inlen 需要加密的数据的长度。
    // @param[in] kp SM2密钥。
    // @return 成功返回1，否则返回0。
    GM_API int GM_SM2_encrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);

    // SM2解密。
    // @param[out] out 解密后的数据。
    // @param[out] outlen 解密后的数据的长度。
    // @param[in] in 需要解密的数据。
    // @param[in] inlen 需要解密的数据的长度。
    // @param[in] kp SM2密钥。
    // @return 成功返回1，否则返回0。
    GM_API int GM_SM2_decrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);

    // SM2签名。
    // @param[out] out 数据的签名。
    // @param[out] outlen 签名的长度。
    // @param[in] in 需要签名的数据。
    // @param[in] inlen 需要签名的数据的长度。
    // @param[in] kp SM2密钥。
    // @return 成功返回1，否则返回0。
    GM_API int GM_SM2_sign(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);

    // SM2验签。
    // @param[in] sig 数据的签名。
    // @param[in] siglen 签名的长度。
    // @param[in] in 需要验签的数据。
    // @param[in] inlen 需要验签的数据的长度。
    // @param[in] kp SM2密钥。
    // @return 验签成功返回1，验签失败返回0，错误返回-1。
    GM_API int GM_SM2_verify(const unsigned char *sig, size_t siglen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
#ifdef __cplusplus
}
#endif