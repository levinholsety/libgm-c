#include "gm.h"

#define GM_SM2_key_encode_private(pem, key) GM_SM2_key_encode(pem, key, 1)
#define GM_SM2_key_encode_public(pem, key) GM_SM2_key_encode(pem, key, 0)
#define GM_SM2_key_decode_private(key, pem) GM_SM2_key_decode(key, pem, 1)
#define GM_SM2_key_decode_public(key, pem) GM_SM2_key_decode(key, pem, 0)
#define GM_SM2_encrypt(out, out_len, in, in_len, key) GM_SM2_crypt(out, out_len, in, in_len, key, 1)
#define GM_SM2_decrypt(out, out_len, in, in_len, key) GM_SM2_crypt(out, out_len, in, in_len, key, 0)

#ifdef __cplusplus
extern "C"
{
#endif
    // 新建一个SM2密钥。
    // @return SM2密钥。失败则返回空指针。
    EC_KEY *GM_SM2_key_new();

    // 释放SM2密钥占用的资源。
    // @param key [in] SM2密钥。
    void GM_SM2_key_free(EC_KEY *key);

    // 编码SM2密钥。
    // @param pem [out] PEM格式的密钥字符串。不用时需要调用者释放资源。
    // @param key [in] SM2密钥。
    // @param pri [in] 需要编码的密钥类型。1表示私钥，0表示公钥。
    // @return 成功返回1，失败返回0。
    int GM_SM2_key_encode(char **pem, EC_KEY *key, int pri);

    // 解码SM2密钥。
    // @param key [out] SM2密钥。不用时需要调用者释放资源。
    // @param pem [in] PEM格式的密钥字符串。
    // @param pri [in] 需要解码的密钥类型。1表示私钥，0表示公钥。
    // @return 成功返回1，失败返回0。
    int GM_SM2_key_decode(EC_KEY **key, const char *pem, int pri);

    // 加密或解密。
    // @param out [out] 加密后或解密后的数据。不用时需要调用者释放资源。
    // @param out_len [out] 加密后或解密后的数据长度。
    // @param in [in] 需要加密或解密的数据。
    // @param in_len [in] 需要加密或解密的数据长度。
    // @param key [in] SM2密钥。
    // @param enc [in] 操作类型。1表示加密，0表示解密。
    // @return 成功返回1，失败返回0。
    int GM_SM2_crypt(unsigned char **out, size_t *out_len, const unsigned char *in, size_t in_len, EC_KEY *key, int enc);

    // 签名。
    // @param sig [out] 签名。不用时需要调用者释放资源。
    // @param sig_len [out] 签名长度。
    // @param data [in] 需要签名的数据。
    // @param data_len [in] 需要签名的数据长度。
    // @param id [in] 用户身份标识ID。SM2规范规定在用SM2签名时需要指定用户身份标识，无特殊约定的情况下，用户身份标识ID的长度为16个字节，其默认值从左至右依次为：0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38。
    // @param key [in] SM2密钥。
    // @return 成功返回1，失败返回0。
    int GM_SM2_sign(unsigned char **sig, size_t *sig_len, const unsigned char *data, size_t data_len, const unsigned char *id, EC_KEY *key);

    // 验签。
    // @param sig [in] 签名。
    // @param sig_len [in] 签名长度。
    // @param data [in] 需要验签的数据。
    // @param data_len [in] 需要验签的数据长度。
    // @param id [in] 用户身份标识ID。
    // @param key [in] SM2密钥。
    // @return 成功返回1，失败返回0。
    int GM_SM2_verify(const unsigned char *sig, size_t sig_len, const unsigned char *data, size_t data_len, unsigned char *id, EC_KEY *key);
#ifdef __cplusplus
}
#endif