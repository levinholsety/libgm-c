# libgm

使用OpenSSL实现国密SM2、SM3和SM4算法的C库。

## 编译动态库

```sh
gcc -DGM_DLL_EXPORT -std=c11 -shared -fPIC -s -ooutput/libgm.dll src/main/*.c -Llib -lcrypto -Iinclude
```

## 函数定义

`sm2.h`

```c
    // 新建SM2密钥。
    // @return SM2密钥。
    EVP_PKEY *GM_SM2_new_key();

    // 导入SM2密钥。
    // @param[in] priv SM2私钥PEM字符串。
    // @param[in] pub SM2公钥PEM字符串。
    // @return SM2密钥。
    EVP_PKEY *GM_SM2_import_key(const char *priv, const char *pub);

    // 释放SM2密钥拥有的资源。
    // @param[in] kp SM2密钥。
    void GM_SM2_free_key(EVP_PKEY *kp);

    // 从SM2密钥导出私钥。
    // @param[in] kp SM2密钥。
    // @return SM2私钥PEM字符串。
    char *GM_SM2_export_private(EVP_PKEY *kp);

    // 从SM2密钥导出公钥。
    // @param[in] kp SM2密钥。
    // @return SM2公钥PEM字符串。
    char *GM_SM2_export_public(EVP_PKEY *kp);

    // SM2加密。
    // @param[out] out 加密后的数据。
    // @param[out] outlen 加密后的数据的长度。
    // @param[in] in 需要加密的数据。
    // @param[in] inlen 需要加密的数据的长度。
    // @param[in] kp SM2密钥。
    // @return 成功返回1，否则返回0。
    int GM_SM2_encrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);

    // SM2解密。
    // @param[out] out 解密后的数据。
    // @param[out] outlen 解密后的数据的长度。
    // @param[in] in 需要解密的数据。
    // @param[in] inlen 需要解密的数据的长度。
    // @param[in] kp SM2密钥。
    // @return 成功返回1，否则返回0。
    int GM_SM2_decrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);

    // SM2签名。
    // @param[out] out 数据的签名。
    // @param[out] outlen 签名的长度。
    // @param[in] in 需要签名的数据。
    // @param[in] inlen 需要签名的数据的长度。
    // @param[in] kp SM2密钥。
    // @return 成功返回1，否则返回0。
    int GM_SM2_sign(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);

    // SM2验签。
    // @param[in] sig 数据的签名。
    // @param[in] siglen 签名的长度。
    // @param[in] in 需要验签的数据。
    // @param[in] inlen 需要验签的数据的长度。
    // @param[in] kp SM2密钥。
    // @return 验签成功返回1，验签失败返回0，错误返回-1。
    int GM_SM2_verify(const unsigned char *sig, size_t siglen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
```

说明：

SM2用于非对称加密。

`GM_SM2_new_key`新建一个密钥对。失败返回NULL。

`GM_SM2_free_key`释放由`GM_SM2_new_key`创建的密钥对拥有的资源。

`GM_SM2_export_private`、`GM_SM2_export_public`和`GM_SM2_import_key`用于将密钥对导出成字符串以及从字符串导入密钥对。失败返回NULL。

`GM_SM2_encrypt`方法进行数据加密。成功返回1，失败返回0。

`GM_SM2_decrypt`方法进行数据解密。成功返回1，失败返回0。

`GM_SM2_sign`方法进行数据签名。成功返回1，失败返回0。

`GM_SM2_verify`进行数据验签。验签成功返回1，验签失败返回0，错误返回-1。

---

`sm3.h`

```c
    // 新建并返回一个SM3上下文。
    // @return 返回SM3上下文。失败返回NULL。
    EVP_MD_CTX *GM_SM3_new();

    // 释放SM3上下文拥有的资源。
    void GM_SM3_free(EVP_MD_CTX *ctx);

    // 更新SM3上下文中的数据。
    // @param[in] ctx SM3上下文；
    // @param[in] in 需要更新的数据；
    // @param[in] inlen 数据长度。
    // @return 成功返回1，失败返回0。
    int GM_SM3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen);

    // 计算并返回SM3哈希值。
    // @param[in] ctx SM3上下文；
    // @param[in] md 用于存储返回的哈希值的变量指针。
    // @return 成功返回1，失败返回0。
    int GM_SM3_final(EVP_MD_CTX *ctx, GM_SM3_MD md);

    // 直接计算并返回SM3哈希值。
    // @param[in] md 用于存储返回的哈希值的变量指针。
    // @param[in] in 需要计算哈希值的数据；
    // @param[in] inlen 数据长度。
    // @return 成功返回1，失败返回0。
    int GM_SM3_digest(GM_SM3_MD md, const void *in, size_t inlen);
```

说明：

SM3用于计算数据哈希值。

`GM_SM3_digest`方法用于一次性数据转换。其它方法用于数据流转换。

---

`sm4.h`

```c
    // 生成随机密钥和静态向量。
    // @param[out] key 密钥。
    // @param[out] iv 静态向量。
    // @return 成功返回1，失败返回0。
    int GM_SM4_rand_key(GM_SM4_KEY key, GM_SM4_IV iv);

    // 新建SM4加密器。
    // @param[in] key 密钥。
    // @param[in] iv 静态向量。
    // @return SM4加密器上下文。
    EVP_CIPHER_CTX *GM_SM4_new_encryptor(const GM_SM4_KEY key, const GM_SM4_IV iv);

    // 新建SM4解密器。
    // @param[in] key 密钥。
    // @param[in] iv 静态向量。
    // @return SM4解密器上下文。
    EVP_CIPHER_CTX *GM_SM4_new_decryptor(const GM_SM4_KEY key, const GM_SM4_IV iv);

    // 释放上下文拥有的资源。
    // @param[in] ctx SM4加密器或解密器的上下文。
    void GM_SM4_free(EVP_CIPHER_CTX *ctx);

    // 往上下文中更新数据进行加密/解密转换并获取转换后的数据。
    // @param[in] ctx 上下文。
    // @param[out] out 转换后的数据。
    // @param[out] outlen 转换后的数据的长度。
    // @param[in] in 本次更新的数据。
    // @param[in] inlen 本次更新的数据的长度。
    // @return 成功返回1，失败返回0。
    int GM_SM4_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen, const unsigned char *in, int inlen);

    // 执行最后一次加密/解密转换并获取转换后的数据。
    // @param[in] ctx 上下文。
    // @param[out] out 转换后的数据。
    // @param[out] outlen 转换后的数据的长度。
    // @return 成功返回1，失败返回0。
    int GM_SM4_final(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen);

    // 直接加密数据。
    // @param[out] out 加密后的数据。如果该参数为NULL，则函数只会评估加密后的数据的长度。
    // @param[out] outlen 加密后的数据的长度。
    // @param[in] in 需要加密的数据。
    // @param[in] inlen 需要加密的数据的长度。
    // @param[in] key 密钥。
    // @param[in] iv 静态向量。
    // @return 成功返回1，失败返回0。
    int GM_SM4_encrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv);

    // 直接解密数据。
    // @param[out] out 解密后的数据。如果该参数为NULL，则函数只会评估解密后的数据的长度。
    // @param[out] outlen 解密后的数据的长度。
    // @param[in] in 需要解密的数据。
    // @param[in] inlen 需要解密的数据的长度。
    // @param[in] key 密钥。
    // @param[in] iv 静态向量。
    // @return 成功返回1，失败返回0。
    int GM_SM4_decrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV iv);
```

说明：

SM4用于对称加密。

`GM_SM4_rand_key`方法用于生成随机密钥和静态向量。

`GM_SM4_new_encryptor`和`GM_SM4_new_decryptor`分别用于产生加密和解密的上下文，使用完需要用`GM_SM4_free`方法释放资源。

`GM_SM4_update`和`GM_SM4_final`用于使用相应的加密或解密上下文进行数据转换。

`GM_SM4_encrypt`和`GM_SM4_decrypt`用于一次性数据加密或解密。