# libgm

使用OpenSSL实现国密SM2、SM3和SM4算法的C库。

## 编译动态库

```sh
gcc -DGM_DLL_EXPORT -std=c11 -shared -fPIC -s -ooutput/libgm.dll src/main/*.c -Llib -lcrypto -Iinclude
```

## 函数定义

`sm2.h`

```c
    GM_API EVP_PKEY *GM_SM2_new_key();
    GM_API EVP_PKEY *GM_SM2_import_key(const char *priv, const char *pub);
    GM_API void GM_SM2_free_key(EVP_PKEY *kp);
    GM_API char *GM_SM2_export_private(EVP_PKEY *kp);
    GM_API char *GM_SM2_export_public(EVP_PKEY *kp);
    GM_API int GM_SM2_encrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    GM_API int GM_SM2_decrypt(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    GM_API int GM_SM2_sign(unsigned char **out, size_t *outlen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
    GM_API int GM_SM2_verify(const unsigned char *sig, size_t siglen, const unsigned char *in, size_t inlen, EVP_PKEY *kp);
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
    // 返回值：返回SM3上下文。失败返回NULL。
    GM_API EVP_MD_CTX *GM_SM3_new();

    // 释放SM3上下文拥有的资源。
    GM_API void GM_SM3_free(EVP_MD_CTX *ctx);

    // 更新SM3上下文中的数据。
    // 参数1：SM3上下文；
    // 参数2：需要更新的数据；
    // 参数3：数据长度。
    // 返回值：成功返回1，失败返回0。
    GM_API int GM_SM3_update(EVP_MD_CTX *ctx, const void *in, size_t inlen);

    // 计算并返回SM3哈希值。
    // 参数1：SM3上下文；
    // 参数2：用于存储返回的哈希值的变量指针。
    // 返回值：成功返回1，失败返回0。
    GM_API int GM_SM3_final(EVP_MD_CTX *ctx, GM_SM3_MD md);

    // 直接计算并返回SM3哈希值。
    // 参数1：用于存储返回的哈希值的变量指针。
    // 参数2：需要计算哈希值的数据；
    // 参数3：数据长度。
    // 返回值：成功返回1，失败返回0。
    GM_API int GM_SM3_digest(GM_SM3_MD md, const void *in, size_t inlen);
```

说明：

SM3用于计算数据哈希值。

`GM_SM3_digest`方法用于一次性数据转换。其它方法用于数据流转换。

---

`sm4.h`

```c
    GM_API int GM_SM4_rand_key(GM_SM4_KEY key, GM_SM4_IV iv);
    GM_API EVP_CIPHER_CTX *GM_SM4_new_encryptor(const GM_SM4_KEY key, const GM_SM4_IV);
    GM_API EVP_CIPHER_CTX *GM_SM4_new_decryptor(const GM_SM4_KEY key, const GM_SM4_IV);
    GM_API void GM_SM4_free(EVP_CIPHER_CTX *ctx);
    GM_API int GM_SM4_update(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen, const unsigned char *in, int inlen);
    GM_API int GM_SM4_final(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outlen);
    GM_API int GM_SM4_encrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV);
    GM_API int GM_SM4_decrypt(unsigned char *out, int *outlen, const unsigned char *in, int inlen, const GM_SM4_KEY key, const GM_SM4_IV);
```

说明：

SM4用于对称加密。

`GM_SM4_rand_key`方法用于生成随机密钥和静态向量。

`GM_SM4_new_encryptor`和`GM_SM4_new_decryptor`分别用于产生加密和解密的上下文，使用完需要用`GM_SM4_free`方法释放资源。

`GM_SM4_update`和`GM_SM4_final`用于使用相应的加密或解密上下文进行数据转换。

`GM_SM4_encrypt`和`GM_SM4_decrypt`用于一次性数据加密或解密。