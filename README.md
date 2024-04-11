# 环境

程序基于openssl-3.2.1编写，编译前需要设置`OPENSSL`环境变量指向openssl安装目录。

# 编译

```bash
make
```

# 说明

## SM2

数据格式可以参考《GB/T 35276-2017 信息安全技术 SM2密码算法使用规范》。

```c
int sm2_key_pair_new(unsigned char *pub, size_t *pub_len, unsigned char *pri, size_t *pri_len);
int sm2_encrypt(unsigned char **out, size_t *out_len, const unsigned char *in, size_t in_len, const unsigned char *pub, size_t pub_len);
int sm2_decrypt(unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len, const unsigned char *pri, size_t pri_len);
int sm2_sign(unsigned char *sig, size_t *sig_len, const unsigned char *in, size_t in_len, const unsigned char *pri, size_t pri_len);
int sm2_verify(const unsigned char *sig, size_t sig_len, const unsigned char *in, size_t in_len, const unsigned char *pub, size_t pub_len);
SM2_SIG_CTX *sm2_sig_ctx_new(const unsigned char *key, size_t key_len, int is_pri);
void sm2_sig_ctx_free(SM2_SIG_CTX *ctx);
int sm2_sig_update(SM2_SIG_CTX *ctx, const unsigned char *in, size_t in_len);
int sm2_sig_sign(SM2_SIG_CTX *ctx, unsigned char *sig, size_t *sig_len);
int sm2_sig_verify(SM2_SIG_CTX *ctx, const unsigned char *sig, size_t sig_len);
```

### sm2_key_pair_new

新建SM2密钥对。

| 参数    | 类型            | 说明                        |
| ------- | --------------- | --------------------------- |
| pub     | unsigned char * | [out]用于接收公钥的缓冲区。 |
| pub_len | size_t *        | [out]用于接收公钥长度。     |
| pri     | unsigned char * | [out]用于接收私钥的缓冲区。 |
| pri_len | size_t *        | [out]用于接收私钥长度。     |

返回1表示成功，0表示失败。

### sm2_encrypt

加密。

| 参数    | 类型                  | 说明                                  |
| ------- | --------------------- | ------------------------------------- |
| out     | unsigned char **      | [out]用于接收加密数据的缓冲区的指针。 |
| out_len | size_t *              | [out]用于接收加密数据长度。           |
| in      | const unsigned char * | 需要加密的数据。                      |
| in_len  | size_t                | 需要加密的数据长度。                  |
| pub     | const unsigned char * | 公钥。                                |
| pub_len | size_t                | 公钥长度。                            |

返回1表示成功，0表示失败。

### sm2_decrypt

解密。

| 参数    | 类型                  | 说明                                                         |
| ------- | --------------------- | ------------------------------------------------------------ |
| out     | unsigned char *       | [out]用于接收解密数据的缓冲区。需要的缓冲区大小不会超过需要加密的数据长度。 |
| out_len | size_t *              | [out]用于接收解密数据长度。                                  |
| in      | const unsigned char * | 需要解密的数据。                                             |
| in_len  | size_t                | 需要解密的数据长度。                                         |
| pri     | const unsigned char * | 私钥。                                                       |
| pri_len | size_t                | 私钥长度。                                                   |

返回1表示成功，0表示失败。

### sm2_sign

签名。

| 参数    | 类型                  | 说明                                                    |
| ------- | --------------------- | ------------------------------------------------------- |
| sig     | unsigned char *       | [out]用于接收签名的缓冲区。需要的缓冲区大小不会超过72。 |
| sig_len | size_t *              | [out]签名长度。                                         |
| in      | const unsigned char * | 需要签名的数据。                                        |
| in_len  | size_t                | 需要签名的数据长度。                                    |
| pri     | const unsigned char * | 私钥。                                                  |
| pri_len | size_t                | 私钥长度。                                              |

返回1表示成功，0表示失败。

### sm2_verify

验签。

| 参数    | 类型                  | 说明                 |
| ------- | --------------------- | -------------------- |
| sig     | const unsigned char * | 签名。               |
| sig_len | size_t                | 签名长度。           |
| in      | const unsigned char * | 需要验签的数据。     |
| in_len  | size_t                | 需要验签的数据长度。 |
| pub     | const unsigned char * | 公钥。               |
| pub_len | size_t                | 公钥长度。           |

返回1表示成功，0表示失败。

## SM3

### sm3_digest

摘要。

| 参数   | 类型                  | 说明                                                      |
| ------ | --------------------- | --------------------------------------------------------- |
| md     | unsigned char *       | [out]用于接收哈希值的缓冲区。需要的缓冲区大小不会超过32。 |
| md_len | unsigned int *        | [out]用于接收哈希值长度。                                 |
| in     | const unsigned char * | 需要计算哈希值的数据。                                    |
| in_len | size_t                | 需要计算哈希值的数据长度。                                |

返回1表示成功，0表示失败。

## SM4

### sm4_generate_key

生成密钥。

| 参数 | 类型            | 说明                                              |
| ---- | --------------- | ------------------------------------------------- |
| key  | unsigned char * | [out]用于接收密钥的缓冲区。需要的缓冲区大小为16。 |

返回1表示成功，0表示失败。

### sm4_crypt

加/解密。

| 参数    | 类型                  | 说明                                                         |
| ------- | --------------------- | ------------------------------------------------------------ |
| out     | unsigned char *       | [out]用于接收加/解密数据的缓冲区。加密数据需要的缓冲区大小不会超过待加密数据长度加16，解密数据需要的缓冲区大小不会超过待解密数据长度。 |
| out_len | int *                 | [out]用于接收加/解密数据长度。                               |
| in      | const unsigned char * | 待加/解密数据。                                              |
| in_len  | int                   | 待加/解密数据长度。                                          |
| mode    | int                   | 模式。1-ECB；2-CBC。                                         |
| key     | const unsigned char * | 密钥。                                                       |
| iv      | const unsigned char * | 模式为CBC时需要设置初始向量。                                |
| enc     | int                   | 是否为加密。0表示解密，其它表示加密。                        |

### 宏

```c
#define sm4_enc_max_size(size) ...
#define sm4_dec_max_size(size) ...
#define sm4_encrypt_ecb(out, out_len, in, in_len, key) ...
#define sm4_decrypt_ecb(out, out_len, in, in_len, key) ...
#define sm4_encrypt_cbc(out, out_len, in, in_len, key, iv) ...
#define sm4_decrypt_cbc(out, out_len, in, in_len, key, iv) ...
```

