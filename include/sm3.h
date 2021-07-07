#include "gm.h"
#include "stdio.h"

#ifdef __cplusplus
extern "C"
{
#endif
    // 计算数据的SM3消息摘要。
    // @param md [out] SM3消息摘要。需要事先分配32字节内存。
    // @param data [in] 需要计算SM3消息摘要的数据。
    // @param data_len [in] 数据长度。
    // @return 成功返回1，失败返回0。
    int GM_SM3_digest(unsigned char *md, const void *data, size_t data_len);

    // 计算文件的SM3消息摘要。
    // @param md [out] SM3消息摘要。需要事先分配32字节内存。
    // @param file [in] 需要计算SM3消息摘要的文件。
    // @return 成功返回1，失败返回0。
    int GM_SM3_digest_file(unsigned char *md, FILE *file);
#ifdef __cplusplus
}
#endif