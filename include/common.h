#include <stddef.h>

#ifdef _WIN32
#ifdef __GNUC__
#define EXPORT __attribute__((dllexport))
#else
#define EXPORT __declspec(dllexport)
#endif
#else
#if __GNUC__ >= 4
#define EXPORT __attribute__((visibility("default")))
#else
#define EXPORT
#endif
#endif

#ifdef __cplusplus
extern "C"
{
#endif
    EXPORT unsigned long get_error(char *buf);
    EXPORT unsigned char *mem_new(unsigned char **data, size_t len);
    EXPORT void mem_free(unsigned char **data);
#ifdef __cplusplus
}
#endif