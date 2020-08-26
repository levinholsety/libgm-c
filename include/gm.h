
#ifdef GM_DLL_EXPORT
#define GM_API __declspec(dllexport)
#else
#define GM_API __declspec(dllimport)
#endif

typedef char RESULT;
#define RESULT_SUCCESS 1
#define RESULT_FAILURE 0
#define RESULT_ERROR -1
