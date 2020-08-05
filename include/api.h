#ifdef DLL_EXPORT
#define API __declspec(dllexport)
#else
#define API __declspec(dllimport)
#endif

typedef char RESULT;

#define RESULT_SUCCESS 1
#define RESULT_FAILURE 0
#define RESULT_ERROR -1

#define GM_result(value) value > 0 ? RESULT_SUCCESS : (value == 0 ? RESULT_FAILURE : RESULT_ERROR)