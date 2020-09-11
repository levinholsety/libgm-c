#ifdef GM_DLL_EXPORT
#define GM_API __declspec(dllexport)
#else
#define GM_API __declspec(dllimport)
#endif
