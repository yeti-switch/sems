#if defined __cpp_lib_format || defined __glibcxx_format
#include <format>
using std::format;
#else
// std::format polyfill using fmtlib
#define FMT_HEADER_ONLY
#include <fmt/format.h>
using fmt::format;
#endif
