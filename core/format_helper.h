#if __has_include(<format>)
#include <format>
using std::format;
#else
// std::format polyfill using fmtlib
#define FMT_HEADER_ONLY
#include <fmt/format.h>
using fmt::format;
#endif
