#ifndef __cpp_lib_format
    // std::format polyfill using fmtlib
#   define FMT_HEADER_ONLY
#   include <fmt/format.h>
    using fmt::format;
#else
#   include <format>
    using std::format;
#endif
