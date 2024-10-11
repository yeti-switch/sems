#ifndef BASE64_URL_H
#define BASE64_URL_H

#include <string>

std::string base64_url_encode(const std::string_view & in);
bool base64_url_decode(const std::string_view & in, std::string& out);

#endif/*BASE64_URL_H*/
