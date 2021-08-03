#ifndef BASE64_URL_H
#define BASE64_URL_H

#include <string>

std::string base64_url_encode(const std::string & in);
bool base64_url_decode(const std::string & in, std::string& out);

#endif/*BASE64_URL_H*/
