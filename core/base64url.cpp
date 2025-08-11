#include <string>
#include <array>

/*
Base64 translates 24 bits into 4 ASCII characters at a time. First,
3 8-bit bytes are treated as 4 6-bit groups. Those 4 groups are
translated into ASCII characters. That is, each 6-bit number is treated
as an index into the ASCII character array.

If the final set of bits is less 8 or 16 instead of 24, traditional base64
would add a padding character. However, if the length of the data is
known, then padding can be eliminated.

One difference between the "standard" Base64 is two characters are different.
See RFC 4648 for details.
This is how we end up with the Base64 URL encoding.
*/

const char base64_url_alphabet[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                     'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                     'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_' };

static const class Base64AlphabetCharSuperset : public std::array<int, 256> {
  public:
    Base64AlphabetCharSuperset()
    {
        fill(-1);
        for (unsigned int i = 0; i < 64; i++)
            at(base64_url_alphabet[i]) = i;
    }
} base64_alphabet_char_superset;

std::string base64_url_encode(const std::string_view &in)
{
    std::string out;
    int         val = 0, valb = -6;
    size_t      len = in.length();

    for (unsigned int i = 0; i < len; i++) {
        unsigned char c = in[i];
        val             = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_url_alphabet[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        out.push_back(base64_url_alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    return out;
}

bool base64_url_decode(const std::string_view &in, std::string &out)
{
    int val = 0, valb = -8;

    for (unsigned int i = 0; i < in.length(); i++) {
        unsigned char c = in[i];

        if (base64_alphabet_char_superset[c] == -1)
            return false;

        val = (val << 6) + base64_alphabet_char_superset[c];
        valb += 6;

        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return true;
}
