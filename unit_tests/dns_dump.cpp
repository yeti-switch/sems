#include <string.h>
#include <string>
#include <string_view>
#include <map>
#include "dns_dump.h"

/**
    ns_class: ns_c_in(1) Internet.
    ns_type:  ns_t_a(1), ns_t_aaaa(28), ns_t_srv(33)
*/

/** _sip._udp.test.invalid 60 IN SRV 0 0 5060 test.invalid. */
static const unsigned char _sip_udp_test_invalid_cl1_type33[] = {
    0x3B, 0xE1, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x5F, 0x73, 0x69, // |  ;............_si
    0x70, 0x04, 0x5F, 0x75, 0x64, 0x70, 0x04, 0x74,
    0x65, 0x73, 0x74, 0x07, 0x69, 0x6E, 0x76, 0x61, // |  p._udp.test.inva
    0x6C, 0x69, 0x64, 0x00, 0x00, 0x21, 0x00, 0x01,
    0xC0, 0x0C, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, // |  lid..!.....!....
    0x00, 0x3C, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
    0x13, 0xC4, 0x04, 0x74, 0x65, 0x73, 0x74, 0x07, // |  .<.........test.
    0x69, 0x6E, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x00  // |  invalid.
};

/** test.invalid 0 IN A 42.42.42.42 */
static const unsigned char test_invalid_cl1_type1[] = {
    0xDA, 0x08, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x74,
    0x65, 0x73, // |  .............tes
    0x74, 0x07, 0x69, 0x6E, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x00, 0x00, 0x01, 0x00, 0x01,
    0xC0, 0x0C,                                                                        // |  t.invalid.......
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x2A, 0x2A, 0x2A, 0x2A // |  ..........****
};

/** test.invalid 0 IN AAAA ::1 */
static const unsigned char test_invalid_cl1_type28[] = {
    0xE3, 0x75, 0x85, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x74, 0x65, 0x73, // |  .u...........tes
    0x74, 0x07, 0x69, 0x6E, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x00,
    0x00, 0x1C, 0x00, 0x01, 0xC0, 0x0C, // |  t.invalid.......
    0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                        // |  ................
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 // |  ..........
};

struct ns_key {
    std::string dname;
    int         cl, type;
    auto        operator<=>(const ns_key &) const = default;
    ns_key(std::string_view dname, int cl, int type)
        : dname{ dname }
        , cl{ cl }
        , type{ type }
    {
    }
};
using ns_entity = std::basic_string_view<unsigned char>;

std::map<ns_key, ns_entity> ns_db = {
    { { "_sip._udp.test.invalid", ns_c_in, ns_t_srv },
     { _sip_udp_test_invalid_cl1_type33, sizeof _sip_udp_test_invalid_cl1_type33 }                                },
    {             { "test.invalid", ns_c_in, ns_t_a },   { test_invalid_cl1_type1, sizeof test_invalid_cl1_type1 } },
    {          { "test.invalid", ns_c_in, ns_t_aaaa }, { test_invalid_cl1_type28, sizeof test_invalid_cl1_type28 } }
};

#ifdef DNS_DUMP_DEBUG
static void DumpHex(const void *data, size_t size)
{
    char   ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}
#endif

int dns_dump_res_search(const char *dname, int cl, int type, unsigned char *answer, int anslen) __THROW
{
    int              ret = -1;
    std::string_view name{ dname };

    // omit final dot
    if (name.ends_with("."))
        name.remove_suffix(1);

    if (auto it = ns_db.find({ name, cl, type }); it != ns_db.end()) {
        const auto &ns_entity = it->second;
        if ((int)ns_entity.size() <= anslen) {
            memcpy(answer, ns_entity.data(), ns_entity.size());
            ret = ns_entity.size();
        }
    }

#ifdef DNS_DUMP_DEBUG
    /** fallthrough to libresolv */
    bool real = false;
    if (ret < 0)
        real = true, ret = real_res_search(dname, cl, type, answer, anslen);
    fprintf(stderr, "%s res_search(): '%s' cl=%d type=%d length=%d\n", real ? "REAL" : "MOCK", dname, cl, type, ret);
    if (ret > 0)
        DumpHex(answer, ret);
#endif

    return ret;
}
