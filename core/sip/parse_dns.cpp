#include <string.h>

#include "parse_dns.h"
#include "resolver.h"

#define SECTION_COUNTS_OFF 4
#define HEADER_OFFSET      12

unsigned short dns_msg_count(u_char* begin, dns_section_type sect);
int dns_skip_name(u_char** p, u_char* end);
int dns_expand_name(
    u_char** ptr, u_char* begin, u_char* end,
    u_char* buf, unsigned int len);


const char* dns_rr_type_str(dns_rr_type rr_type, unsigned short addr_type)
{
    switch(rr_type) {
        case dns_r_ns:    return "NS";
        case dns_r_cname: return "CNAME";
        case dns_r_srv:   return "SRV";
        case dns_r_naptr: return "NAPTR";
        case dns_r_ip:
            switch((address_type)addr_type) {
                case IPv4: return "A";
                case IPv6: return "AAAA";
                default:   return "A or AAAA";
            };
        default: return "UNKNOWN";
    };
}

ns_type dns_rr_type_tons_type(dns_rr_type rr_type, unsigned short addr_type)
{
    switch(rr_type) {
        case dns_r_ns:    return ns_t_ns;
        case dns_r_cname: return ns_t_cname;
        case dns_r_srv:   return ns_t_srv;
        case dns_r_naptr: return ns_t_naptr;
        case dns_r_ip:
            switch((address_type)addr_type) {
                case IPv4: return ns_t_a;
                case IPv6: return ns_t_aaaa;
                default:;
            };
        default: return ns_t_invalid;
    };
}


int dns_msg_parse(u_char* msg, int len, dns_parse_fct fct, void* data)
{
    int ret;
    u_char* begin = msg;
    u_char* p = begin + HEADER_OFFSET;
    u_char* end = msg + len;

    if(p >= end) return -1;

    // skip query section
    for(int i=0; i<dns_msg_count(begin,dns_s_qd); i++){
        // query name
        if(dns_skip_name(&p,end) < 0) return -1;
        // skip query type+class
        if((p += 4) > end) return -1;
    }

    dns_record rr;
    for(int s = (int)dns_s_an;
        s < (int)__dns_max_sections;
        ++s)
    {
        for(int i = 0;
            i < dns_msg_count(begin,(dns_section_type)s);
            i++)
        {
            // expand name
            if((ret = dns_expand_name(
                &p, begin, end,
                (u_char*)rr.name, NS_MAXDNAME)) < 0)
            {
                DBG("dns_expand_name failed: %d", ret);
                return -1;
            }

            // at least 8 bytes for type+class+ttl left?
            if((p + 8) > end) return -1;

            rr.type = dns_get_16(p);
            p += 2;

            rr.rr_class = dns_get_16(p);
            p += 2;

            rr.ttl = dns_get_32(p);
            p+= 4;

            // fetch rdata len
            if(p+2 > end) return -1;

            rr.rdata_len = *(p++) << 8;
            rr.rdata_len |= *(p++);
            rr.rdata = p;

            // skip rdata
            if((p += rr.rdata_len) > end)
                return -1;

            // call provided function
            if(fct && (*fct)(&rr,(dns_section_type)s,begin,end,data))
                return -1;
        } //loop over section's entries
    } //loop over sections

    return 0;
}

unsigned short dns_msg_count(u_char* begin, dns_section_type sect)
{
    u_char* p = begin + SECTION_COUNTS_OFF + 2*sect;

    return ((u_short)*p)<<8 | ((u_short)*(p+1));
}

int dns_skip_name(u_char** p, u_char* end)
{
    while(*p < end) {
        if(!**p) { // zero label
            if(++(*p) < end)	return 0;
            return -1;
        }
        else if(**p & 0xC0) { // ptr
            if((*p += 2) < end) return 0;
            return -1;
        }
        else { // label
            *p += **p+1;
        }
    }

    return -1;
}

int dns_expand_name(
    u_char** ptr, u_char* begin, u_char* end,
    u_char* start_buf, unsigned int len)
{
    enum dns_expand_name_errors {
        GENERIC = 1,
        END_OF_LABEL,
        NAME_PTR_SIZE_OVERFLOW,
        NO_DATA_AFTER_NAME_PTR,
        NAME_PTR_OFFSET_OVERFLOW,
        RECURSIVE_PTR,
        LABEL_SIZE_OVERFLOW,
        LABEL_LENGTH_OVERFLOW,
        MALFORMED_TRAILING_LABEL
    };

    u_char* buf = start_buf;
    u_char* p = *ptr;
    bool    is_ptr = false;

    while(p < end) {

        if(!*p) { // reached the end of a label
            if(len) {
                *buf = '\0'; // zero-term
                if(!is_ptr) {
                    *ptr = p+1;
                }
                return (buf-start_buf);
            }
            return -END_OF_LABEL;
        }

        if( (*p & 0xC0) == 0xC0 ) { // ptr

            unsigned short l_off = (((unsigned short)*p & 0x3F) << 8);
            if(++p >= end) return -NAME_PTR_SIZE_OVERFLOW;
            l_off |= *p;
            if(++p >= end) return -NO_DATA_AFTER_NAME_PTR;

            if(begin + l_off + 1 >= end) return -NAME_PTR_OFFSET_OVERFLOW;

            if(!is_ptr) {
                *ptr = p;
                is_ptr = true;
            }

            p = begin + l_off;
            continue;
        }

        if( (*p & 0x3F) != *p ) { // NOT a label
            return -RECURSIVE_PTR;
        }

        if(p + *p + 1 >= end) return -LABEL_SIZE_OVERFLOW;
        if(len <= *p) return -LABEL_LENGTH_OVERFLOW;

        memcpy(buf,p+1,*p);
        len -= *p;
        buf += *p;
        p += *p + 1;

        if(*p) {
            if(!(--len)) return -MALFORMED_TRAILING_LABEL;
            *(buf++) = '.';
        }
    } //while(p < end)

    return -GENERIC;
}
