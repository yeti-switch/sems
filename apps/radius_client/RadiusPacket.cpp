#include "RadiusPacket.h"
#include "AmUtils.h"
#include "log.h"

#include "md5.h"
#include "string.h"

#pragma pack(push,1)
struct vendor_attr {
    uint8_t  type;
    uint8_t  length;
    uint32_t  vendor_id;
};
#pragma pack(pop)

RadiusPacket::RadiusPacket()
{
    init();
}

RadiusPacket::RadiusPacket(uint8_t code, uint8_t id)
{
    init();
    set_code(code);
    set_id(id);
    //build();
}

RadiusPacket::RadiusPacket(unsigned char *buf, unsigned int len)
{
    init();

    if(len > RAD_MAX_PACKET_SIZE)
        len = RAD_MAX_PACKET_SIZE;

    memcpy(&packet,buf,len);

    unsigned int attrs_offset = len-sizeof(static_header);
    attrs_tail+=attrs_offset;
}

RadiusPacket::~RadiusPacket()
{}

void RadiusPacket::init(){
    attrs_tail = (unsigned char *)&packet.attrs;
    attrs_end = attrs_tail+RAD_ATTRS_SIZE;
    attempt = 0;
}

int RadiusPacket::add_attr(uint8_t type, const char *buf, unsigned int len)
{
    unsigned int attr_len = len+2;

    if(attrs_tail + attr_len >= attrs_end){
        DBG("no space in packet buffer");
        return -1;
    }

    *attrs_tail++ = type;
    *attrs_tail++ = attr_len;
    memcpy(attrs_tail,buf,len);
    attrs_tail+=len;

    return 0;
}

int RadiusPacket::add_vendor_attr(uint8_t type, uint32_t vendor_id, uint8_t vendor_type, const char *buf, unsigned int len)
{
    struct vendor_attr va;

    unsigned int attr_len = len+sizeof(struct vendor_attr)+2;

    if(attrs_tail + attr_len >= attrs_end){
        DBG("no space in packet buffer");
        return -1;
    }

    //vsa header
    va.type = type;
    va.length = attr_len;
    va.vendor_id = htonl(vendor_id);
    memcpy(attrs_tail,&va,sizeof(struct vendor_attr));
    attrs_tail+=sizeof(struct vendor_attr);

    //incapsulated attribute
    *attrs_tail++ = vendor_type;
    *attrs_tail++ = len+2;
    memcpy(attrs_tail,buf,len);
    attrs_tail+=len;

    return 0;
}

void RadiusPacket::set_session_id(const string &session_id)
{
    request_session_id = session_id;
}

void RadiusPacket::set_expire(const struct timeval &timestamp)
{
    expire_at = timestamp;
}

int RadiusPacket::add_attr_string(uint8_t type,const string &s)
{
    return add_attr(type,s.data(),s.size());
}

int RadiusPacket::add_attr_int32(uint8_t type,uint32_t i)
{
    if(attrs_tail + sizeof(uint32_t) + 2 >= attrs_end){
        DBG("no space in packet buffer");
        return -1;
    }

    *attrs_tail++ = type;
    *attrs_tail++ = sizeof(uint32_t)+2;
    *(uint32_t *)attrs_tail = htonl(i); attrs_tail+=sizeof(uint32_t);

    return 0;
}

int RadiusPacket::add_vendor_attr_int32(uint8_t type, uint32_t vendor_id, uint8_t vendor_type, uint32_t i)
{
    struct vendor_attr va;

    unsigned int attr_len = sizeof(uint32_t)+sizeof(struct vendor_attr)+2;

    if(attrs_tail + attr_len >= attrs_end){
        DBG("no space in packet buffer");
        return -1;
    }

    //vsa header
    va.type = type;
    va.length = attr_len;
    va.vendor_id = htonl(vendor_id);
    memcpy(attrs_tail,&va,sizeof(struct vendor_attr));
    attrs_tail+=sizeof(struct vendor_attr);

    //incapsulated attribute
    *attrs_tail++ = vendor_type;
    *attrs_tail++ = sizeof(uint32_t)+2;
    *(uint32_t *)attrs_tail = htonl(i); attrs_tail+=sizeof(uint32_t);

    return 0;
}

void RadiusPacket::gen_auth(const string &secret)
{
    if(code()==AccountingRequest){
        /* rfc2866 3. Packet Format Request Authenticator
           Code + Identifier + Length +
           16 zero octets + request attributes + shared secret
        */
        MD5_CTX c;
        unsigned char *p = (unsigned char *)&packet.hdr.auth;

        memset(p,0,RAD_AUTH_SIZE);

        MD5Init(&c);
        MD5Update(&c, (unsigned char *)&packet, sizeof(struct cil_header));
        MD5Update(&c,p,RAD_AUTH_SIZE);
        MD5Update(&c,packet.attrs,len()-sizeof(static_header));
        MD5Update(&c,(const unsigned char *)secret.data(),secret.size());
        MD5Final(p,&c);

    } else {
        //random header
        unsigned int *p = (unsigned int *)&packet.hdr.auth;
        for(int i = 0;i<4;i++)
            *p++ = get_random();
    }
}

void RadiusPacket::build(const string &secret)
{
    packet.hdr.cil.len = htons(attrs_tail-(uint8_t *)&packet);
    gen_auth(secret);
}

int RadiusPacket::read_from_socket(int fd)
{
    int ret;
    ret = ::read(fd,&packet,RAD_MAX_PACKET_SIZE);
    if(ret == -1){
        ERROR("reading from socket: %s",strerror(errno));
        return -1;
    }
    gettimeofday(&netstamp,NULL);
    return 0;
}

int RadiusPacket::send(int fd)
{
    attempt++;
    DBG("send radius packet with code %d for session %s",\
        code(),session().c_str());
    gettimeofday(&netstamp,NULL);
    if(len()!=::send(fd,&packet,len(),0)){
        ERROR("error sending request: %s",strerror(errno));
        return -1;
    }
    return 0;
}

bool RadiusPacket::validate(const RadiusPacket &request, const string &secret)
{
    MD5_CTX c;
    unsigned char digest[16];

    if(len() > RAD_MAX_PACKET_SIZE){
        DBG("invalid reply length %id",len());
        return false;
    }

    MD5Init(&c);
    MD5Update(&c, (unsigned char *)&packet, sizeof(struct cil_header));
    MD5Update(&c,request.auth(),RAD_AUTH_SIZE);
    MD5Update(&c,packet.attrs,len()-sizeof(static_header));
    MD5Update(&c,(const unsigned char *)secret.data(),secret.size());
    MD5Final(digest,&c);

    if(0!=memcmp(digest,auth(),RAD_AUTH_SIZE)){
        ERROR("invalid authenticator in reply");
        return false;
    }

    return true;
}
