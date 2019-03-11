#ifndef AM_STUN_CLIENT_H
#define AM_STUN_CLIENT_H

#include "AmSdp.h"
#include <commonincludes.hpp>
#include <stunauth.h>
#include <stunreader.h>

class AmRtpStream;

struct StunCandidate
{
    typedef enum {
        NO_AUTH,
        CHECK_OTHER,
        ALLOW,
        ERROR
    } auth_state;
    auth_state state;
    int priority;
    sockaddr_storage l_sa;
    sockaddr_storage r_sa;
    
    bool operator == (sockaddr_storage* sa) {
        return memcmp(sa, &r_sa, (sa->ss_family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)) == 0;
    }
};

class AmStunClient
{
    std::vector<StunCandidate> pairs;
    string local_password;
    string remote_password;
    string local_user;
    string remote_user;
    AmRtpStream* rtp_stream;
public:
    AmStunClient(AmRtpStream* rtp_stream);
    ~AmStunClient();
    
    void set_credentials(const string& luser, const string& lpassword,
                        const string& ruser, const string& rpassword);
    
    void add_candidate(int priority, sockaddr_storage l_sa, sockaddr_storage r_sa);
    
    void on_data_recv(uint8_t* data, unsigned int size, sockaddr_storage* addr);
    
private:
    void check_request(CStunMessageReader* reader, sockaddr_storage* addr);
};

#endif/*AM_STUN_CLIENT_H*/
