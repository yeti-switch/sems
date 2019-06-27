#ifndef AM_STUN_CLIENT_H
#define AM_STUN_CLIENT_H

#include "AmSdp.h"
#include <commonincludes.hpp>
#include <stunreader.h>

class AmRtpStream;
class msg_logger;

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
    bool isrtcp;
    sockaddr_storage l_saddr;
public:
    AmStunClient(AmRtpStream* rtp_stream, bool b_rtcp);
    ~AmStunClient();
    
    void setLocalAddr(struct sockaddr_storage& saddr);

    void set_credentials(const string& luser, const string& lpassword,
                        const string& ruser, const string& rpassword);
    
    void add_candidate(int priority, sockaddr_storage l_sa, sockaddr_storage r_sa);
    
    void on_data_recv(uint8_t* data, unsigned int size, sockaddr_storage* addr);

    void logReceivedPacket(msg_logger* logger, uint8_t* data, unsigned int size, sockaddr_storage* addr);

private:
    void check_request(CStunMessageReader* reader, sockaddr_storage* addr);
    void check_response(CStunMessageReader* reader, sockaddr_storage* addr);
    void send_request(StunCandidate candidate);
};

#endif/*AM_STUN_CLIENT_H*/
