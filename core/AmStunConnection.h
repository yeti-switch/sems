#ifndef AM_STUN_CONNECTION_H
#define AM_STUN_CONNECTION_H

#include "AmRtpConnection.h"
#include "AmStunProcessor.h"
#include "sip/wheeltimer.h"
#include <commonincludes.hpp>
#include <stunreader.h>
#include <string>

using std::string;

class StunTimer : public timer
{
    sp_addr spaddr;
public:
    StunTimer(const sp_addr& addr, uint32_t duration);
    void updateTimer(uint32_t duration);
    void fire() override;
};

class AmStunConnection : public AmStreamConnection
{
public:
    enum AuthState{
        NO_AUTH,
        CHECK_OTHER,
        ALLOW,
        ERROR
    };
private:
    AuthState auth_state;
    int err_code;
    int priority;
    string local_password;
    string remote_password;
    string local_user;
    string remote_user;
    StunTimer* timer;

    void check_request(CStunMessageReader* reader, sockaddr_storage* addr);
    void check_response(CStunMessageReader* reader, sockaddr_storage* addr);
public:
    AmStunConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, int priority);
    virtual ~AmStunConnection();

    void set_credentials(const string& luser, const string& lpassword,
                        const string& ruser, const string& rpassword);

    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time);

    void send_request();
    void updateStunTimer();
    AuthState getConnectionState();
};

#endif/*AM_STUN_CONNECTION_H*/
