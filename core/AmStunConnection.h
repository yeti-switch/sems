#ifndef AM_STUN_CONNECTION_H
#define AM_STUN_CONNECTION_H

#include "AmRtpConnection.h"
#include <commonincludes.hpp>
#include <stunreader.h>
#include <string>

using std::string;

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
    int priority;
    string local_password;
    string remote_password;
    string local_user;
    string remote_user;

    void check_request(CStunMessageReader* reader, sockaddr_storage* addr);
    void check_response(CStunMessageReader* reader, sockaddr_storage* addr);
    void send_request();
public:
    AmStunConnection(AmRtpTransport* _transport, struct sockaddr_storage* remote_addr, int priority);
    virtual ~AmStunConnection();

    void set_credentials(const string& luser, const string& lpassword,
                        const string& ruser, const string& rpassword);

    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr);

    AuthState getConnectionState();
};

#endif/*AM_STUN_CONNECTION_H*/
