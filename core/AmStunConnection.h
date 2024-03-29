#ifndef AM_STUN_CONNECTION_H
#define AM_STUN_CONNECTION_H

#include "AmRtpConnection.h"
#include "AmStunProcessor.h"
#include "sip/wheeltimer.h"
#include <stun/commonincludes.hpp>
#include <stun/stunreader.h>
#include <string>

using std::string;

#define STUN_INTERVALS_COUNT    7

class AmStunConnection : public AmStreamConnection
{
private:
    AmStreamConnection* depend_conn;
    bool isAuthentificated;
    int err_code;
    int priority;
    string local_password;
    string remote_password;
    string local_user;
    string remote_user;
    int count;
    int intervals[STUN_INTERVALS_COUNT+1];

    void check_request(CStunMessageReader* reader, sockaddr_storage* addr);
    void check_response(CStunMessageReader* reader, sockaddr_storage* addr);
public:
    AmStunConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, int priority);
    virtual ~AmStunConnection();

    void set_credentials(const string& luser, const string& lpassword,
                        const string& ruser, const string& rpassword);

    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time);

    void setDependentConnection(AmStreamConnection* conn);

    void send_request();
    void updateStunTimer(bool remove = true);
    bool getConnectionState();
};

#endif/*AM_STUN_CONNECTION_H*/
