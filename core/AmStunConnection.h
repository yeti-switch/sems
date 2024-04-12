#ifndef AM_STUN_CONNECTION_H
#define AM_STUN_CONNECTION_H

#include "AmRtpConnection.h"
#include "AmStunProcessor.h"
#include "sip/wheeltimer.h"
#include <stun/commonincludes.hpp>
#include <stun/stunreader.h>
#include <string>
#include <optional>

using std::string;

#define STUN_INTERVALS_COUNT    7

class AmStunConnection : public AmStreamConnection
{
private:
    enum AuthDirection {
        AUTH_RESPONSE = 0,
        AUTH_REQUEST,
        MAX_DIRECTION
    };

    AmStreamConnection* depend_conn;
    bool isAuthentificated[MAX_DIRECTION];
    int err_code;
    unsigned int priority;
    unsigned int lpriority;
    string local_password;
    string remote_password;
    string local_user;
    string remote_user;
    int count;
    int intervals[STUN_INTERVALS_COUNT+1];

    uint64_t local_tiebreaker;
    bool local_ice_role_is_controlled;

    void check_request(CStunMessageReader* reader, sockaddr_storage* addr);
    void check_response(CStunMessageReader* reader, sockaddr_storage* addr);
    void checkAllowPair();

    void change_ice_role();

public:
    AmStunConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, unsigned int lpriority, unsigned int priority = 0);
    virtual ~AmStunConnection();

    void set_credentials(const string& luser, const string& lpassword,
                        const string& ruser, const string& rpassword);

    void set_ice_role_controlled(bool ice_role_controlled) { this->local_ice_role_is_controlled = ice_role_controlled; }

    virtual void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time);

    void setDependentConnection(AmStreamConnection* conn);

    void send_request();
    bool isAllowPair();

    /** @return interval to be scheduled or nullopt */
    std::optional<unsigned long long> checkStunTimer();

    void updateStunTimer();
};

#endif/*AM_STUN_CONNECTION_H*/
