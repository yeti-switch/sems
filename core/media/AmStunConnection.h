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
using std::multimap;

class AmRtpConnection;
class AmRtpStream;

#define STUN_INTERVALS_COUNT    7
#define STUN_TA_TIMEOUT 50
#define STUN_KEEPALIVE_TIMEOUT 2500

class ReferenceUniquePtr : public std::unique_ptr<AmStunConnection, void (*)(AmStunConnection* item) >
{
public:
    ReferenceUniquePtr(AmStunConnection* conn);

    void reset(AmStunConnection* conn);
    void reset(const ReferenceUniquePtr& ptr);

    operator AmStunConnection* ();
};

class IceContext
{
public:
    enum State{
        ICE_INITIAL = 0,
        ICE_CONNECTIVITY_CHECK,
        ICE_NOMINATIONS,
        ICE_KEEP_ALIVE
    };
private:
    AmRtpStream* stream;
    State  state;
    int type;
    AmMutex pairs_mut;
    multimap<unsigned int, ReferenceUniquePtr> pairs;

    map<int, sockaddr_storage> current_family_addr;
    ReferenceUniquePtr current_candidate;
public:
    void setCurrentCandidate(AmStunConnection* conn);
    AmStunConnection* getNominatedPair();
    void allowStunPair();
    void setState(State initial);
public:
    IceContext(AmRtpStream* stream, int type);
    ~IceContext();

    sockaddr_storage* getAllowedIceAddr(int family);
    AmMediaTransport* getCurrentTransport();

    int getType() { return type; }
    AmRtpStream* getStream() { return stream; }

    //functions for AmRtpStream and AmMediaTransport
    void initContext();
    void destroyContext();
    void addConnection(AmStunConnection* conn);
    void removeConnection(AmStunConnection* conn);
    void reset();

    //function for AmStunProcessor
    void updateStunTimers(std::unordered_map<AmStunConnection *, unsigned long long>& connections);

    //functions for AmStunConnection
    bool isUseCandidate(AmStunConnection* conn);
    void failedCandidate(AmStunConnection* conn);
    void allowCandidate(AmStunConnection* conn);
    void useCandidate(AmStunConnection* conn);
    void updateConnection(AmStunConnection* conn);
};

class AmStunConnection : public AmStreamConnection
{
public:
    enum PairState{
        PAIR_FROZEN = 0,
        PAIR_WAITING,
        PAIR_IN_PROGRESS,
        PAIR_RETRANSMIT,
        PAIR_FAILED,
        PAIR_SUCCEEDED
    };
    static string state2str(PairState state);
private:
    PairState state;

    unsigned int priority;
    unsigned int lpriority;
    string local_password;
    string remote_password;
    string local_user;
    string remote_user;

    StunTransactionId current_trans_id;
    int count;
    int retransmit_intervals[STUN_INTERVALS_COUNT];
    
    IceContext* context;

    void check_request(CStunMessageReader* reader, sockaddr_storage* addr);
    void check_response(CStunMessageReader* reader, sockaddr_storage* addr);
    void allow_candidate(bool use_candidate);

public:
    AmStunConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, unsigned int lpriority, unsigned int priority = 0);
    virtual ~AmStunConnection();

    void set_credentials(const string& luser, const string& lpassword,
                        const string& ruser, const string& rpassword);
    void setLocalPriority(unsigned int priority) { lpriority = priority; }

    unsigned int getPriority();

    void handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time) override;
    void handleSymmetricRtp(struct sockaddr_storage*, struct timeval*) override { /*symmetric rtp is disabled for ice*/ }
    void getInfo(AmArg & ret) override;

    void checkState();
    PairState getState() { return state; }
    void setState(PairState st) { state = st; }

    void send_request(StunTransactionId trans_id);
    void retransmit();

    /** @return interval to be scheduled or nullopt */
    std::optional<unsigned long long> checkStunTimer();
};

#endif/*AM_STUN_CONNECTION_H*/
