#include "log.h"
#include "AmStunConnection.h"
#include "AmMediaTransport.h"
#include "AmRtpStream.h"
#include "AmConcurrentVector.h"
#include "stun/stunbuilder.h"
#include "sip/ip_util.h"

#include <endian.h>

#define STUN_ERROR_ROLECONFLICT 487
#define STUN_ERROR_INCORRECT_TRANSID 404

static const uint16_t STUN_ATTRIBUTE_USE_CANDIDATE = 0x0025;

ReferenceUniquePtr::ReferenceUniquePtr(AmStunConnection* conn)
 : std::unique_ptr<AmStunConnection, void (*)(AmStunConnection* item) >(conn, ReferenceDeleter){
     if(conn) inc_ref(conn);
}
 
void ReferenceUniquePtr::reset(AmStunConnection* conn)
{
    if(conn) inc_ref(conn);
    std::unique_ptr<AmStunConnection, void (*)(AmStunConnection* item) >::reset(conn);
}

void ReferenceUniquePtr::reset(const ReferenceUniquePtr& ptr)
{
    if(ptr) inc_ref(ptr.get());
    std::unique_ptr<AmStunConnection, void (*)(AmStunConnection* item) >::reset(ptr.get());
}

ReferenceUniquePtr::operator AmStunConnection *()
{
    return get();
}

IceContext::IceContext(AmRtpStream* stream, int type)
: stream(stream)
, state(ICE_INITIAL)
, type(type)
, current_candidate(nullptr)
{
    CLASS_DBG("IceContext(): transport type %d", type);
    stun_processor::instance()->add_ice_context(this);
}
IceContext::~IceContext() {}

void IceContext::addConnection(AmStunConnection* conn) {
    CLASS_DBG("add pair in ice context %s:%u/%s:%u, priority %u",
              conn->getTransport()->getLocalIP().c_str(), conn->getTransport()->getLocalPort(),
              conn->getRHost().c_str(), conn->getRPort(), conn->getPriority());
    AmLock lock(pairs_mut);
    pairs.emplace(conn->getPriority(), conn);
    if(state == ICE_KEEP_ALIVE ||
       state == ICE_NOMINATIONS)
        state = ICE_CONNECTIVITY_CHECK;
}

void IceContext::updateConnection(AmStunConnection* conn)
{
    CLASS_DBG("update pair in ice context %s:%u/%s:%u, priority %u",
              conn->getTransport()->getLocalIP().c_str(), conn->getTransport()->getLocalPort(),
              conn->getRHost().c_str(), conn->getRPort(), conn->getPriority());

    ReferenceGuard guard(conn);
    removeConnection(conn);
    addConnection(conn);
}

void IceContext::removeConnection(AmStunConnection* conn)
{
    AmLock lock(pairs_mut);
    for(auto pair = pairs.begin(); pair != pairs.end(); pair++) {
        if(pair->second == conn) {
            pairs.erase(pair);
            break;
        }
    }
}

void IceContext::useCandidate(AmStunConnection* conn)
{
    switch(state) {
    case ICE_NOMINATIONS:
    case ICE_KEEP_ALIVE:
        setCurrentCandidate(conn);
        allowStunPair();
        break;
    case ICE_CONNECTIVITY_CHECK: 
        DBG("use candidate in incorrect ice state %d", state);
        break;
    default: break;
    }
}

void IceContext::initContext()
{
    if(state == ICE_INITIAL) {
        {
            AmLock lock(pairs_mut);
            if(!pairs.empty())
                pairs.rbegin()->second->setState(AmStunConnection::PAIR_WAITING);
        }

        setCurrentCandidate(nullptr);
        state = ICE_CONNECTIVITY_CHECK;
    }
}

void IceContext::destroyContext()
{
    stun_processor::instance()->remove_ice_context(this);
    reset();
}

AmStunConnection* IceContext::getNominatedPair()
{
    AmLock lock(pairs_mut);
    for(auto pair = pairs.rbegin();
        pair != pairs.rend(); pair++) {
            AmStunConnection::PairState state = pair->second->getState();
            if(state == AmStunConnection::PAIR_SUCCEEDED) {
                return pair->second;
            }
    }
    return nullptr;
}

sockaddr_storage* IceContext::getAllowedIceAddr(int family)
{
    AmLock lock(pairs_mut);
    if(current_candidate) {
        sockaddr_storage* sa = &current_family_addr[family];
        if(family == current_candidate->getTransport()->getLocalAddrFamily()) {
            current_candidate->getRAddr(sa);
            return sa;
        }
    }
    for(auto& pair : pairs) {
        AmStunConnection::PairState state = pair.second->getState();
        sockaddr_storage* sa = &current_family_addr[family];
        if(state == AmStunConnection::PAIR_SUCCEEDED &&
           family == pair.second->getTransport()->getLocalAddrFamily()) {
            pair.second->getRAddr(sa);
            return sa;
        }
    }
    return nullptr;
}

AmMediaTransport* IceContext::getCurrentTransport()
{
    AmLock lock(pairs_mut);
    for(auto& pair : pairs) {
        AmStunConnection::PairState state = pair.second->getState();
        if(state == AmStunConnection::PAIR_SUCCEEDED) {
            return pair.second->getTransport();
        }
    }
    return nullptr;
}

void IceContext::reset() {
    CLASS_DBG("reset ice context: type %d", type);
    AmLock lock(pairs_mut);
    for(auto& pair : pairs) {
        stun_processor::instance()->remove_timer(pair.second);
    }
    pairs.clear();
    current_candidate.reset(nullptr);
    state = ICE_INITIAL;
}

bool IceContext::isUseCandidate(AmStunConnection* conn)
{
    /* current_candidate can be changed in parallel
       so function can return not an actual value.

       locking IceContext::pairs_mut here causes lock-ordering issue with AmStunProcessor::connections_mutex
        * AmStunProcessor::on_timer //AmLock connections_lock(connections_mutex);
            AmStunConnection::send_request()
                AmStunConnection::checkState()
                    IceContext::isUseCandidate() //AmLock lock(pairs_mut);
        * AmRtpStream::~AmRtpStream
            IceContext::reset() //AmLock lock(pairs_mut);
               AmStunProcessor::remove_timer() //AmLock l(connections_mutex);

        we do not use current_candidate and only compare pointers
        so it's safe to comment-out locking */

    //AmLock lock(pairs_mut);

    if(state == ICE_NOMINATIONS || state == ICE_KEEP_ALIVE) {
        if(!stream->isIceControlled() && conn == current_candidate.get()) {
            return true;
        }
    }
    return false;
}

void IceContext::failedCandidate(AmStunConnection*)
{
    switch(state) {
    case ICE_NOMINATIONS:
    case ICE_KEEP_ALIVE: {
        state = ICE_NOMINATIONS;
        setCurrentCandidate(nullptr);
    }
    default: break;
    };
}

void IceContext::allowCandidate(AmStunConnection* conn)
{
    if(conn->getState() == AmStunConnection::PAIR_WAITING &&
       state == ICE_KEEP_ALIVE) {
        state = ICE_NOMINATIONS;
        setCurrentCandidate(nullptr);
    }

    sockaddr_storage ss;
    conn->getRAddr(&ss);
    stream->allowStunConnection(conn->getTransport(), &ss, conn->getPriority());
}

void IceContext::allowStunPair()
{
    sockaddr_storage ss;
    AmMediaTransport* transport;
    {
        AmLock lock(pairs_mut);
        assert(current_candidate);
        current_candidate->getRAddr(&ss);
        transport = current_candidate->getTransport();
    }
    stream->allowStunPair(transport, &ss);
}

void IceContext::setState(IceContext::State initial)
{
    state = initial;
}

void IceContext::setCurrentCandidate(AmStunConnection* conn)
{
    AmLock lock(pairs_mut);
    current_candidate.reset(conn);
}

void IceContext::updateStunTimers(std::unordered_map<AmStunConnection *, unsigned long long>& connections)
{
    ReferenceUniquePtr conn(nullptr);
    switch(state) {
    case ICE_CONNECTIVITY_CHECK:
    {
        bool finish = true;
        ReferenceUniquePtr wait_conn(nullptr);
        ReferenceUniquePtr frozen_conn(nullptr);
        {
            AmLock lock(pairs_mut);
            if(pairs.empty()) break;

            auto pair = pairs.rbegin();
            while(pair != pairs.rend()) {
                AmStunConnection::PairState pstate = pair->second->getState();
                if(pstate == AmStunConnection::PAIR_WAITING && !wait_conn) 
                    wait_conn.reset(pair->second);
                if(pstate == AmStunConnection::PAIR_FROZEN && !frozen_conn) 
                    frozen_conn.reset(pair->second);
                switch(pstate) {
                case AmStunConnection::PAIR_WAITING:
                case AmStunConnection::PAIR_FROZEN:
                case AmStunConnection::PAIR_IN_PROGRESS:
                    finish = false;
                default: break;
                }
                pair++;
            }
        }
        if(finish) {
            DBG("ice: finished connectivity check phase(type %d)", type);
            state = ICE_NOMINATIONS;
        } else {
            if(wait_conn) {
                wait_conn->checkState();
                if(auto interval = wait_conn->checkStunTimer(); interval.has_value())
                    connections[wait_conn] = interval.value();
            }
            if(frozen_conn)
                frozen_conn->checkState();
        }
        break;
    }
    case ICE_NOMINATIONS:
    {
        {
            AmLock lock(pairs_mut);
            conn.reset(current_candidate.get());
        }
        if(conn) {
            if(conn->getState() == AmStunConnection::PAIR_SUCCEEDED) {
                DBG("ice: finished nomination phase(type %d)", type);
                state = ICE_KEEP_ALIVE;
            } else return;
        } else {
            conn.reset(getNominatedPair());
            if(conn) {
                setCurrentCandidate(conn.get());
                if(stream->isIceControlled()) {
                    DBG("ice: finished nomination phase(type %d)", type);
                    state = ICE_KEEP_ALIVE;
                } else {
                    conn->setState(AmStunConnection::PAIR_WAITING);
                    connections[conn.get()] = STUN_TA_TIMEOUT;
                    return;
                }
            } else return;
        }
        allowStunPair();
        break;
    }
    case ICE_KEEP_ALIVE:
    {
        AmLock lock(pairs_mut);
        connections[current_candidate.get()] = STUN_KEEPALIVE_TIMEOUT;
        break;
    }
    default: break;
    }
}

AmStunConnection::AmStunConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, unsigned int _lpriority, unsigned int _priority)
  : AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::STUN_CONN),
    state(PAIR_FROZEN),
    priority(_priority),
    lpriority(_lpriority),
    current_trans_id{0},
    count(0),
    retransmit_intervals{500, 1500, 3500, 7500, 15500, 31500, 39500},//rfc5389 7.2.1.Sending over UDP
    context(transport->getRtpStream()->getIceContext(transport->getTransportType()))
{
    CLASS_DBG("AmStunConnection() r_host: %s, r_port: %d, transport: %hhu",
              r_host.data(), r_port, SA_transport(&r_addr));
    SA_transport(&r_addr) = transport->getTransportType();
    context->addConnection(this);
}

AmStunConnection::~AmStunConnection()
{
    CLASS_DBG("~AmStunConnection()");
}

void AmStunConnection::set_credentials(const string& luser, const string& lpassword,
                                       const string& ruser, const string& rpassword)
{
    DBG("set credentials: %s:%s/%s:%s", luser.c_str(), lpassword.c_str(), ruser.c_str(), rpassword.c_str());
    local_user = luser;
    remote_user = ruser;
    local_password = lpassword;
    remote_password = rpassword;
}

unsigned int AmStunConnection::getPriority()
{
    // see rfc 8445 6.1.2.3
    unsigned long long pair_priority =
        ((unsigned long long)1<<32)*(priority <= lpriority ? priority : lpriority) +
        2*(priority <= lpriority ? lpriority : priority);
    return pair_priority;
}

void AmStunConnection::handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time)
{
    CStunMessageReader reader;
    if(reader.AddBytes(data, size) == CStunMessageReader::ParseError) {
        return;
    }

    StunMessageClass msgClass = reader.GetMessageClass();
    if(msgClass == StunMsgClassRequest) {
        check_request(&reader, recv_addr);
    } else if(msgClass == StunMsgClassSuccessResponse) {
        check_response(&reader, recv_addr);
    }
}

void AmStunConnection::getInfo(AmArg& ret)
{
    AmStreamConnection::getInfo(ret);
    ret["state"] = state2str(state);
    ret["priority"] = getPriority();
    ret["retransmit_count"] = count;
}

std::string AmStunConnection::state2str(AmStunConnection::PairState state)
{
    switch(state) {
    case PAIR_FROZEN:
        return "FROZEN";
    case PAIR_WAITING:
        return "WAITING";
    case PAIR_IN_PROGRESS:
        return "IN_PROGRESS";
    case PAIR_RETRANSMIT:
        return "RETRANSMIT";
    case PAIR_FAILED:
        return "FAILED";
    case PAIR_SUCCEEDED:
        return "SUCCEEDED";
    }
}

void AmStunConnection::check_request(CStunMessageReader* reader, sockaddr_storage* addr)
{
    StunAttribute user;
    bool valid = true;
    int err_code = 0;
    std::string error_str;

    std::string username;
    if(reader->GetAttributeByType(STUN_ATTRIBUTE_USERNAME, &user) == S_OK) {
        username.append((char*)reader->GetStream().GetDataPointerUnsafe() + user.offset, user.size);
        if(username != (local_user + ":" + remote_user)) {
            err_code = STUN_ERROR_UNAUTHORIZED;
            error_str = "invalid username";
            valid = false;
        }
    } else {
        err_code = STUN_ERROR_BADREQUEST;
        error_str = "absent username";
        valid = false;
    }

    if(valid && !reader->HasMessageIntegrityAttribute()) {
        err_code = STUN_ERROR_UNAUTHORIZED;
        error_str = "absent message integrity attribute";
        valid = false;
    }
    if(valid && reader->ValidateMessageIntegrityShort(local_password.c_str()) != S_OK) {
        err_code = STUN_ERROR_UNAUTHORIZED;
        error_str = "message integrity attribute validation failed";
        valid = false;
    }

    if(valid && (!reader->HasFingerprintAttribute() || !reader->IsFingerprintAttributeValid())) {
        err_code = STUN_ERROR_BADREQUEST;
        error_str = "fingerprint attribute validation failed";
        valid = false;
    }

    //ICE_CONTROLLING/ICE_CONTROLLED, rfc5245#section-7.2.1.1

    uint64_t remote_tiebreaker = 0;
    std::optional<bool> remote_ice_role_is_controlled;
    StunAttribute ice_ctrl_attr;
    if (S_OK == reader->GetAttributeByType(STUN_ATTRIBUTE_ICE_CONTROLLING, &ice_ctrl_attr)) {
        remote_ice_role_is_controlled = false;
    } if (S_OK ==reader->GetAttributeByType(STUN_ATTRIBUTE_ICE_CONTROLLED, &ice_ctrl_attr)) {
        remote_ice_role_is_controlled = true;
    }

    if(remote_ice_role_is_controlled.has_value()) {
        remote_tiebreaker = be64toh(*(uint64_t*)(
            reader->GetStream().GetDataPointerUnsafe() + ice_ctrl_attr.offset));

        if(valid && ((*remote_ice_role_is_controlled) == transport->getRtpStream()->isIceControlled())) {
            //roles conflict. less tiebreaker value means controlled mode
            DBG("roles conflict. local:0x%llx, remote:0x%llx",
                transport->getRtpStream()->getIceTieBreaker(),
                remote_tiebreaker);

            bool tiebreaked_local_role_is_controlled = transport->getRtpStream()->getIceTieBreaker() < remote_tiebreaker;
            if(tiebreaked_local_role_is_controlled != transport->getRtpStream()->isIceControlled()) {
                DBG("accept role change");
                //accept role change
                transport->getRtpStream()->onIceRoleConflict();
            } else {
                DBG("reject role change");
                //reject ICE role change
                err_code = STUN_ERROR_ROLECONFLICT;
                error_str = "Role Conflict";
                valid = false;
            }
        }
    } else {
        DBG("no ICE_CONTROLLING/ICE_CONTROLLED attributes in the STUN binding request from %s:%hu",
            am_inet_ntop(addr).data(), am_get_port(addr));
    }

    // ICE_PRIORITY

    StunTransactionId trnsId;
    StunAttribute priority_attr;
    reader->GetTransactionId(&trnsId);
    unsigned int new_priority = 0;
    if(valid && (S_OK == reader->GetAttributeByType(STUN_ATTRIBUTE_ICE_PRIORITY, &priority_attr))) {
        if(priority_attr.size == 4)
            new_priority = htonl(*(int*)(reader->GetStream().GetDataPointerUnsafe() + priority_attr.offset));
        else {
            err_code = STUN_ERROR_BADREQUEST;
            error_str = "incorrect priority attribute size";
            valid = false;
        }

        // see rfc8445 5.1.2
        if (valid && (new_priority >= (1U<<31) || new_priority == 0)) {
            err_code = STUN_ERROR_BADREQUEST;
            error_str = "incorrect priority attribute value";
            valid = false;
        }
    }
    if(new_priority != priority) {
        priority = new_priority;
        context->updateConnection(this);
    }

    bool use_candidate = false;
    StunAttribute useCandidate;
    if(valid && (S_OK == reader->GetAttributeByType(STUN_ATTRIBUTE_USE_CANDIDATE, &useCandidate))) {
        if(transport->getRtpStream()->isIceControlled())
            use_candidate = true;
        else {
            err_code = STUN_ERROR_BADREQUEST;
            error_str = "invalid role for use candidate attribute";
            valid = false;
        }
    }
    
    CStunMessageBuilder builder;
    builder.AddBindingResponseHeader(valid);
    builder.AddTransactionId(trnsId);
    if(err_code) {
        string error(", stun packet is dropped, ");
        transport->getRtpStream()->onErrorRtpTransport(STUN_DROPPED_ERROR, error_str + error + username, transport);
        builder.AddErrorCode(err_code, error_str.c_str());
    } else {
        CSocketAddress addr(r_addr);
        builder.AddXorMappedAddress(addr);
        builder.AddMessageIntegrityShortTerm(local_password.c_str());
        builder.AddFingerprintAttribute();
    }

    CRefCountedBuffer buffer;
    HRESULT ret = builder.GetResult(&buffer);
    if(ret == S_OK) {
        transport->send(addr, (unsigned char*)buffer->GetData(), buffer->GetSize(), AmStreamConnection::STUN_CONN);
        if(valid) {
            allow_candidate(use_candidate);
        }
    }
}

void AmStunConnection::allow_candidate(bool use_candidate)
{
    switch(state) {
    case PAIR_WAITING:
    case PAIR_IN_PROGRESS:
    case PAIR_RETRANSMIT:
        state = PAIR_SUCCEEDED;
        break;
    case PAIR_FAILED:
        state = PAIR_WAITING;
        break;
    case PAIR_FROZEN:
    case PAIR_SUCCEEDED:
        return;
    }
    CLASS_DBG("stun pair %s:%d", getRHost().c_str(), getRPort());
    context->allowCandidate(this);
    if(use_candidate)
        context->useCandidate(this);
    stun_processor::instance()->remove_timer(this);
}

void AmStunConnection::check_response(CStunMessageReader* reader, sockaddr_storage* addr)
{
    bool valid = true;
    std::string error_str;
    uint16_t err_code = 0;

    StunTransactionId trnsId;
    reader->GetTransactionId(&trnsId);
    for(size_t i = 0; i < STUN_TRANSACTION_ID_LENGTH && valid; i++) {
        if(trnsId.id[i] != current_trans_id.id[i]) {
            error_str = "invalid stun transaction id";
            err_code = STUN_ERROR_INCORRECT_TRANSID;
            valid = false;
        }
    }

    if(valid && reader->GetErrorCode(&err_code) == S_OK) {
        if(err_code == STUN_ERROR_ROLECONFLICT) {
            transport->getRtpStream()->onIceRoleConflict();
        }
        error_str = "error response";
        valid = false;
    }

    if(valid && !reader->HasMessageIntegrityAttribute()) {
        err_code = STUN_ERROR_UNAUTHORIZED;
        error_str = "absent message integrity attribute";
        valid = false;
    }
    if(valid && reader->ValidateMessageIntegrityShort(remote_password.c_str()) != S_OK) {
        err_code = STUN_ERROR_UNAUTHORIZED;
        error_str = "message integrity attribute validation failed";
        valid = false;
    }
    if(valid && (!reader->HasFingerprintAttribute() || !reader->IsFingerprintAttributeValid())) {
        err_code = STUN_ERROR_BADREQUEST;
        error_str = "fingerprint attribute validation failed";
        valid = false;
    }

    if(valid) {
        allow_candidate(false);
    } else if(!valid){
        string error("invalid stun message: ");
        transport->getRtpStream()->onErrorRtpTransport(STUN_VALID_ERROR, error + error_str, transport);
        if(err_code == STUN_ERROR_INCORRECT_TRANSID) return;
        if(err_code == STUN_ERROR_ROLECONFLICT) {
            state = PAIR_WAITING;
            return;
        }
        if(state == PAIR_IN_PROGRESS) {
            state = PAIR_FAILED;
            context->failedCandidate(this);
            stun_processor::instance()->remove_timer(this);
        }
    }
}

void AmStunConnection::send_request(StunTransactionId trans_id)
{
    CLASS_DBG("AmStunConnection::send_request()");

    // see rfc8445 5.1.2
    if(lpriority >= (1U<<31) || lpriority == 0) {
        WARN("stun priority (0x%x) is incorrect. raddr: %s:%hu",
            lpriority, am_inet_ntop(&r_addr).data(), am_get_port(&r_addr));
    }

    CStunMessageBuilder builder;
    builder.AddBindingRequestHeader();
    current_trans_id = trans_id;
    builder.AddTransactionId(trans_id);
    string username = remote_user + ":" + local_user;
    builder.AddUserName(username.c_str());

    uint16_t nt_info[2] = {0};
    nt_info[0] = htons(1);
    builder.AddAttribute(STUN_ATTRIBUTE_NETWORK_INFO, &nt_info, 4);

    uint64_t tb = htobe64(transport->getRtpStream()->getIceTieBreaker());
    builder.AddAttribute(
        transport->getRtpStream()->isIceControlled() ? STUN_ATTRIBUTE_ICE_CONTROLLED: STUN_ATTRIBUTE_ICE_CONTROLLING,
        (uint8_t*)&tb, STUN_TIE_BREAKER_LENGTH);
    if(context->isUseCandidate(this))
        builder.AddAttribute(STUN_ATTRIBUTE_USE_CANDIDATE, nullptr, 0);

    int priority_netorder = htonl(lpriority);
    builder.AddAttribute(STUN_ATTRIBUTE_ICE_PRIORITY, (char*)&priority_netorder, 4);
    builder.AddMessageIntegrityShortTerm(remote_password.c_str());
    builder.AddFingerprintAttribute();

    CRefCountedBuffer buffer;
    HRESULT ret = builder.GetResult(&buffer);
    if(ret == S_OK) {
         transport->send(&r_addr, (unsigned char*)buffer->GetData(), buffer->GetSize(), AmStreamConnection::STUN_CONN);
    }
}

void AmStunConnection::retransmit()
{
    send_request(current_trans_id);
}

void AmStunConnection::checkState()
{
    CLASS_DBG("checkState: state = %hhu", state);
    if(state == PAIR_FROZEN) {
        state = PAIR_WAITING;
        return;
    } else if(state == PAIR_SUCCEEDED ||
              state == PAIR_FAILED ||
              state == PAIR_WAITING) {
        count = 0;
        state = PAIR_IN_PROGRESS;
    } else if(state == PAIR_IN_PROGRESS) {
        state = PAIR_RETRANSMIT;
        context->failedCandidate(this);
    } else if(state == PAIR_RETRANSMIT) {
        if(count == STUN_INTERVALS_COUNT) {
            state = PAIR_FAILED;
            context->failedCandidate(this);
        }
    } else return;

    StunTransactionId trnsId;
    if(!count) {
        *(int*)trnsId.id = htonl(STUN_COOKIE);
        for(int i = 4; i < STUN_TRANSACTION_ID_LENGTH; i++) {
            trnsId.id[i] = (uint8_t)rand();
        }
        current_trans_id = trnsId;
        send_request(trnsId);
    } else {
        retransmit();
    }
}

std::optional<unsigned long long> AmStunConnection::checkStunTimer()
{
    if(state == PAIR_IN_PROGRESS || state == PAIR_RETRANSMIT) {
        DBG("will update retransmit stun timer: count %d", count);
        if(++count < STUN_INTERVALS_COUNT){
            return retransmit_intervals[count];
        }
    }
    return std::nullopt;
}

