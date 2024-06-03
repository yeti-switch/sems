#include "log.h"
#include "AmStunConnection.h"
#include "AmMediaTransport.h"
#include "AmRtpStream.h"
#include "stun/stunbuilder.h"
#include "sip/ip_util.h"

#include <byteswap.h>

#define STUN_ERROR_ROLECONFLICT 487

AmStunConnection::AmStunConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, unsigned int _lpriority, unsigned int _priority)
  : AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::STUN_CONN),
    isAuthentificated{false,false},
    err_code(0),
    priority(_priority),
    lpriority(_lpriority),
    count(0),
    intervals{0, 500, 1500, 3500, 7500, 15500, 31500, 39500},//rfc5389 7.2.1.Sending over UDP
    local_ice_role_is_controlled(false)
{
    SA_transport(&r_addr) = transport->getTransportType();
    CLASS_DBG("AmStunConnection() r_host: %s, r_port: %d, transport: %hhu",
              r_host.data(), r_port, SA_transport(&r_addr));

    ((uint32_t*)&local_tiebreaker)[0] = rand();
    ((uint32_t*)&local_tiebreaker)[1] = rand();
}

AmStunConnection::~AmStunConnection()
{
    CLASS_DBG("~AmStunConnection()");
    stun_processor::instance()->remove_timer(this);
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
        remote_tiebreaker = bswap_64(*(uint64_t*)(
            reader->GetStream().GetDataPointerUnsafe() + ice_ctrl_attr.offset));

        if(valid && ((*remote_ice_role_is_controlled) == local_ice_role_is_controlled)) {
            //roles conflict. less tiebreaker value means controlled mode
            bool tiebreaked_local_role_is_controlled = local_tiebreaker < remote_tiebreaker;
            if(tiebreaked_local_role_is_controlled != local_ice_role_is_controlled) {
                //accept role change
                change_ice_role();
            } else {
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
    if(valid && (S_OK == reader->GetAttributeByType(STUN_ATTRIBUTE_ICE_PRIORITY, &priority_attr))) {
        if(priority_attr.size == 4)
            priority = htonl(*(int*)(reader->GetStream().GetDataPointerUnsafe() + priority_attr.offset));
        else {
            err_code = STUN_ERROR_BADREQUEST;
            error_str = "incorrect priority attribute size";
            valid = false;
        }

        // see rfc8445 5.1.2
        if (priority >= (unsigned int)(1<<31) || priority == 0) {
            err_code = STUN_ERROR_BADREQUEST;
            error_str = "incorrect priority attribute value";
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
        if(valid && !isAuthentificated[AUTH_REQUEST]) {
            isAuthentificated[AUTH_REQUEST] = true;
            checkAllowPair();
        }
    }
}

bool AmStunConnection::isAllowPair() {
    for(int i = 0; i < sizeof(isAuthentificated); i++)
        if(!isAuthentificated[i]) return false;
    return true;
}


void AmStunConnection::checkAllowPair()
{
    if(!isAllowPair()) return;
    transport->getRtpStream()->allowStunConnection(transport, &r_addr, priority);
}

//rfc8445 7.2.5.1
void AmStunConnection::change_ice_role()
{
    local_ice_role_is_controlled = !local_ice_role_is_controlled;
}

void AmStunConnection::check_response(CStunMessageReader* reader, sockaddr_storage* addr)
{
    bool valid = true;
    std::string error_str;
    uint16_t error_code = 0;
    if(reader->GetErrorCode(&error_code) == S_OK) {
        if(error_code == STUN_ERROR_ROLECONFLICT) {
            change_ice_role();
        }
        err_code = error_code;
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

    if(valid && !isAuthentificated[AUTH_RESPONSE]) {
        isAuthentificated[AUTH_RESPONSE] = true;
        checkAllowPair();
    } else if(!valid){
        string error("invalid stun message: ");
        transport->getRtpStream()->onErrorRtpTransport(STUN_VALID_ERROR, error + error_str, transport);
    }
}

void AmStunConnection::send_request()
{
    CLASS_DBG("AmStunConnection::send_request()");

    // see rfc8445 5.1.2
    if(lpriority >= (unsigned int)(1<<31) || lpriority == 0) {
        WARN("stun priority (0x%x) is incorrect. raddr: %s:%hu",
            lpriority, am_inet_ntop(&r_addr).data(), am_get_port(&r_addr));
    }

    CStunMessageBuilder builder;
    builder.AddBindingRequestHeader();
    StunTransactionId trnsId;
    *(int*)trnsId.id = htonl(STUN_COOKIE);
    for(int i = 4; i < STUN_TRANSACTION_ID_LENGTH; i++) {
        trnsId.id[i] = (uint8_t)rand();
    }
    builder.AddTransactionId(trnsId);
    string username = remote_user + ":" + local_user;
    builder.AddUserName(username.c_str());

    uint16_t nt_info[2] = {0};
    nt_info[0] = htons(1);
    builder.AddAttribute(STUN_ATTRIBUTE_NETWORK_INFO, &nt_info, 4);

    uint64_t tb = bswap_64(local_tiebreaker);
    builder.AddAttribute(
        local_ice_role_is_controlled ? STUN_ATTRIBUTE_ICE_CONTROLLED: STUN_ATTRIBUTE_ICE_CONTROLLING,
        (uint8_t*)&tb, STUN_TIE_BREAKER_LENGTH);

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

std::optional<unsigned long long> AmStunConnection::checkStunTimer()
{
    DBG("will update stun timer: count %d", count);
    if((isAllowPair() && count == STUN_INTERVALS_COUNT) ||
        ++count <= STUN_INTERVALS_COUNT)
    {
        return intervals[count];
    }
    return std::nullopt;
}

void AmStunConnection::updateStunTimer()
{
    if(auto interval = checkStunTimer(); interval.has_value()) {
        stun_processor::instance()->set_timer(this, interval.value());
    } else {
        stun_processor::instance()->remove_timer(this);
    }
}
