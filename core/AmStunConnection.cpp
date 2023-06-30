#include "AmStunConnection.h"
#include "log.h"
#include <stun/stunbuilder.h>
#include "AmMediaTransport.h"
#include "AmRtpStream.h"

AmStunConnection::AmStunConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, int _priority)
  : AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::STUN_CONN),
    depend_conn(0),
    isAuthentificated(false),
    err_code(0),
    priority(_priority),
    count(0),
    intervals{0, 500, 1500, 3500, 7500, 15500, 31500, 39500} //rfc5389 7.2.1.Sending over UDP
{
    SA_transport(&r_addr) = transport->getTransportType();
    CLASS_DBG("AmStunConnection() r_host: %s, r_port: %d, transport: %hhu",
              r_host.data(), r_port, SA_transport(&r_addr));
}

AmStunConnection::~AmStunConnection()
{
    CLASS_DBG("~AmStunConnection()");
    stun_processor::instance()->remove_timer(this);
}

void AmStunConnection::set_credentials(const string& luser, const string& lpassword,
                                       const string& ruser, const string& rpassword)
{
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

void AmStunConnection::setDependentConnection(AmStreamConnection* conn)
{
    depend_conn = conn;
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
    StunTransactionId trnsId;
    StunAttribute controlling;
    reader->GetTransactionId(&trnsId);
    reader->GetAttributeByType(STUN_ATTRIBUTE_ICE_CONTROLLING, &controlling);

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
        if(valid && !isAuthentificated) {
            isAuthentificated = true;
            if(depend_conn) depend_conn->setRAddr(am_inet_ntop(addr), am_get_port(addr));
            transport->allowStunConnection(addr, priority);
        }
    }
}

void AmStunConnection::check_response(CStunMessageReader* reader, sockaddr_storage* addr)
{
    bool valid = true;
    std::string error_str;

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

    if(valid && !isAuthentificated) {
        isAuthentificated = true;
        if(depend_conn) depend_conn->setRAddr(am_inet_ntop(addr), am_get_port(addr));
        transport->allowStunConnection(addr, priority);
    } else if(!valid){
        string error("valid stun message is false ERR = ");
        transport->getRtpStream()->onErrorRtpTransport(STUN_VALID_ERROR, error + error_str, transport);
    }
}

void AmStunConnection::send_request()
{
    CLASS_DBG("AmStunConnection::send_request()");

    updateStunTimer(false);

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

    char data[STUN_TIE_BREAKER_LENGTH];
    for(int i = 0; i < STUN_TIE_BREAKER_LENGTH; i++) {
        data[i] = (uint8_t)rand();
    }
    builder.AddAttribute(STUN_ATTRIBUTE_ICE_CONTROLLED, data, STUN_TIE_BREAKER_LENGTH);
    int priority_netorder = htonl(priority);
    builder.AddAttribute(STUN_ATTRIBUTE_ICE_PRIORITY, (char*)&priority_netorder, 4);
    builder.AddMessageIntegrityShortTerm(remote_password.c_str());
    builder.AddFingerprintAttribute();

    CRefCountedBuffer buffer;
    HRESULT ret = builder.GetResult(&buffer);
    if(ret == S_OK) {
         transport->send(&r_addr, (unsigned char*)buffer->GetData(), buffer->GetSize(), AmStreamConnection::STUN_CONN);
    }
}

void AmStunConnection::updateStunTimer(bool remove)
{
    if(remove)
        stun_processor::instance()->remove_timer(this);
    DBG("stun request update timer: count %d", count);
    if((isAuthentificated && count == STUN_INTERVALS_COUNT) ||
        ++count <= STUN_INTERVALS_COUNT) {
        stun_processor::instance()->set_timer(this, intervals[count]);
    }
}

bool AmStunConnection::getConnectionState()
{
    return isAuthentificated;
}
