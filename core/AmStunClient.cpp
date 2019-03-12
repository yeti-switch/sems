#include "AmStunClient.h"
#include <stunbuilder.h>
#include "AmRtpStream.h"

AmStunClient::AmStunClient(AmRtpStream* stream, bool b_rtcp)
: rtp_stream(stream), isrtcp(b_rtcp)
{
}

AmStunClient::~AmStunClient()
{
}

void AmStunClient::set_credentials(const string& luser, const string& lpassword,
                    const string& ruser, const string& rpassword)
{
    local_user = luser;
    remote_user = ruser;
    local_password = lpassword;
    remote_password = rpassword;
}

void AmStunClient::add_candidate(int priority, sockaddr_storage l_sa, sockaddr_storage r_sa)
{
    StunCandidate candidate;
    candidate.priority = priority;
    candidate.l_sa = l_sa;
    candidate.r_sa = r_sa;
    candidate.state = StunCandidate::NO_AUTH;
    pairs.push_back(candidate);
    INFO("add ice candidate %s:%d - %s:%d", am_inet_ntop(&l_sa).c_str(), am_get_port(&l_sa),
                                            am_inet_ntop(&r_sa).c_str(), am_get_port(&r_sa));
}

void AmStunClient::on_data_recv(uint8_t* data, unsigned int size, sockaddr_storage* addr)
{
    CStunMessageReader reader;
    if(reader.AddBytes(data, size) == CStunMessageReader::ParseError) {
        return;
    }
    
    StunMessageClass msgClass = reader.GetMessageClass();
    if(msgClass == StunMsgClassRequest) {
        check_request(&reader, addr);
    } else if(msgClass == StunMsgClassSuccessResponse) {

    } else if(msgClass == StunMsgClassFailureResponse) {
    
    }
}

void AmStunClient::check_request(CStunMessageReader* reader, sockaddr_storage* addr)
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
    
    auto it = std::find(pairs.begin(), pairs.end(), addr);
    if(it != pairs.end()) {
        it->state = StunCandidate::CHECK_OTHER;
    } else {
        WARN("not found ice pair %s:%d", am_inet_ntop(addr).c_str(), am_get_port(addr));
    }
    
    CStunMessageBuilder builder;
    builder.AddBindingResponseHeader(valid);
    builder.AddTransactionId(trnsId);
    if(err_code) {
        WARN("%s, stun packet is dropped, %s", error_str.c_str(), username.c_str());
        builder.AddErrorCode(err_code, error_str.c_str());
    } else {
        builder.AddAttribute(STUN_ATTRIBUTE_ICE_CONTROLLED, (char*)reader->GetStream().GetDataPointerUnsafe() + controlling.offset, controlling.size);
        builder.AddFingerprintAttribute();
    }
    
    CRefCountedBuffer buffer;
    HRESULT ret = builder.GetResult(&buffer);
    if(ret == S_OK) {
        rtp_stream->send(addr, (unsigned char*)buffer->GetData(), buffer->GetSize(), isrtcp);
    }
}
