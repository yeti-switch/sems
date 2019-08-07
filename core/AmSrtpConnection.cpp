#include "AmSrtpConnection.h"
#include "AmRtpStream.h"
#include "AmDtlsConnection.h"
#include "rtp/rtp.h"

#include <algorithm>
#include <botan/base64.h>
#include <botan/uuid.h>

AmSrtpConnection::AmSrtpConnection(AmRtpTransport* _transport, const string& remote_addr, int remote_port, AmStreamConnection::ConnectionType conn_type)
    : AmStreamConnection(_transport, remote_addr, remote_port, conn_type)
    , srtp_s_session(0)
    , srtp_r_session(0)
    , srtp_profile(srtp_profile_reserved)
{
    memset(b_init, 0, sizeof(b_init));
    if(conn_type == RTP_CONN)
        s_stream = new AmRtpConnection(this, remote_addr, remote_port);
    else if(conn_type == RTCP_CONN)
        s_stream = new AmRtcpConnection(this, remote_addr, remote_port);
    else
        throw string("incorrect connection type for srtp connection");
}

AmSrtpConnection::~AmSrtpConnection()
{
    if(srtp_s_session) {
        srtp_dealloc(srtp_s_session);
        srtp_s_session = 0;
    }
    if(srtp_r_session) {
        srtp_dealloc(srtp_r_session);
        srtp_r_session = 0;
    }

    if(s_stream)
        delete s_stream;
}

void AmSrtpConnection::use_key(srtp_profile_t profile, unsigned char* key_s, unsigned int key_s_len, unsigned char* key_r, unsigned int key_r_len)
{
    if(srtp_s_session || srtp_r_session) {
        return;
    }

    CLASS_DBG("create s%s connection", getConnType() == RTP_CONN ? "rtp" : "rtcp");
    unsigned int master_key_len = srtp_profile_get_master_key_length(profile);
    master_key_len += srtp_profile_get_master_salt_length(profile);
    if(master_key_len != key_s_len || master_key_len != key_r_len) {
        char error[100];
        sprintf(error, "srtp key not corrected, another size: needed %u in fact local-%u, remote-%u",
                                master_key_len, key_s_len, key_r_len);
        transport->getRtpStream()->onErrorRtpTransport(error, transport);
        return;
    }

    if (srtp_create(&srtp_s_session, NULL) != srtp_err_status_ok ||
        srtp_create(&srtp_r_session, NULL) != srtp_err_status_ok) {
        transport->getRtpStream()->onErrorRtpTransport("srtp session not created", transport);
        return;
    }

    memcpy(c_key_s, key_s, key_s_len);
    memcpy(c_key_r, key_r, key_r_len);
    srtp_profile = profile;
}

void AmSrtpConnection::base64_key(const std::string& key, unsigned char* key_s, unsigned int& key_s_len)
{
    Botan::secure_vector<uint8_t> data = Botan::base64_decode(key);
    if(data.size() > key_s_len) {
        ERROR("key buffer less base64 decoded key");
        return;
    }
    key_s_len = data.size();
    memcpy(key_s, data.data(), key_s_len);
}

std::string AmSrtpConnection::gen_base64_key(srtp_profile_t profile)
{
    unsigned int master_key_len = srtp_profile_get_master_key_length(profile);
    master_key_len += srtp_profile_get_master_salt_length(profile);
    return gen_base64(master_key_len);
}

std::string AmSrtpConnection::gen_base64(unsigned int key_s_len)
{
    unsigned int len = 0;
    std::vector<uint8_t> data;
    while(len != key_s_len) {
        const Botan::UUID random_uuid(*rand_generator_dtls::instance());
        if(key_s_len < len + random_uuid.binary_value().size()) {
            data.insert(data.end(), random_uuid.binary_value().begin(), random_uuid.binary_value().begin() + (key_s_len - len));
        } else {
            data.insert(data.end(), random_uuid.binary_value().begin(), random_uuid.binary_value().end());
        }
        len = data.size();
    }
    return Botan::base64_encode(data);
}

void AmSrtpConnection::handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time)
{
    if(!srtp_r_session) {
        transport->getRtpStream()->onErrorRtpTransport("srtp session not initialized", transport);
        return;
    }
    if(!b_init[0]) {
        b_init[0] = true;

        srtp_policy_t policy;
        memset(&policy, 0, sizeof(policy));
        if(getConnType() == RTP_CONN)
            srtp_crypto_policy_set_from_profile_for_rtp(&policy.rtp, srtp_profile);
        else
            srtp_crypto_policy_set_from_profile_for_rtcp(&policy.rtcp, srtp_profile);
        policy.window_size = 128;
        policy.num_master_keys = 1;

        CLASS_DBG("create s%s stream for receving stream", getConnType() == RTP_CONN ? "rtp" : "rtcp");
        policy.key = c_key_r;
        if(getConnType() == RTP_CONN) {
            rtp_hdr_t *header = (rtp_hdr_t *)data;
            policy.ssrc.value = header->ssrc;  // transport->getRtpStream()->get_rsrc();
        } else {
            RtcpCommonHeader *header = (RtcpCommonHeader*)data;
            policy.ssrc.value = header->ssrc;
        }
        policy.ssrc.type = ssrc_any_inbound;
        if(srtp_add_stream(srtp_r_session, &policy) != srtp_err_status_ok) {
            transport->getRtpStream()->onErrorRtpTransport("srtp recv stream not added", transport);
            return;
        }
    }
    
    srtp_err_status_t ret;
    if(getConnType() == RTP_CONN)
        ret = srtp_unprotect(srtp_r_session, data, (int*)&size);
    else
        ret = srtp_unprotect_rtcp(srtp_r_session, data, (int*)&size);

    if(ret == srtp_err_status_ok)
        s_stream->handleConnection(data, size, recv_addr, recv_time);
    else {
        sockaddr_storage saddr;
        transport->getLocalAddr(&saddr);
        transport->getRtpStream()->onErrorRtpTransport("error parsing: incorrect srtp packet", transport);
    }
}

int AmSrtpConnection::send(AmRtpPacket* p)
{
    if(!srtp_s_session){
        transport->getRtpStream()->onErrorRtpTransport("srtp session not initialized", transport);
        return -1;
    }

    if(!b_init[1]) {
        b_init[1] = true;
        
        srtp_policy_t policy;
        memset(&policy, 0, sizeof(policy));
        if(getConnType() == RTP_CONN)
            srtp_crypto_policy_set_from_profile_for_rtp(&policy.rtp, srtp_profile);
        else
            srtp_crypto_policy_set_from_profile_for_rtcp(&policy.rtcp, srtp_profile);
        policy.window_size = 128;
        policy.num_master_keys = 1;
            
        CLASS_DBG("create s%s stream for sending stream", getConnType() == RTP_CONN ? "rtp" : "rtcp");
        policy.key = c_key_s;
        policy.ssrc.value = transport->getRtpStream()->get_ssrc();
        policy.ssrc.type = ssrc_any_outbound;
        if(srtp_add_stream(srtp_s_session, &policy) != srtp_err_status_ok) {
            transport->getRtpStream()->onErrorRtpTransport("srtp send stream not added", transport);
            return -1;
        }
    }
    
    unsigned int size = p->getBufferSize();
    uint32_t trailer_len = 0;
    srtp_get_protect_trailer_length(srtp_s_session, false, 0, &trailer_len);
    if(size + trailer_len > RTP_PACKET_BUF_SIZE) {
        transport->getRtpStream()->onErrorRtpTransport("size + trailer_len > RTP_PACKET_BUF_SIZE", transport);
        return -1;
    }

    if((getConnType() == RTP_CONN && srtp_protect(srtp_s_session, p->getBuffer(), (int*)&size) != srtp_err_status_ok) ||
       (getConnType() == RTCP_CONN && srtp_protect_rtcp(srtp_s_session, p->getBuffer(), (int*)&size) != srtp_err_status_ok)) {
        transport->getRtpStream()->onErrorRtpTransport("error encripting", transport);
        return -1;
    }

    p->setBufferSize(size);

    return s_stream->send(p);
}
