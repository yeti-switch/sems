#include "AmSrtpConnection.h"
#include "AmRtpStream.h"
#include "AmDtlsConnection.h"
#include "rtp/rtp.h"

#include <algorithm>
#include <botan/base64.h>
#include <botan/uuid.h>

AmSrtpConnection::AmSrtpConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, AmStreamConnection::ConnectionType conn_type)
    : AmStreamConnection(_transport, remote_addr, remote_port, conn_type)
    , srtp_profile(srtp_profile_reserved)
    , srtp_s_session(nullptr)
    , srtp_r_session(nullptr)
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
        srtp_s_session = nullptr;
    }
    if(srtp_r_session) {
        srtp_dealloc(srtp_r_session);
        srtp_r_session = nullptr;
    }

    if(s_stream)
        delete s_stream;
}

void AmSrtpConnection::use_key(srtp_profile_t profile, const unsigned char* key_s, size_t key_s_len, const unsigned char* key_r, size_t key_r_len)
{
    if(srtp_s_session || srtp_r_session) {
        return;
    }

    CLASS_DBG("create s%s connection: profile %s", getConnType() == RTP_CONN ? "rtp" : "rtcp",
              SdpCrypto::profile2str((CryptoProfile)profile).c_str());
    unsigned int master_key_len = srtp::profile_get_master_key_length(profile);
    master_key_len += srtp::profile_get_master_salt_length(profile);
    if(master_key_len != key_s_len || master_key_len != key_r_len) {
        char error[100];
        sprintf(error, "srtp key not corrected, another size: needed %u in fact local-%lu, remote-%lu",
                                master_key_len, key_s_len, key_r_len);
        transport->getRtpStream()->onErrorRtpTransport(error, transport);
        return;
    }

    if (srtp_create(&srtp_s_session, nullptr) != srtp_err_status_ok ||
        srtp_create(&srtp_r_session, nullptr) != srtp_err_status_ok) {
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
    key_s_len = static_cast<unsigned int>(data.size());
    memcpy(key_s, data.data(), key_s_len);
}

int srtp::profile_get_master_key_length(srtp_profile_t profile)
{
    switch((int)profile) {
        case CP_AES128_CM_SHA1_80:
        case CP_AES128_CM_SHA1_32:
//         case CP_AEAD_AES_128_GCM:
            return SRTP_AES_128_KEY_LEN;
//         case CP_AES192_CM_SHA1_80:
//         case CP_AES192_CM_SHA1_32:
//             return SRTP_AES_192_KEY_LEN;
        case CP_AES256_CM_SHA1_80:
        case CP_AES256_CM_SHA1_32:
//         case CP_AEAD_AES_256_GCM:
            return SRTP_AES_256_KEY_LEN;
    }

    return 0;
}

int srtp::profile_get_master_salt_length(srtp_profile_t profile)
{
    switch ((int)profile) {
    case CP_AES128_CM_SHA1_80:
    case CP_AES128_CM_SHA1_32:
//     case CP_AES192_CM_SHA1_80:
//     case CP_AES192_CM_SHA1_32:
    case CP_AES256_CM_SHA1_80:
    case CP_AES256_CM_SHA1_32:
    case CP_NULL_SHA1_80:
        return SRTP_SALT_LEN;
//     case CP_AEAD_AES_128_GCM:
//     case CP_AEAD_AES_256_GCM:
//         return SRTP_AEAD_SALT_LEN;
    }

    return 0;
}

void srtp::crypto_policy_set_from_profile_for_rtp(srtp_crypto_policy_t* policy, srtp_profile_t profile)
{
    switch ((int)profile) {
        case CP_AES128_CM_SHA1_80:
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(policy);
            break;
        case CP_AES128_CM_SHA1_32:
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(policy);
            break;
//         case CP_AES192_CM_SHA1_80:
//             srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(policy);
//             break;
//         case CP_AES192_CM_SHA1_32:
//             srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(policy);
//             break;
        case CP_AES256_CM_SHA1_80:
            srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(policy);
            break;
        case CP_AES256_CM_SHA1_32:
            srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(policy);
            break;
        case CP_NULL_SHA1_80:
            srtp_crypto_policy_set_null_cipher_hmac_sha1_80(policy);
            break;
//         case CP_AEAD_AES_128_GCM:
//             srtp_crypto_policy_set_aes_gcm_128_16_auth(policy);
//             break;
//         case CP_AEAD_AES_256_GCM:
//             srtp_crypto_policy_set_aes_gcm_256_16_auth(policy);
//             break;
    }
}

std::string AmSrtpConnection::gen_base64_key(srtp_profile_t profile)
{
    unsigned int master_key_len = srtp::profile_get_master_key_length(profile);
    master_key_len += srtp::profile_get_master_salt_length(profile);
    return gen_base64(master_key_len);
}

std::string AmSrtpConnection::gen_base64(unsigned int key_s_len)
{
    unsigned int len = 0;
    std::vector<uint8_t> data;
    dtls_rand_generator rand_gen;
    while(len != key_s_len) {
        const Botan::UUID random_uuid(rand_gen);
        if(key_s_len < len + random_uuid.binary_value().size()) {
            data.insert(data.end(), random_uuid.binary_value().begin(), random_uuid.binary_value().begin() + (key_s_len - len));
        } else {
            data.insert(data.end(), random_uuid.binary_value().begin(), random_uuid.binary_value().end());
        }
        len = static_cast<unsigned int>(data.size());
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
        srtp::crypto_policy_set_from_profile_for_rtp(&policy.rtp, srtp_profile);
        srtp::crypto_policy_set_from_profile_for_rtcp(&policy.rtcp, srtp_profile);
        policy.window_size = 128;
        policy.num_master_keys = 1;

        policy.key = c_key_r;
        if(getConnType() == RTP_CONN) {
            rtp_hdr_t *header = reinterpret_cast<rtp_hdr_t *>(data);
            policy.ssrc.value = header->ssrc;
        } else {
            RtcpCommonHeader *header = reinterpret_cast<RtcpCommonHeader*>(data);
            policy.ssrc.value = header->ssrc;
        }
        policy.ssrc.type = ssrc_any_inbound;
        CLASS_DBG("create s%s stream for receving stream: ssrc - %x", getConnType() == RTP_CONN ? "rtp" : "rtcp", policy.ssrc.value);
        int ret = srtp_err_status_ok;
        if((ret = srtp_add_stream(srtp_r_session, &policy)) != srtp_err_status_ok) {
            ERROR("srtp_add_stream error %d", ret);
            string error("s");
            error.append(getConnType() == RTP_CONN ? "rtp" : "rtcp");
            error.append(" recv stream not added");
            transport->getRtpStream()->onErrorRtpTransport(error, transport);
            return;
        }
    }

    srtp_err_status_t ret;
    if(getConnType() == RTP_CONN)
        ret = srtp_unprotect(srtp_r_session, data, reinterpret_cast<int *>(&size));
    else
        ret = srtp_unprotect_rtcp(srtp_r_session, data, reinterpret_cast<int *>(&size));

    if(ret == srtp_err_status_ok || getConnType() == RTCP_CONN)
        s_stream->handleConnection(data, size, recv_addr, recv_time);
    else {
        CLASS_DBG("srtp_unprotect for %s - error:%d", getConnType() == RTP_CONN ? "rtp" : "rtcp", ret);
        sockaddr_storage saddr;
        transport->getLocalAddr(&saddr);
        string error("error parsing: incorrect s");
        error.append(getConnType() == RTP_CONN ? "rtp" : "rtcp");
        error.append(" packet");
        transport->getRtpStream()->onErrorRtpTransport(error, transport);
    }
}

ssize_t AmSrtpConnection::send(AmRtpPacket* p)
{
    if(!srtp_s_session){
        transport->getRtpStream()->onErrorRtpTransport("srtp session not initialized", transport);
        return -1;
    }

    if(!b_init[1]) {
        b_init[1] = true;
        
        srtp_policy_t policy;
        memset(&policy, 0, sizeof(policy));
        srtp::crypto_policy_set_from_profile_for_rtp(&policy.rtp, srtp_profile);
        srtp::crypto_policy_set_from_profile_for_rtcp(&policy.rtcp, srtp_profile);
        policy.window_size = 128;
        policy.num_master_keys = 1;
            
        CLASS_DBG("create s%s stream for sending stream", getConnType() == RTP_CONN ? "rtp" : "rtcp");
        policy.key = c_key_s;
        policy.ssrc.value = transport->getRtpStream()->get_ssrc();
        policy.ssrc.type = ssrc_any_outbound;
        int ret = srtp_err_status_ok;
        if((ret = srtp_add_stream(srtp_s_session, &policy)) != srtp_err_status_ok) {
            ERROR("srtp_add_stream error %d", ret);
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

    if((getConnType() == RTP_CONN &&
        srtp_protect(srtp_s_session, p->getBuffer(), reinterpret_cast<int *>(&size)) != srtp_err_status_ok) ||
       (getConnType() == RTCP_CONN &&
        srtp_protect_rtcp(srtp_s_session, p->getBuffer(), reinterpret_cast<int *>(&size)) != srtp_err_status_ok))
    {
        transport->getRtpStream()->onErrorRtpTransport("error encrypting", transport);
        return -1;
    }

    p->setBufferSize(size);

    return s_stream->send(p);
}
