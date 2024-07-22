#include "AmSrtpConnection.h"
#include "AmRtpStream.h"
#include <format_helper.h>

#include "rtp/rtp.h"
#include <botan/base64.h>
#include <botan/uuid.h>

#include <algorithm>

srtp_master_keys::strp_mater_key_container::strp_mater_key_container(
    const string &key_,
    uint32_t mki_id_,
    uint32_t mki_size_)
  : key_data(key_),
    mki_id_data(mki_id_)
{
    key = reinterpret_cast<unsigned char *>(key_data.data());
    mki_id = reinterpret_cast<unsigned char*>(&mki_id_data);
    mki_size = mki_size_;
}

bool srtp_master_keys::strp_mater_key_container::operator==(const strp_mater_key_container& other) const
{
    if (mki_size != other.mki_size)
        return false;

    if (mki_id != other.mki_id)
        return false;

    if (key_data != other.key_data)
        return false;

    return true;
}

srtp_master_keys::srtp_master_keys(
    const string& key,
    uint32_t mki_id, uint32_t mki_size)
{
    add(key, mki_id, mki_size);
}

void srtp_master_keys::operator=(srtp_master_keys const &other)
{
    for(const auto &d : other.get_data())
        add(d.key_data, d.mki_id_data, d.mki_size);
}

void srtp_master_keys::add(
    const string& key,
    uint32_t mki_id, uint32_t mki_size)
{
    auto &d = data.emplace_back(key, mki_id, mki_size);
    srtp_data_ptrs.emplace_back(&d);
}

AmSrtpConnection::AmSrtpConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, AmStreamConnection::ConnectionType conn_type)
  : AmStreamConnection(_transport, remote_addr, remote_port, conn_type),
    use_mki(false),
    rx_context_initialized(false),
    tx_context_initialized(false),
    connection_invalidated(false),
    last_rx_ssrc_net_order(0),
    rx_ssrc_changes_count(0),
    srtp_profile(srtp_profile_reserved),
    srtp_tx_session(nullptr),
    srtp_rx_session(nullptr)
{
    if(conn_type == RTP_CONN)
        s_stream = new AmRtpConnection(this, remote_addr, remote_port);
    else if(conn_type == RTCP_CONN)
        s_stream = new AmRtcpConnection(this, remote_addr, remote_port);
    else
        throw string("incorrect connection type for srtp connection");
}

AmSrtpConnection::~AmSrtpConnection()
{
    if(srtp_tx_session) {
        srtp_dealloc(srtp_tx_session);
        srtp_tx_session = nullptr;
    }
    if(srtp_rx_session) {
        srtp_dealloc(srtp_rx_session);
        srtp_rx_session = nullptr;
    }

    if(s_stream)
        delete s_stream;
}

void AmSrtpConnection::use_keys(
    srtp_profile_t profile,
    const string &tx_key,
    const srtp_master_keys& rx_keys)
{
    if (srtp_tx_session || srtp_rx_session) {
        CLASS_DBG("attempt to call use_keys() for initialized rx/tx sessions");
        return;
    }

    CLASS_DBG("create s%s connection: profile %s", getConnType() == RTP_CONN ? "rtp" : "rtcp",
              SdpCrypto::profile2str((CryptoProfile)profile).c_str());

    if (is_valid_keys(profile, tx_key, rx_keys) < 0)
        return;

    if (srtp_create(&srtp_tx_session, nullptr) != srtp_err_status_ok ||
        srtp_create(&srtp_rx_session, nullptr) != srtp_err_status_ok)
    {
        transport->getRtpStream()->onErrorRtpTransport(
            SRTP_CREATION_ERROR, "srtp session was not created", transport);
        return;
    }

    srtp_profile = profile;

    c_tx_key = tx_key;
    c_rx_keys = rx_keys;
    use_mki = rx_keys.has_mki();
}

void AmSrtpConnection::update_keys(
    srtp_profile_t profile,
    const string &tx_key,
    const srtp_master_keys& rx_keys)
{
    if (is_valid_keys(profile, tx_key, rx_keys) < 0)
        return;

    if (srtp_profile != profile)
        srtp_profile = profile;

    do { //scope for session_tx_mutex
        AmLock lock(session_tx_mutex);

        if (srtp_tx_session == nullptr)
            break;

        if (c_tx_key == tx_key)
            break;

        CLASS_DBG("update c_tx_key");
        c_tx_key = tx_key;

        if (!tx_context_initialized)
            break;

        srtp_policy_t tx_policy;
        memset(&tx_policy, 0, sizeof(tx_policy));

        srtp::crypto_policy_set_from_profile_for_rtp(&tx_policy.rtp, srtp_profile);
        srtp::crypto_policy_set_from_profile_for_rtcp(&tx_policy.rtcp, srtp_profile);

        tx_policy.window_size = 128;
        tx_policy.num_master_keys = 1;
        tx_policy.key = reinterpret_cast<unsigned char *>(c_tx_key.data());
        tx_policy.ssrc.value = transport->getRtpStream()->get_ssrc();
        tx_policy.ssrc.type = ssrc_any_outbound;

        if (auto ret = srtp_update_stream(srtp_tx_session, &tx_policy);
            ret != srtp_err_status_ok)
        {
            ERROR("srtp_update_stream error %d", ret);
        }
    } while(0);

    do { //scope for session_rx_mutex
        AmLock lock(session_rx_mutex);

        if (srtp_rx_session == nullptr)
            break;

        if (c_rx_keys == rx_keys)
            break;

        CLASS_DBG("update c_rx_keys");
        c_rx_keys = rx_keys;
        use_mki = rx_keys.has_mki();

        if (!rx_context_initialized)
            break;

        srtp::crypto_policy_set_from_profile_for_rtp(&rx_policy.rtp, srtp_profile);
        srtp::crypto_policy_set_from_profile_for_rtcp(&rx_policy.rtcp, srtp_profile);

        apply_rx_policy_keys();

        if (auto ret = srtp_update_stream(srtp_rx_session, &rx_policy);
            ret != srtp_err_status_ok)
        {
            ERROR("srtp_update_stream error %d", ret);
        }
    } while(0);
}

int AmSrtpConnection::is_valid_keys(
    srtp_profile_t profile,
    const string &tx_key,
    const srtp_master_keys& rx_keys)
{
    unsigned int master_key_len = srtp::profile_get_master_key_length(profile);
    master_key_len += srtp::profile_get_master_salt_length(profile);

    if(master_key_len != tx_key.length()) {
        transport->getRtpStream()->onErrorRtpTransport(
            SRTP_KEY_ERROR,
            format("incorrect SRTP TX key size. expected:{}, got: {}",
                master_key_len, tx_key.length()),
            transport);
        return -1;
    }

    if (!rx_keys.size()) {
        transport->getRtpStream()->onErrorRtpTransport(
            SRTP_KEY_ERROR, "missed RX keys", transport);
        return -1;
    }

    for(const auto &key : rx_keys.get_data()) {
        if(master_key_len != key.key_data.size()) {
            transport->getRtpStream()->onErrorRtpTransport(
                SRTP_KEY_ERROR,
                format("incorrect SRTP RX key size. expected:{}, got:{}",
                    master_key_len, key.key_data.size()),
                transport);
            return -1;
        }

        if(key.mki_size && key.mki_size > 4) {
            transport->getRtpStream()->onErrorRtpTransport(
                SRTP_KEY_ERROR,
                format("SRTP mki_size larger than 4 bytes is not supported. received:{}",
                    key.mki_size),
                transport);
            return -1;
        }
    }

    return 0;
}

void AmSrtpConnection::base64_key(const std::string& key,
                                  unsigned char* key_s, unsigned int& key_s_len)
{
    Botan::secure_vector<uint8_t> data = Botan::base64_decode(key);
    if(data.size() > key_s_len) {
        ERROR("key buffer is less than base64 decoded key");
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
    while(len != key_s_len) {
        const Botan::UUID random_uuid(Botan::system_rng());
        if(key_s_len < len + random_uuid.binary_value().size()) {
            data.insert(data.end(), random_uuid.binary_value().begin(), random_uuid.binary_value().begin() + (key_s_len - len));
        } else {
            data.insert(data.end(), random_uuid.binary_value().begin(), random_uuid.binary_value().end());
        }
        len = static_cast<unsigned int>(data.size());
    }
    return Botan::base64_encode(data);
}

void AmSrtpConnection::apply_rx_policy_keys()
{
    if (use_mki) {
        rx_policy.key = nullptr;
        rx_policy.keys = c_rx_keys.get_ptrs();
        rx_policy.num_master_keys = c_rx_keys.size();
    } else {
        rx_policy.key = reinterpret_cast<unsigned char *>(c_rx_keys.get_first_key().data());
        rx_policy.keys = nullptr;
        rx_policy.num_master_keys = 1;
    }
}

int AmSrtpConnection::ensure_rx_stream_context(uint32_t ssrc_net_order)
{
    if(!rx_context_initialized) {
        rx_context_initialized = true;

        memset(&rx_policy, 0, sizeof(rx_policy));

        srtp::crypto_policy_set_from_profile_for_rtp(&rx_policy.rtp, srtp_profile);
        srtp::crypto_policy_set_from_profile_for_rtcp(&rx_policy.rtcp, srtp_profile);

        rx_policy.window_size = 128;
        rx_policy.num_master_keys = 1;
        rx_policy.ssrc.type = ssrc_specific;

        apply_rx_policy_keys();
    } else {
        //context changed. remove the old one
        //!FIXME: maybe we have to keep old ctx in SRTP session
        CLASS_DBG("remove old SRTP context for SSRC: 0x%x",
                  ntohl(last_rx_ssrc_net_order));
        srtp_remove_stream(srtp_rx_session, ntohl(last_rx_ssrc_net_order));
    }

    last_rx_ssrc_net_order = ssrc_net_order;
    rx_policy.ssrc.value = ntohl(ssrc_net_order);

    CLASS_DBG("add %s receive stream context. SSRC:0x%x",
        getConnType() == RTP_CONN ? "RTP" : "RTCP",
        rx_policy.ssrc.value);

    if (auto ret = srtp_add_stream(srtp_rx_session, &rx_policy);
        ret != srtp_err_status_ok)
    {
        ERROR("srtp_add_stream error %d", ret);
        transport->getRtpStream()->onErrorRtpTransport(
            SRTP_ADD_STREAM_ERROR,
            format("failed to ass S{} rx stream context",
                getConnType() == RTP_CONN ? "RTP" : "RTCP"),
            transport);
        return 1;
    }

    return 0;
}

void AmSrtpConnection::handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time)
{
    srtp_err_status_t ret;
    uint32_t rx_ssrc_net_order;

    if(connection_invalidated)
        return;

    {
        AmLock lock(session_rx_mutex);
        if(!srtp_rx_session) {
            transport->getRtpStream()->onErrorRtpTransport(
                SRTP_INIT_ERROR, "srtp session is not initialized", transport);
            return;
        }

        if(getConnType() == RTP_CONN) {
            rtp_hdr_t *header = reinterpret_cast<rtp_hdr_t *>(data);
            rx_ssrc_net_order = header->ssrc;
        } else {
            RtcpCommonHeader *header = reinterpret_cast<RtcpCommonHeader*>(data);
            rx_ssrc_net_order = header->ssrc;
        }

        if(last_rx_ssrc_net_order != rx_ssrc_net_order) {
            if(last_rx_ssrc_net_order) {
                CLASS_DBG("SSRC changed 0x%x -> 0x%x. add new SRTP stream context",
                        ntohl(last_rx_ssrc_net_order), ntohl(rx_ssrc_net_order));
            } else {
                CLASS_DBG("got first packet withing SRTP session. SSRC:0x%x. add new SRTP stream context",
                        ntohl(rx_ssrc_net_order));
            }

            if(ensure_rx_stream_context(rx_ssrc_net_order)) {
                return;
            }
        }

        if(getConnType() == RTP_CONN)
            ret = srtp_unprotect_mki(srtp_rx_session, data, reinterpret_cast<int *>(&size), use_mki);
        else
            ret = srtp_unprotect_rtcp_mki(srtp_rx_session, data, reinterpret_cast<int *>(&size), use_mki);
    }

    if(ret == srtp_err_status_ok || getConnType() == RTCP_CONN) {
        s_stream->process_packet(data, size, recv_addr, recv_time);
    } else {
        CLASS_DBG("srtp_unprotect for %s - error:%d", getConnType() == RTP_CONN ? "rtp" : "rtcp", ret);
        sockaddr_storage saddr;
        transport->getLocalAddr(&saddr);
        string error("error parsing: incorrect S");
        error.append(getConnType() == RTP_CONN ? "RTP" : "RTCP");
        error.append(" packet");
        transport->getRtpStream()->onErrorRtpTransport(SRTP_UNPROTECT_ERROR, error, transport);
    }
}

void AmSrtpConnection::setRAddr(const string& addr, unsigned short port)
{
    CLASS_DBG("setRAddr(%s,%hu) type:%d, endpoint: %s:%d",
              addr.data(), port, conn_type,
              r_host.data(), r_port);
    resolveRemoteAddress(addr, port);
    s_stream->setRAddr(addr, port);
}

ssize_t AmSrtpConnection::send(AmRtpPacket* p)
{
    AmLock lock(session_tx_mutex);
    if(!srtp_tx_session){
        transport->getRtpStream()->onErrorRtpTransport(
            SRTP_INIT_ERROR, "srtp session is not initialized", transport);
        return -1;
    }

    if(!tx_context_initialized) {
        tx_context_initialized = true;

        srtp_policy_t policy;
        memset(&policy, 0, sizeof(policy));
        srtp::crypto_policy_set_from_profile_for_rtp(&policy.rtp, srtp_profile);
        srtp::crypto_policy_set_from_profile_for_rtcp(&policy.rtcp, srtp_profile);
        policy.window_size = 128;
        policy.num_master_keys = 1;

        CLASS_DBG("create s%s stream for sending stream", getConnType() == RTP_CONN ? "rtp" : "rtcp");
        policy.key = reinterpret_cast<unsigned char *>(c_tx_key.data());
        policy.ssrc.value = transport->getRtpStream()->get_ssrc();
        policy.ssrc.type = ssrc_any_outbound;
        int ret = srtp_err_status_ok;
        if((ret = srtp_add_stream(srtp_tx_session, &policy)) != srtp_err_status_ok) {
            ERROR("srtp_add_stream error %d", ret);
            transport->getRtpStream()->onErrorRtpTransport(SRTP_ADD_STREAM_ERROR, "srtp send stream not added", transport);
            return -1;
        }
    }

    unsigned int size = p->getBufferSize();
    uint32_t trailer_len = 0;
    srtp_get_protect_trailer_length(srtp_tx_session, false, 0, &trailer_len);
    if(size + trailer_len > RTP_PACKET_BUF_SIZE) {
        transport->getRtpStream()->onErrorRtpTransport(RTP_BUFFER_SIZE_ERROR, "size + trailer_len > RTP_PACKET_BUF_SIZE", transport);
        return -1;
    }

    if((getConnType() == RTP_CONN &&
        srtp_protect(srtp_tx_session, p->getBuffer(), reinterpret_cast<int *>(&size)) != srtp_err_status_ok) ||
       (getConnType() == RTCP_CONN &&
        srtp_protect_rtcp(srtp_tx_session, p->getBuffer(), reinterpret_cast<int *>(&size)) != srtp_err_status_ok))
    {
        transport->getRtpStream()->onErrorRtpTransport(SRTP_PROTECT_ERROR, "error encrypting", transport);
        return -1;
    }

    p->setBufferSize(size);

    return s_stream->send(p);
}

void AmSrtpConnection::setPassiveMode(bool p)
{
    s_stream->setPassiveMode(p);
    AmStreamConnection::setPassiveMode(p);
}
