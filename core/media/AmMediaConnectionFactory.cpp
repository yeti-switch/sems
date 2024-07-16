#include "AmMediaConnectionFactory.h"
#include "AmMediaTransport.h"
#include "AmRtpStream.h"

AmMediaConnectionFactory::AmMediaConnectionFactory(AmMediaTransport* transport)
  : transport(transport)
{
    srtp_cred.srtp_profile = srtp_profile_reserved;
}

int AmMediaConnectionFactory::store_ice_cred(const SdpMedia& local_media, const SdpMedia& remote_media)
{
    ice_cred.luser = local_media.ice_ufrag;
    ice_cred.lpassword = local_media.ice_pwd;
    ice_cred.ruser = remote_media.ice_ufrag;
    ice_cred.rpassword = remote_media.ice_pwd;
    return 0;
}

int AmMediaConnectionFactory::store_srtp_cred(const SdpMedia& local_media, const SdpMedia& remote_media)
{
    int cprofile = transport->getSrtpCredentialsBySdp(local_media, remote_media, srtp_cred.local_key, srtp_cred.remote_keys);
    if(cprofile < 0) return -1;
    srtp_cred.srtp_profile = static_cast<srtp_profile_t>(cprofile);
    return 0;
}

int AmMediaConnectionFactory::store_srtp_cred(uint16_t srtp_profile, const string& local_key, const string& remote_key)
{
    srtp_cred.srtp_profile = static_cast<srtp_profile_t>(srtp_profile);
    srtp_cred.local_key = local_key;
    srtp_cred.remote_keys = remote_key;
    return 0;
}

AmStreamConnection* AmMediaConnectionFactory::createStunConnection(const string& raddr, int rport,
                                                        unsigned int lpriority, unsigned int priority)
{
    AmStunConnection* conn = new AmStunConnection(transport, raddr, rport, lpriority, priority);
    conn->set_credentials(ice_cred.luser, ice_cred.lpassword, ice_cred.ruser, ice_cred.rpassword);
    return conn;
}

AmStreamConnection* AmMediaConnectionFactory::createDtlsConnection(const string& raddr, int rport, DtlsContext* context)
{
    AmDtlsConnection* conn = new AmDtlsConnection(transport, raddr, rport, context);

    context->setCurrentConnection(conn);
    if(!context->isInited()) {
        try {
            transport->getRtpStream()->initDtls(transport->getTransportType(), context->is_client);
        } catch(string& error) {
            CLASS_ERROR("DTLS connection error: %s", error.c_str());
        }
    }

    return conn;
}

AmStreamConnection* AmMediaConnectionFactory::createSrtpConnection(const string& raddr, int rport)
{
    return createSrtpConnection(raddr, rport,
                             srtp_cred.srtp_profile,
                             srtp_cred.local_key,
                             srtp_cred.remote_keys,
                             false);
}

AmStreamConnection* AmMediaConnectionFactory::createSrtpConnection(const string& raddr, int rport,
                                                        int srtp_profile, const string& local_key,
                                                        const srtp_master_keys& remote_keys, bool rtcp)
{
    try {
        AmSrtpConnection* conn = new AmSrtpConnection(transport, raddr, rport, rtcp ? AmStreamConnection::RTCP_CONN : AmStreamConnection::RTP_CONN);
        conn->use_keys(static_cast<srtp_profile_t>(srtp_profile), local_key, remote_keys);

        if(conn->isMute()) {
            transport->getRtpStream()->setMute(true);
        }

        return conn;
    } catch(string& error) {
        CLASS_ERROR("SRTP connection error: %s", error.c_str());
    }

    return nullptr;
}

AmStreamConnection* AmMediaConnectionFactory::createSrtcpConnection(const string& raddr, int rport)
{
    return createSrtpConnection(raddr, rport,
                             srtp_cred.srtp_profile,
                             srtp_cred.local_key,
                             srtp_cred.remote_keys,
                             true);
}

AmStreamConnection* AmMediaConnectionFactory::createZrtpConnection(const string& raddr, int rport, zrtpContext* context) {
    return new AmZRTPConnection(transport, raddr, rport, context);;
}

AmStreamConnection* AmMediaConnectionFactory::createRtpConnection(const string& raddr, int rport)
{
    try {
        return new AmRtpConnection(transport, raddr, rport);;
    } catch(string& error) {
        CLASS_ERROR("RTP connection error: %s", error.c_str());
    }

    return nullptr;
}

AmStreamConnection* AmMediaConnectionFactory::createRtcpConnection(const string& raddr, int rport)
{
    try {
        return new AmRtcpConnection(transport, raddr, rport);
    } catch(string& error) {
        CLASS_ERROR("RTCP connection error: %s", error.c_str());
    }

    return nullptr;
}

AmStreamConnection* AmMediaConnectionFactory::createRawConnection(const string& raddr, int rport)
{
    return new AmRawConnection(transport, raddr, rport);
}

AmStreamConnection* AmMediaConnectionFactory::createUdptlConnection(const string& raddr, int rport)
{
    return new UDPTLConnection(transport, raddr, rport);
}

AmStreamConnection* AmMediaConnectionFactory::createDtlsUdptlConnection(const string& raddr, int rport, AmStreamConnection *dtls)
{
    return new DTLSUDPTLConnection(transport, raddr, rport, dtls);
}
