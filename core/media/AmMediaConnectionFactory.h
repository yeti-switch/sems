#pragma once

#include "AmRtpConnection.h"
#include "AmDtlsConnection.h"
#include "AmStunConnection.h"
#include "AmSrtpConnection.h"
#include "AmZrtpConnection.h"
#include "AmFaxImage.h"

#include <srtp/srtp.h>

#include <string>
using std::string;

class AmMediaTransport;

class AmMediaConnectionFactory
{
private:
    AmMediaTransport* transport;

    AmStreamConnection* createSrtpConnection(const string& raddr, int rport,
                                          int srtp_profile, const string& local_key,
                                          const srtp_master_keys& remote_keys, bool rtcp);
public:

    struct
    {
        string luser;
        string lpassword;
        string ruser;
        string rpassword;
        unsigned int lpriority;
    } ice_cred;

    struct {
        srtp_profile_t srtp_profile;
        string local_key;
        srtp_master_keys remote_keys;
    } srtp_cred;

    AmMediaConnectionFactory(AmMediaTransport* transport);

    int store_ice_cred(const SdpMedia& local_media, const SdpMedia& remote_media);
    int store_srtp_cred(const SdpMedia& local_media, const SdpMedia& remote_media);
    int store_srtp_cred(uint16_t srtp_profile, const string& local_key, const string& remote_key);

    // create-funcs
    AmStreamConnection* createStunConnection(const string& raddr, int rport,
                                          unsigned int lpriority, unsigned int priority = 0);
    AmStreamConnection* createDtlsConnection(const string& raddr, int rport,
                                          DtlsContext* context);
    AmStreamConnection* createSrtpConnection(const string& raddr, int rport);
    AmStreamConnection* createSrtcpConnection(const string& raddr, int rport);
    AmStreamConnection* createZrtpConnection(const string& raddr, int rport,
                                          zrtpContext* context);
    AmStreamConnection* createRtpConnection(const string& raddr, int rport);
    AmStreamConnection* createRtcpConnection(const string& raddr, int rport);
    AmStreamConnection* createRawConnection(const string& raddr, int rport);
    AmStreamConnection* createUdptlConnection(const string& raddr, int rport);
    AmStreamConnection* createDtlsUdptlConnection(const string& raddr, int rport,
                                                AmStreamConnection *dtls);
};
