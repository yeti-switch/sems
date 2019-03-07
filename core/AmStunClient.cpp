#include "AmStunClient.h"

AmStunClient::AmStunClient(AmRtpStream* rtp_stream)
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
}

void AmStunClient::on_data_recv(uint8_t* data, unsigned int* size)
{
}

HRESULT AmStunClient::DoAuthCheck(AuthAttributes* pAuthAttributes, AuthResponse* pResponse)
{
    return S_OK;
}
