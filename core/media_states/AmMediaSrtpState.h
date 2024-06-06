#pragma once

#include "AmMediaState.h"

class AmMediaSrtpState
  : public virtual AmMediaState
{
public:
    AmMediaSrtpState(AmMediaTransport *transport);
    /* sdes+srtp */
    AmMediaState* init(const AmArg& args) override;
    AmMediaState* update(const AmArg& args) override;
    /* dtls+srtp, zrtp+srtp; base_conn_type is dtls or zrtp */
    AmMediaState* initSrtp(AmStreamConnection::ConnectionType base_conn_type);
    const char* state2str() override;
};
