#pragma once

#include "AmMediaState.h"

class AmMediaDtlsState
  : public virtual AmMediaState
{
protected:
    bool is_dtls_srtp;

public:
    AmMediaDtlsState(AmMediaTransport *transport);
    AmMediaState* init(const AmArg& args) override;
    AmMediaState* update(const AmArg& args) override;
    AmMediaState* onSrtpKeysAvailable() override;
    bool isDtlsSrtp() { return is_dtls_srtp; }
    const char* state2str() override;
};
