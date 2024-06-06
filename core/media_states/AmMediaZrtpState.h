#pragma once

#include "AmMediaSrtpState.h"

class AmMediaZrtpState
  : public virtual AmMediaSrtpState
{
public:
    AmMediaZrtpState(AmMediaTransport *transport);
    AmMediaState* init(const AmArg& args) override;
    AmMediaState* update(const AmArg& args) override;
    AmMediaState* onSrtpKeysAvailable() override;
    const char* state2str() override;
};
