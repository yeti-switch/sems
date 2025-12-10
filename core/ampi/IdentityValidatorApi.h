#pragma once

#include <AmEvent.h>

#define IDENTITY_VALIDATOR_APP_QUEUE "identity_validator"

/* Request */

struct IdentityValidatorRequest : public AmEvent {
    enum Type { LoadTrustedCerts = 0, LoadTrustedRepos, AddIdentity };

    IdentityValidatorRequest(int event_id)
        : AmEvent(event_id)
    {
    }
};

struct LoadTrustedCertsRequest : public IdentityValidatorRequest {
    LoadTrustedCertsRequest()
        : IdentityValidatorRequest(LoadTrustedCerts)
    {
    }
};

struct LoadTrustedReposRequest : public IdentityValidatorRequest {
    LoadTrustedReposRequest()
        : IdentityValidatorRequest(LoadTrustedRepos)
    {
    }
};

struct AddIdentityRequest : public IdentityValidatorRequest {
    vector<string> value;
    string         session_id;
    AddIdentityRequest(const vector<string> &_value, const string &_session_id)
        : IdentityValidatorRequest(AddIdentity)
        , value(_value)
        , session_id(_session_id)
    {
    }
};

/* Response */

struct IdentityValidatorResponse : public AmEvent {
    enum Type { IdentityData = 0 };

    IdentityValidatorResponse(int event_id)
        : AmEvent(event_id)
    {
    }
};

struct IdentityDataResponse : public IdentityValidatorResponse {
    AmArg identity_data;
    IdentityDataResponse(const AmArg &data)
        : IdentityValidatorResponse(IdentityData)
        , identity_data(data)
    {
    }
};
