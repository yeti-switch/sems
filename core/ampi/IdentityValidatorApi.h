#pragma once

#include <AmEvent.h>

#define IDENTITY_VALIDATOR_APP_QUEUE "identity_validator"

/* Request */

struct IdentityValidatorRequest : public AmEvent {
    enum Type { LoadTrustedCerts = 0, LoadTrustedRepos, ValidateIdentities };

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

struct ValidateIdentitiesRequest : public IdentityValidatorRequest {
    vector<string> identities;
    string         session_id;
    ValidateIdentitiesRequest(const vector<string> &identities, const string &session_id)
        : IdentityValidatorRequest(ValidateIdentities)
        , identities(identities)
        , session_id(session_id)
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

struct ValidateIdentitiesResponse : public IdentityValidatorResponse {
    AmArg identity_data;
    ValidateIdentitiesResponse(const AmArg &data)
        : IdentityValidatorResponse(IdentityData)
        , identity_data(data)
    {
    }
};
