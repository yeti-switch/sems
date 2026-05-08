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
    string session_id;
    LoadTrustedCertsRequest(const string &_session_id)
        : IdentityValidatorRequest(LoadTrustedCerts)
        , session_id(_session_id)
    {
    }
};

struct LoadTrustedReposRequest : public IdentityValidatorRequest {
    string session_id;
    LoadTrustedReposRequest(const string &_session_id)
        : IdentityValidatorRequest(LoadTrustedRepos)
        , session_id(_session_id)
    {
    }
};

struct ValidateIdentitiesRequest : public IdentityValidatorRequest {
    vector<string> identities;
    string         session_id;
    ValidateIdentitiesRequest(const vector<string> &identities, const string &_session_id)
        : IdentityValidatorRequest(ValidateIdentities)
        , identities(identities)
        , session_id(_session_id)
    {
    }
};

/* Response */

struct IdentityValidatorResponse : public AmEvent {
    enum Type { IdentityData = 0, TrustedCerts, TrustedRepos };

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

struct TrustedCertsResponse : public IdentityValidatorResponse {
    bool success;
    TrustedCertsResponse(bool _success)
        : IdentityValidatorResponse(TrustedCerts)
        , success(_success)
    {
    }
};

struct TrustedReposResponse : public IdentityValidatorResponse {
    bool success;
    TrustedReposResponse(bool _success)
        : IdentityValidatorResponse(TrustedRepos)
        , success(_success)
    {
    }
};
