#pragma once

#include "AmEvent.h"
#include "AmSipMsg.h"

#include <string>
#include <set>
#include <map>

#define SIP_REGISTRAR_QUEUE "sip_registrar"

struct SipRegistrarEvent
  : public AmEvent
{
    using RegistrationIdType = string;

    enum Type {
        RegisterRequest,
        ResolveAors,
        ResolveAorsSubscribe,
        ResolveAorsUnsubscribe,
        TransportDown,
    };

    std::string session_id;

    SipRegistrarEvent(int event_id, const std::string &session_id)
      : AmEvent(event_id),
        session_id(session_id)
    { }
};

struct SipRegistrarRegisterRequestEvent
  : public SipRegistrarEvent
{
    std::unique_ptr<AmSipRequest> req;
    RegistrationIdType registration_id;

    SipRegistrarRegisterRequestEvent(
        const AmSipRequest& req, const std::string &session_id,
        RegistrationIdType registration_id = string())
      : SipRegistrarEvent(RegisterRequest, session_id),
        req(new AmSipRequest(req)),
        registration_id(registration_id)
    {}
};

struct SipRegistrarRegisterResponseEvent
   : public AmEvent
{
    int code;
    std::string reason;
    std::string hdrs;

    SipRegistrarRegisterResponseEvent(
        int code, const std::string &reason,
        const std::string &hdrs = string())
      : AmEvent(SipRegistrarEvent::RegisterRequest),
        code(code), reason(reason), hdrs(hdrs)
    {}
};

struct SipRegistrarResolveRequestEvent
  : public SipRegistrarEvent
{
    std::set<RegistrationIdType> aor_ids;

    SipRegistrarResolveRequestEvent(const std::string &session_id)
      : SipRegistrarEvent(ResolveAors, session_id)
    {}

    SipRegistrarResolveRequestEvent(
        const std::set<RegistrationIdType> &aor_ids,
        const std::string &session_id)
      : SipRegistrarEvent(ResolveAors, session_id),
        aor_ids(aor_ids)
    {}
};

struct SipRegistrarResolveAorsSubscribeEvent
  : public SipRegistrarEvent
{
    std::set<RegistrationIdType> aor_ids;
    std::chrono::milliseconds timeout;

    SipRegistrarResolveAorsSubscribeEvent(const std::string &session_id)
      : SipRegistrarEvent(ResolveAorsSubscribe, session_id)
    {}
};

struct SipRegistrarResolveAorsUnsubscribeEvent
  : public SipRegistrarEvent
{
    std::set<RegistrationIdType> aor_ids;

    SipRegistrarResolveAorsUnsubscribeEvent(const std::string &session_id)
      : SipRegistrarEvent(ResolveAorsUnsubscribe, session_id)
    {}
};

struct SipRegistrarResolveResponseEvent
   : public AmEvent
{
    using RegistrationIdType = SipRegistrarEvent::RegistrationIdType;

    struct aor_data {
        string contact;
        string path;
        aor_data(const char *contact, const char *path)
          : contact(contact),
            path(path)
        {}
    };

    std::map<RegistrationIdType, std::list<aor_data>> aors;

    SipRegistrarResolveResponseEvent()
      : AmEvent(SipRegistrarEvent::ResolveAors)
    {}

    SipRegistrarResolveResponseEvent(
        const std::map<RegistrationIdType, std::list<aor_data>> &aors
    )
      : AmEvent(SipRegistrarEvent::ResolveAors),
        aors(aors)
    {}
};
