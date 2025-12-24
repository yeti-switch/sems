#include "RegistrarTestClient.h"
#include <AmSessionContainer.h>

#define session_container AmSessionContainer::instance()

RegistrarTestClient::RegistrarTestClient()
    : TestClient(REGISTRAR_TEST_CLIENT_QUEUE)
{
}

void RegistrarTestClient::process(AmEvent *event)
{
    switch (event->event_id) {
    case SipRegistrarEvent::RegisterRequest:
        if (auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event)) {
            register_reply_code   = e->code;
            register_reply_reason = e->reason;
            register_reply_hdrs   = e->hdrs;
            reply_available.set(true);
            register_reply_available.set(true);
            return;
        }
        break;
    case SipRegistrarEvent::ResolveAors:
        if (auto e = dynamic_cast<SipRegistrarResolveResponseEvent *>(event)) {
            resolve_reply_aors = e->aors;
            reply_available.set(true);
            resolve_aors_reply_available.set(true);
            return;
        }
        break;
    case SipRegistrarEvent::TransportDown: break;
    }

    TestClient::process(event);
}

void RegistrarTestClient::reset()
{
    TestClient::reset();
    register_reply_available.set(false);
    resolve_aors_reply_available.set(false);
    register_reply_code   = 0;
    register_reply_reason = "";
    register_reply_hdrs   = "";
    resolve_reply_aors    = {};
}

bool RegistrarTestClient::subscribeForRegEvent(RegistrationIdType reg_id)
{
    auto *event    = new SipRegistrarResolveAorsSubscribeEvent(REGISTRAR_TEST_CLIENT_QUEUE);
    event->timeout = std::chrono::milliseconds(5000);
    event->aor_ids.emplace(reg_id);

    if (false == session_container->postEvent(SIP_REGISTRAR_QUEUE, event)) {
        ERROR("failed to post 'resolve subscribe' event to registrar");
        return false;
    }

    return true;
}

bool RegistrarTestClient::unsubscribeForRegEvent(RegistrationIdType reg_id)
{
    auto *event = new SipRegistrarResolveAorsUnsubscribeEvent(REGISTRAR_TEST_CLIENT_QUEUE);
    event->aor_ids.emplace(reg_id);

    if (false == session_container->postEvent(SIP_REGISTRAR_QUEUE, event)) {
        ERROR("failed to post 'resolve unsubscribe' event to registrar");
        return false;
    }

    return true;
}
