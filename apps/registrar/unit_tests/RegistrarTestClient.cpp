#include "RegistrarTestClient.h"

RegistrarTestClient::RegistrarTestClient()
  : TestClient(REGISTRAR_TEST_CLIENT_QUEUE)
{}

void RegistrarTestClient::process(AmEvent* event)
{
    switch(event->event_id) {
        case SipRegistrarEvent::RegisterRequest:
            if(auto e = dynamic_cast<SipRegistrarRegisterResponseEvent*>(event)) {
                register_reply_code = e->code;
                register_reply_reason = e->reason;
                register_reply_hdrs = e->hdrs;
                reply_available.set(true);
                return;
            }
            break;
        case SipRegistrarEvent::ResolveAors:
            if(auto e = dynamic_cast<SipRegistrarResolveResponseEvent*>(event)) {
                resolve_reply_aors = e->aors;
                reply_available.set(true);
                return;
            }
            break;
        case SipRegistrarEvent::TransportDown:
            break;
    }

    TestClient::process(event);
}

void RegistrarTestClient::reset() {
    TestClient::reset();
    register_reply_code = 0;
    register_reply_reason = "";
    register_reply_hdrs = "";
    resolve_reply_aors = {};
}
