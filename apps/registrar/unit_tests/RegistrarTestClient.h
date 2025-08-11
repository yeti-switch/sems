#pragma once

#include <TestClient.h>
#include <SipRegistrarApi.h>

#define REGISTRAR_TEST_CLIENT_QUEUE "registrar_test_client_queue"

using RegistrationIdType = SipRegistrarEvent::RegistrationIdType;
using AorData            = SipRegistrarResolveResponseEvent::aor_data;
using Aors               = map<RegistrationIdType, list<AorData>>;

class RegistrarTestClient : public TestClient {
  protected:
    void process(AmEvent *e) override;

  public:
    RegistrarTestClient();
    void reset() override;

    int    register_reply_code;
    string register_reply_reason;
    string register_reply_hdrs;
    Aors   resolve_reply_aors;
};
