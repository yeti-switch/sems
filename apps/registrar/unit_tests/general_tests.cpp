#include <gtest/gtest.h>
#include "RegistrarTest.h"
#include "../SipRegistrar.h"
#include "ampi/SipRegistrarApi.h"
#include "RegistrarHandler.h"

#include <sip/parse_common.h>
#include <sip/sip_parser.h>
#include <sip/parse_header.h>
#include <sip/parse_nameaddr.h>
#include <sip/parse_from_to.h>
#include <sip/parse_cseq.h>
#include <sip/parse_100rel.h>
#include <sip/parse_via.h>
#include <AmUriParser.h>
#include <jsonArg.h>

#include <vector>
using std::vector;

using RegistrationIdType = SipRegistrarResolveRequestEvent::RegistrationIdType;

/* Gloval vars */

auto registrarHandler = RegistrarHandler::instance();
auto sessionContainer = AmSessionContainer::instance();

/* marcroses for RegistrarHandler */

#define START(handler) \
    handler->start(); \
    GTEST_ASSERT_EQ(handler->eventPending(), false); \
    GTEST_ASSERT_EQ(handler->is_stopped(), false); \

#define POST_REGISTER(req, registration_id) \
    sessionContainer->postEvent( \
        SIP_REGISTRAR_QUEUE, \
        new SipRegistrarRegisterRequestEvent( \
            req, REGISTRAR_HANDLER_QUEUE, registration_id)); \

#define POST_RESOLVE(aor_ids) \
    sessionContainer->postEvent( \
        SIP_REGISTRAR_QUEUE, \
        new SipRegistrarResolveRequestEvent(aor_ids, REGISTRAR_HANDLER_QUEUE)); \

#define WAIT(handler) \
    for(int r = 0; handler->eventPending() && r < 10; ++r) { \
        DBG("handler pending"); \
        usleep(500); \
    } \
    GTEST_ASSERT_EQ(handler->eventPending(), false); \
    \
    for(int r = 0; !handler->is_stopped() && r < 10; ++r) { \
        DBG("handler stopping"); \
        usleep(500); \
    } \
    GTEST_ASSERT_EQ(handler->is_stopped(), true); \


/* Helper Functions */


bool str2am_sip_request(const char *str, AmSipRequest &req) {
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;
    msg->copy_msg_buf(str, strlen(str));

    const char* err;
    if(parse_sip_msg(msg.get(), err) != EXIT_SUCCESS)
        return false;

    return req.init(msg.get());
}

/* Tests */

/** \brief unbind all records at the beginning of each test */
void unbind_all(string registration_id, RedisTestServer* server) {
    AmSipRequest req;
    char req_str[] =
        "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKbqffqskw\r\n"
        "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
        "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=ursab\r\n"
        "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
        "CSeq: 99 REGISTER\r\n"
        "Contact: *\r\n"
        "User-Agent: Twinkle/1.10.2\r\n"
        "Expires: 0\r\n";
    str2am_sip_request(req_str, req);
    registrarHandler->handle_event = [](AmEvent* event){
        auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
        GTEST_ASSERT_TRUE(e);
        GTEST_ASSERT_EQ(e->code, 200);
        GTEST_ASSERT_EQ(e->reason, "OK");
        GTEST_ASSERT_EQ(e->hdrs, "");
    };

    AmArg ret;
    ret.assertArray();
    server->addCommandResponse("FCALL register 1 %s 0", REDIS_REPLY_ARRAY, ret, registration_id.c_str());
    server->addCommandResponse("EVALSHA %s 1 %s 0", REDIS_REPLY_ARRAY, ret,
        register_script_hash, registration_id.c_str());

    START(registrarHandler);
    POST_REGISTER(req, registration_id);
    WAIT(registrarHandler);
}

/** \brief unbind all -> bind Name1 -> fetch all -> unbind Name1 */
TEST_F(RegistrarTest, TestRegister1) {

    static RegistrationIdType registration_id = "test";
    unbind_all(registration_id, server);

    // bind Name1
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 100 REGISTER\r\n"
            "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0]])", ret);
        server->addCommandResponse("FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "");
        server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "");

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            GTEST_ASSERT_EQ(e->hdrs, "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n");
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // fetch all
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxsyeixyv\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=krytr\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 101 REGISTER\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0]])", ret);
        server->addCommandResponse("FCALL register 1 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str());
        server->addCommandResponse("EVALSHA %s 1 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str());

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            GTEST_ASSERT_EQ(e->hdrs, "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n" );
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // unbind Name1
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKbqffqskw\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=ursab\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 102 REGISTER\r\n"
            "Contact: <sip:Name1@127.0.0.1:6057>;expires=0\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        ret.assertArray();
        server->addCommandResponse("FCALL register 1 %s 0 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "");
        server->addCommandResponse("EVALSHA %s 1 %s 0 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "");

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            GTEST_ASSERT_EQ(e->hdrs, "");
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }
}

/** \brief unbind all -> bind Name1 -> bind Name2 -> fetch all -> unbind Name1 -> unbind Name2 */
TEST_F(RegistrarTest, TestRegister2) {

    static RegistrationIdType registration_id = "test";
    unbind_all(registration_id, server);

    // bind Name1
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 100 REGISTER\r\n"
            "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0]])", ret);
        server->addCommandResponse("FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "");
        server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(),
            AmConfig.node_id, req.local_if, "");

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            GTEST_ASSERT_EQ(e->hdrs, "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n");
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // bind Name2
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 101 REGISTER\r\n"
            "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"raw(
                [
                    ["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0],
                    ["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "", 0]
                ]
            )raw", ret);
        server->addCommandResponse("FCALL register 1 %s 3600 sip:Name2@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "");
        server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name2@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "");

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            GTEST_ASSERT_EQ(e->hdrs,
                "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n");
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // fetch all
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxsyeixyv\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=krytr\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 102 REGISTER\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"raw(
                [
                    ["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0],
                    ["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "", 0]
                ]
            )raw", ret);
        server->addCommandResponse("FCALL register 1 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str());
        server->addCommandResponse("EVALSHA %s 1 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str());

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            GTEST_ASSERT_EQ(e->hdrs,
                "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n");
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // unbind Name1
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKbqffqskw\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=ursab\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 103 REGISTER\r\n"
            "Contact: <sip:Name1@127.0.0.1:6057>;expires=0\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"([["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "", 0]])", ret);
        server->addCommandResponse("FCALL register 1 %s 0 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "");
        server->addCommandResponse("EVALSHA %s 1 %s 0 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "");

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            GTEST_ASSERT_EQ(e->hdrs, "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n");
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // unbind Name2
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKbqffqskw\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=ursab\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 104 REGISTER\r\n"
            "Contact: <sip:Name2@127.0.0.1:6057>;expires=0\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        ret.assertArray();
        server->addCommandResponse("FCALL register 1 %s 0 sip:Name2@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "");
        server->addCommandResponse("EVALSHA %s 1 %s 0 sip:Name2@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "");

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            GTEST_ASSERT_EQ(e->hdrs, "");
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }
}

/** \brief unbind all -> bind Name1 -> bind Name2 -> bind Name3 -> unbind all */
TEST_F(RegistrarTest, TestRegister3) {

    static RegistrationIdType registration_id = "test";
    unbind_all(registration_id, server);

    // bind Name1
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 100 REGISTER\r\n"
            "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0]])", ret);
        server->addCommandResponse("FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "");
        server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "");

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            GTEST_ASSERT_EQ(e->hdrs, "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n");
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // bind Name2
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 101 REGISTER\r\n"
            "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"raw(
                [
                    ["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0],
                    ["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "", 0]
                ]
            )raw", ret);
        server->addCommandResponse("FCALL register 1 %s 3600 sip:Name2@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "");
        server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name2@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "");

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            /*GTEST_ASSERT_EQ(e->hdrs,
                "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n");*/

            // Contacts in the real db may be in a different order so we only check hdrs length
            int hdrs_len = strlen(
                "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n"
            );
            GTEST_ASSERT_EQ(e->hdrs.length(), hdrs_len);
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // bind Name3
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 102 REGISTER\r\n"
            "Contact: <sip:Name3@127.0.0.1:6057>;expires=3600\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"raw([
                ["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0],
                ["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "", 0],
                ["sip:Name3@127.0.0.1:6057", 3600, "c:test:sip:Name3@127.0.0.1:6057", "", 0]
            ])raw", ret);
        server->addCommandResponse("FCALL register 1 %s 3600 sip:Name3@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "");
        server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name3@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "");

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            /*GTEST_ASSERT_EQ(e->hdrs,
                "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n"
                "Contact: <sip:Name3@127.0.0.1:6057>;expires=3600\r\n");*/

            // Contacts in the real db may be in a different order so we only check hdrs length
            int hdrs_len = strlen(
                "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n"
                "Contact: <sip:Name3@127.0.0.1:6057>;expires=3600\r\n"
            );
            GTEST_ASSERT_EQ(e->hdrs.length(), hdrs_len);
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    unbind_all(registration_id, server);
}

/** \brief unbind all -> bind Name1 -> fetch all -> resolve -> unbind all */
TEST_F(RegistrarTest, TestResolve1) {

    static RegistrationIdType registration_id = "test";
    unbind_all(registration_id, server);

    // bind Name1
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 100 REGISTER\r\n"
            "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
            "Path: <sip:path1.test.com;lr>\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "<sip:path1.test.com;lr>", 0]])", ret);
        server->addCommandResponse("FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "<sip:path1.test.com;lr>");
        server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "<sip:path1.test.com;lr>");

        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // fetch all
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxsyeixyv\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=krytr\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 102 REGISTER\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0]])", ret);
        server->addCommandResponse("FCALL register 1 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str());
        server->addCommandResponse("EVALSHA %s 1 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str());

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarRegisterResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->code, 200);
            GTEST_ASSERT_EQ(e->reason, "OK");
            GTEST_ASSERT_EQ(e->hdrs,
                "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n");
        };
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // resolve
    {
        AmArg ret;
        json2arg(R"(["test", ["sip:Name1@127.0.0.1:6057", "<sip:path1.test.com;lr>"]])", ret);
        server->addCommandResponse("FCALL_RO aor_lookup 1 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str());
        server->addCommandResponse("EVALSHA %s 1 %s",
            REDIS_REPLY_ARRAY, ret, aor_lookup_script_hash, registration_id.c_str());

        registrarHandler->handle_event = [](AmEvent* event) {
            auto e = dynamic_cast<SipRegistrarResolveResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->aors.size(), 1);
            GTEST_ASSERT_EQ(e->aors[registration_id].front().contact, "sip:Name1@127.0.0.1:6057");
            GTEST_ASSERT_EQ(e->aors[registration_id].front().path, "<sip:path1.test.com;lr>");
        };
        START(registrarHandler);
        POST_RESOLVE({registration_id});
        WAIT(registrarHandler);
    }

    unbind_all(registration_id, server);
}

/** \brief unbind all -> bind Name1 -> bind Name2 -> fetch all -> resolve -> unbind all */
TEST_F(RegistrarTest, TestResolve2) {

    static RegistrationIdType registration_id = "test";
    unbind_all(registration_id, server);

    // bind Name1
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 100 REGISTER\r\n"
            "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
            "Path: <sip:path1.test.com;lr>\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";

        AmArg ret;
        json2arg(R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "<sip:path1.test.com;lr>", 0]])", ret);
        server->addCommandResponse("FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "<sip:path1.test.com;lr>");
        server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "<sip:path1.test.com;lr>");

        str2am_sip_request(req_str, req);
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // bind Name2
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 101 REGISTER\r\n"
            "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n"
            "Path: <sip:path2.test.com;lr>\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";

        AmArg ret;
        json2arg(R"raw(
                [
                    ["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "<sip:path1.test.com;lr>", 0],
                    ["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "<sip:path2.test.com;lr>", 0]
                ]
            )raw", ret);
        server->addCommandResponse("FCALL register 1 %s 3600 sip:Name2@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "<sip:path2.test.com;lr>");
        server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name2@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "<sip:path2.test.com;lr>");

        str2am_sip_request(req_str, req);
        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // resolve
    {
        AmArg ret;
        json2arg(R"raw(
                [
                    "test",
                    [
                        "sip:Name1@127.0.0.1:6057", "<sip:path1.test.com;lr>",
                        "sip:Name2@127.0.0.1:6057", "<sip:path2.test.com;lr>"
                    ]
                ]
            )raw", ret);
        server->addCommandResponse("FCALL_RO aor_lookup 1 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str());
        server->addCommandResponse("EVALSHA %s 1 %s",
            REDIS_REPLY_ARRAY, ret, aor_lookup_script_hash, registration_id.c_str());

        registrarHandler->handle_event = [](AmEvent* event){
            auto e = dynamic_cast<SipRegistrarResolveResponseEvent *>(event);
            GTEST_ASSERT_TRUE(e);
            GTEST_ASSERT_EQ(e->aors.size(), 1);
            GTEST_ASSERT_EQ(e->aors[registration_id].size(), 2);
            GTEST_ASSERT_EQ(e->aors[registration_id].front().contact, "sip:Name1@127.0.0.1:6057");
            GTEST_ASSERT_EQ(e->aors[registration_id].front().path, "<sip:path1.test.com;lr>");
            GTEST_ASSERT_EQ(e->aors[registration_id].back().contact, "sip:Name2@127.0.0.1:6057");
            GTEST_ASSERT_EQ(e->aors[registration_id].back().path, "<sip:path2.test.com;lr>");
        };
        START(registrarHandler);
        POST_RESOLVE({registration_id});
        WAIT(registrarHandler);
    }

    unbind_all(registration_id, server);
}

/** \brief unbind all -> bind Name1 -> check keepalive ctx -> unbind all */
TEST_F(RegistrarTest, TestSubscribe1) {

    static RegistrationIdType registration_id = "test";
    unbind_all(registration_id, server);
    clear_keepalive_context();

    // bind Name1
    {
        AmSipRequest req;
        char req_str[] =
            "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
            "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
            "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
            "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
            "CSeq: 100 REGISTER\r\n"
            "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
            "Path: <sip:path1.test.com;lr>\r\n"
            "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);

        AmArg ret;
        json2arg(R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "<sip:path1.test.com;lr>", 0]])", ret);
        server->addCommandResponse("FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, registration_id.c_str(), AmConfig.node_id, req.local_if, "<sip:path1.test.com;lr>");
        server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %d %d Twinkle/1.10.2 %s",
            REDIS_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), AmConfig.node_id, req.local_if, "<sip:path1.test.com;lr>");

        START(registrarHandler);
        POST_REGISTER(req, registration_id);
        WAIT(registrarHandler);
    }

    // check keepalive ctx
    {
        AmArg ret;
        get_contacts_subscription()->dumpKeepAliveContexts(ret);
        GTEST_ASSERT_EQ(ret[0]["aor"], "sip:Name1@127.0.0.1:6057");
        GTEST_ASSERT_EQ(ret[0]["path"], "<sip:path1.test.com;lr>");
        GTEST_ASSERT_EQ(ret[0]["key"], "c:test:sip:Name1@127.0.0.1:6057");
    }

    unbind_all(registration_id, server);
    clear_keepalive_context();
}

