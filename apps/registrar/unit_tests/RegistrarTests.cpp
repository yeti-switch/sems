#include <gtest/gtest.h>
#include "RegistrarTest.h"
#include "../SipRegistrar.h"
#include "RegistrarTestClient.h"

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

/* Helpers */

#define session_container AmSessionContainer::instance()

#define post_register(req, registration_id)                                                                            \
    session_container->postEvent(                                                                                      \
        SIP_REGISTRAR_QUEUE, new SipRegistrarRegisterRequestEvent(req, REGISTRAR_TEST_CLIENT_QUEUE, registration_id));

#define post_resolve(aor_ids)                                                                                          \
    session_container->postEvent(SIP_REGISTRAR_QUEUE,                                                                  \
                                 new SipRegistrarResolveRequestEvent(aor_ids, REGISTRAR_TEST_CLIENT_QUEUE));


/* Helper Functions */


bool str2am_sip_request(const char *str, AmSipRequest &req)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;
    msg->copy_msg_buf(str, strlen(str));

    const char *err;
    if (parse_sip_msg(msg.get(), err) != EXIT_SUCCESS)
        return false;

    return req.init(msg.get());
}

/* Tests */

/** \brief unbind all records at the beginning of each test */
void unbind_all(RegistrarTestClient &registrar_client, string registration_id, RedisTestServer *test_server)
{
    AmSipRequest req;
    char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                             "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKbqffqskw\r\n"
                             "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                             "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=ursab\r\n"
                             "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                             "CSeq: 99 REGISTER\r\n"
                             "Contact: *\r\n"
                             "User-Agent: Twinkle/1.10.2\r\n"
                             "Expires: 0\r\n";
    str2am_sip_request(req_str, req);
    req.local_if = 0;

    AmArg ret;
    ret.assertArray();
    test_server->addCommandResponse("FCALL register 1 %s 0", REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str());
    test_server->addCommandResponse("EVALSHA %s 1 %s 0", REDIS_TEST_REPLY_ARRAY, ret, register_script_hash,
                                    registration_id.c_str());

    post_register(req, registration_id);
    wait_for_cond(registrar_client.reply_available);
    GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
    GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
    GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs, "");
    registrar_client.reset();
}

/** \brief unbind all -> bind Name1 -> fetch all -> unbind Name1 */
TEST_F(RegistrarTest, TestRegister1)
{
    RegistrarTestClient registrar_client;
    registrar_client.start();

    static RegistrationIdType registration_id = "test";
    unbind_all(registrar_client, registration_id, test_server);

    // bind Name1
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 100 REGISTER\r\n"
                                 "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                                 "X-Orig-Proto: tcp\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(
            R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"]])",
            ret);
        test_server->addCommandResponse(
            "FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d",
            REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str(), "", AmConfig.node_id, interface_name, "",
            "{\"x_orig_proto\":\"tcp\"}", 10);
        test_server->addCommandResponse(
            "EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d", REDIS_TEST_REPLY_ARRAY,
            ret, register_script_hash, registration_id.c_str(), "", AmConfig.node_id, interface_name, "",
            "{\"x_orig_proto\":\"tcp\"}", 10);

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs, "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n");
        registrar_client.reset();
    }

    // fetch all
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxsyeixyv\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=krytr\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 101 REGISTER\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(
            R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"]])",
            ret);
        test_server->addCommandResponse("FCALL register 1 %s", REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str());
        test_server->addCommandResponse("EVALSHA %s 1 %s", REDIS_TEST_REPLY_ARRAY, ret, register_script_hash,
                                        registration_id.c_str());

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs, "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n");
        registrar_client.reset();
    }

    // unbind Name1
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKbqffqskw\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=ursab\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 102 REGISTER\r\n"
                                 "Contact: <sip:Name1@127.0.0.1:6057>;expires=0\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        ret.assertArray();
        test_server->addCommandResponse("FCALL register 1 %s 0 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s",
                                        REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str(), "", AmConfig.node_id,
                                        interface_name, "");
        test_server->addCommandResponse("EVALSHA %s 1 %s 0 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s",
                                        REDIS_TEST_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), "",
                                        AmConfig.node_id, interface_name, "");

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs, "");
        registrar_client.reset();
    }

    stop(registrar_client);
}

/** \brief unbind all -> bind Name1 -> bind Name2 -> fetch all -> unbind Name1 -> unbind Name2 */
TEST_F(RegistrarTest, TestRegister2)
{
    RegistrarTestClient registrar_client;
    registrar_client.start();

    static RegistrationIdType registration_id = "test";
    unbind_all(registrar_client, registration_id, test_server);

    // bind Name1
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 100 REGISTER\r\n"
                                 "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(
            R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"]])",
            ret);
        test_server->addCommandResponse(
            "FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d",
            REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);
        test_server->addCommandResponse(
            "EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d", REDIS_TEST_REPLY_ARRAY,
            ret, register_script_hash, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs, "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n");
        registrar_client.reset();
    }

    // bind Name2
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 101 REGISTER\r\n"
                                 "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(R"raw(
                [
                    ["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"],
                    ["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"]
                ]
            )raw",
                 ret);
        test_server->addCommandResponse(
            "FCALL register 1 %s 3600 sip:Name2@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d",
            REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);
        test_server->addCommandResponse(
            "EVALSHA %s 1 %s 3600 sip:Name2@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d", REDIS_TEST_REPLY_ARRAY,
            ret, register_script_hash, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        // Contacts in the real db may be in a different order so we only check hdrs length
        int hdrs_len = strlen("Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                              "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs.length(), hdrs_len);
        registrar_client.reset();
    }

    // fetch all
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxsyeixyv\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=krytr\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 102 REGISTER\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(R"raw(
                [
                    ["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"],
                    ["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"]
                ]
            )raw",
                 ret);
        test_server->addCommandResponse("FCALL register 1 %s", REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str());
        test_server->addCommandResponse("EVALSHA %s 1 %s", REDIS_TEST_REPLY_ARRAY, ret, register_script_hash,
                                        registration_id.c_str());

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        // Contacts in the real db may be in a different order so we only check hdrs length
        int hdrs_len = strlen("Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                              "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs.length(), hdrs_len);
        registrar_client.reset();
    }

    // unbind Name1
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKbqffqskw\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=ursab\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 103 REGISTER\r\n"
                                 "Contact: <sip:Name1@127.0.0.1:6057>;expires=0\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(
            R"([["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"]])",
            ret);
        test_server->addCommandResponse(
            "FCALL register 1 %s 0 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d", REDIS_TEST_REPLY_ARRAY,
            ret, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);
        test_server->addCommandResponse("EVALSHA %s 1 %s 0 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d",
                                        REDIS_TEST_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), "",
                                        AmConfig.node_id, interface_name, "", "{}", 10);

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs, "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n");
        registrar_client.reset();
    }

    // unbind Name2
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKbqffqskw\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=ursab\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 104 REGISTER\r\n"
                                 "Contact: <sip:Name2@127.0.0.1:6057>;expires=0\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        ret.assertArray();
        test_server->addCommandResponse(
            "FCALL register 1 %s 0 sip:Name2@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d", REDIS_TEST_REPLY_ARRAY,
            ret, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);
        test_server->addCommandResponse("EVALSHA %s 1 %s 0 sip:Name2@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d",
                                        REDIS_TEST_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), "",
                                        AmConfig.node_id, interface_name, "", "{}", 10);

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs, "");
        registrar_client.reset();
    }

    stop(registrar_client);
}

/** \brief unbind all -> bind Name1 -> bind Name2 -> bind Name3 -> unbind all */
TEST_F(RegistrarTest, TestRegister3)
{
    RegistrarTestClient registrar_client;
    registrar_client.start();

    static RegistrationIdType registration_id = "test";
    unbind_all(registrar_client, registration_id, test_server);

    // bind Name1
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 100 REGISTER\r\n"
                                 "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(
            R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"]])",
            ret);
        test_server->addCommandResponse(
            "FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d",
            REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);
        test_server->addCommandResponse(
            "EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d", REDIS_TEST_REPLY_ARRAY,
            ret, register_script_hash, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs, "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n");
        registrar_client.reset();
    }

    // bind Name2
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 101 REGISTER\r\n"
                                 "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(R"raw(
                [
                    ["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"],
                    ["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"]
                ]
            )raw",
                 ret);
        test_server->addCommandResponse(
            "FCALL register 1 %s 3600 sip:Name2@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d",
            REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);
        test_server->addCommandResponse(
            "EVALSHA %s 1 %s 3600 sip:Name2@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d", REDIS_TEST_REPLY_ARRAY,
            ret, register_script_hash, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        // Contacts in the real db may be in a different order so we only check hdrs length
        int hdrs_len = strlen("Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                              "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs.length(), hdrs_len);
        registrar_client.reset();
    }

    // bind Name3
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 102 REGISTER\r\n"
                                 "Contact: <sip:Name3@127.0.0.1:6057>;expires=3600\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(R"raw([
                ["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"],
                ["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"],
                ["sip:Name3@127.0.0.1:6057", 3600, "c:test:sip:Name3@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"]
            ])raw",
                 ret);
        test_server->addCommandResponse(
            "FCALL register 1 %s 3600 sip:Name3@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d",
            REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);
        test_server->addCommandResponse(
            "EVALSHA %s 1 %s 3600 sip:Name3@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d", REDIS_TEST_REPLY_ARRAY,
            ret, register_script_hash, registration_id.c_str(), "", AmConfig.node_id, interface_name, "", "{}", 10);

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        // Contacts in the real db may be in a different order so we only check hdrs length
        int hdrs_len = strlen("Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                              "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n"
                              "Contact: <sip:Name3@127.0.0.1:6057>;expires=3600\r\n");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs.length(), hdrs_len);
        registrar_client.reset();
    }

    unbind_all(registrar_client, registration_id, test_server);
    stop(registrar_client);
}

/** \brief unbind all -> bind Name1 -> fetch all -> resolve -> unbind all */
TEST_F(RegistrarTest, TestResolve1)
{
    RegistrarTestClient registrar_client;
    registrar_client.start();

    static RegistrationIdType registration_id = "test";
    unbind_all(registrar_client, registration_id, test_server);

    // bind Name1
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 100 REGISTER\r\n"
                                 "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                                 "Path: <sip:path1.test.com;lr>\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(
            R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "<sip:path1.test.com;lr>", "input", "Twinkle/1.10.2", "{}"]])",
            ret);
        test_server->addCommandResponse(
            "FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %d", REDIS_TEST_REPLY_ARRAY,
            ret, registration_id.c_str(), "", AmConfig.node_id, interface_name, "<sip:path1.test.com;lr>", 10);
        test_server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %d",
                                        REDIS_TEST_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), "",
                                        AmConfig.node_id, interface_name, "<sip:path1.test.com;lr>", 10);

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        registrar_client.reset();
    }

    // fetch all
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxsyeixyv\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=krytr\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 102 REGISTER\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(
            R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "", "input", "Twinkle/1.10.2", "{}"]])",
            ret);
        test_server->addCommandResponse("FCALL register 1 %s", REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str());
        test_server->addCommandResponse("EVALSHA %s 1 %s", REDIS_TEST_REPLY_ARRAY, ret, register_script_hash,
                                        registration_id.c_str());

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        GTEST_ASSERT_EQ(registrar_client.register_reply_code, 200);
        GTEST_ASSERT_EQ(registrar_client.register_reply_reason, "OK");
        GTEST_ASSERT_EQ(registrar_client.register_reply_hdrs, "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n");
        registrar_client.reset();
    }

    // resolve
    {
        AmArg ret;
        json2arg(R"(["test", ["sip:Name1@127.0.0.1:6057", "<sip:path1.test.com;lr>", "input"]])", ret);
        test_server->addCommandResponse("FCALL_RO aor_lookup 1 %s", REDIS_TEST_REPLY_ARRAY, ret,
                                        registration_id.c_str());
        test_server->addCommandResponse("EVALSHA %s 1 %s", REDIS_TEST_REPLY_ARRAY, ret, aor_lookup_script_hash,
                                        registration_id.c_str());

        post_resolve({ registration_id });
        wait_for_cond(registrar_client.reply_available);
        auto &aors = registrar_client.resolve_reply_aors;
        GTEST_ASSERT_EQ(aors.size(), 1);
        GTEST_ASSERT_EQ(aors[registration_id].front().contact, "sip:Name1@127.0.0.1:6057");
        GTEST_ASSERT_EQ(aors[registration_id].front().path, "<sip:path1.test.com;lr>");
        GTEST_ASSERT_EQ(aors[registration_id].front().interface_name, "input");
        registrar_client.reset();
    }

    unbind_all(registrar_client, registration_id, test_server);
    stop(registrar_client);
}

/** \brief unbind all -> bind Name1 -> bind Name2 -> fetch all -> resolve -> unbind all */
TEST_F(RegistrarTest, TestResolve2)
{
    RegistrarTestClient registrar_client;
    registrar_client.start();

    static RegistrationIdType registration_id = "test";
    unbind_all(registrar_client, registration_id, test_server);

    // bind Name1
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 100 REGISTER\r\n"
                                 "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                                 "Path: <sip:path1.test.com;lr>\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(
            R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "<sip:path1.test.com;lr>", "input", "Twinkle/1.10.2", "{}"]])",
            ret);
        test_server->addCommandResponse(
            "FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %d", REDIS_TEST_REPLY_ARRAY,
            ret, registration_id.c_str(), "", AmConfig.node_id, interface_name, "<sip:path1.test.com;lr>", 10);
        test_server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %d",
                                        REDIS_TEST_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), "",
                                        AmConfig.node_id, interface_name, "<sip:path1.test.com;lr>", 10);

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        registrar_client.reset();
    }

    // bind Name2
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 101 REGISTER\r\n"
                                 "Contact: <sip:Name2@127.0.0.1:6057>;expires=3600\r\n"
                                 "Path: <sip:path2.test.com;lr>\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(R"raw(
                [
                    ["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "<sip:path1.test.com;lr>", "input", "Twinkle/1.10.2", "{}"],
                    ["sip:Name2@127.0.0.1:6057", 3600, "c:test:sip:Name2@127.0.0.1:6057", "", 0, 1, "<sip:path2.test.com;lr>", "input", "Twinkle/1.10.2", "{}"]
                ]
            )raw",
                 ret);
        test_server->addCommandResponse(
            "FCALL register 1 %s 3600 sip:Name2@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s", REDIS_TEST_REPLY_ARRAY,
            ret, registration_id.c_str(), "", AmConfig.node_id, interface_name, "<sip:path2.test.com;lr>");
        test_server->addCommandResponse("EVALSHA %s 1 %s 3600 sip:Name2@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s",
                                        REDIS_TEST_REPLY_ARRAY, ret, register_script_hash, registration_id.c_str(), "",
                                        AmConfig.node_id, interface_name, "<sip:path2.test.com;lr>");

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        registrar_client.reset();
    }

    // resolve
    {
        AmArg ret;
        json2arg(R"raw(
                [
                    "test",
                    [
                        "sip:Name1@127.0.0.1:6057", "<sip:path1.test.com;lr>", "input",
                        "sip:Name2@127.0.0.1:6057", "<sip:path2.test.com;lr>", "input"
                    ]
                ]
            )raw",
                 ret);
        test_server->addCommandResponse("FCALL_RO aor_lookup 1 %s", REDIS_TEST_REPLY_ARRAY, ret,
                                        registration_id.c_str());
        test_server->addCommandResponse("EVALSHA %s 1 %s", REDIS_TEST_REPLY_ARRAY, ret, aor_lookup_script_hash,
                                        registration_id.c_str());

        post_resolve({ registration_id });
        wait_for_cond(registrar_client.reply_available);
        auto &aors = registrar_client.resolve_reply_aors;
        GTEST_ASSERT_EQ(aors.size(), 1);
        GTEST_ASSERT_EQ(aors[registration_id].size(), 2);
        GTEST_ASSERT_TRUE(aors[registration_id].front().contact.length());
        GTEST_ASSERT_TRUE(aors[registration_id].back().contact.length());

        if (aors[registration_id].front().contact == "sip:Name1@127.0.0.1:6057") {
            GTEST_ASSERT_EQ(aors[registration_id].front().path, "<sip:path1.test.com;lr>");
            GTEST_ASSERT_EQ(aors[registration_id].front().interface_name, "input");
        }

        if (aors[registration_id].back().contact == "sip:Name1@127.0.0.1:6057") {
            GTEST_ASSERT_EQ(aors[registration_id].back().path, "<sip:path1.test.com;lr>");
            GTEST_ASSERT_EQ(aors[registration_id].back().interface_name, "input");
        }

        if (aors[registration_id].front().contact == "sip:Name2@127.0.0.1:6057") {
            GTEST_ASSERT_EQ(aors[registration_id].front().path, "<sip:path2.test.com;lr>");
            GTEST_ASSERT_EQ(aors[registration_id].front().interface_name, "input");
        }

        if (aors[registration_id].back().contact == "sip:Name2@127.0.0.1:6057") {
            GTEST_ASSERT_EQ(aors[registration_id].back().path, "<sip:path2.test.com;lr>");
            GTEST_ASSERT_EQ(aors[registration_id].back().interface_name, "input");
        }

        registrar_client.reset();
    }

    unbind_all(registrar_client, registration_id, test_server);
    stop(registrar_client);
}

/** \brief unbind all -> bind Name1 -> check keepalive ctx -> unbind all */
TEST_F(RegistrarTest, TestSubscribe1)
{
    RegistrarTestClient registrar_client;
    registrar_client.start();

    static RegistrationIdType registration_id = "test";
    unbind_all(registrar_client, registration_id, test_server);
    clear_keepalive_context();

    // bind Name1
    {
        AmSipRequest req;
        char         req_str[] = "REGISTER sip:127.0.0.1:5060 SIP/2.0\r\n"
                                 "Via: SIP/2.0/UDP 127.0.0.1:6057;rport;branch=z9hG4bKxibngdbh\r\n"
                                 "To: \"Name\" <sip:Name@127.0.0.1:5060>\r\n"
                                 "From: \"Name\" <sip:Name@127.0.0.1:5060>;tag=yhurn\r\n"
                                 "Call-ID: xpoxwvvkzlbbwvl@debian\r\n"
                                 "CSeq: 100 REGISTER\r\n"
                                 "Contact: <sip:Name1@127.0.0.1:6057>;expires=3600\r\n"
                                 "Path: <sip:path1.test.com;lr>\r\n"
                                 "User-Agent: Twinkle/1.10.2\r\n";
        str2am_sip_request(req_str, req);
        req.local_if = 0;

        AmArg ret;
        json2arg(
            R"([["sip:Name1@127.0.0.1:6057", 3600, "c:test:sip:Name1@127.0.0.1:6057", "", 0, 1, "<sip:path1.test.com;lr>", "input", "Twinkle/1.10.2", "{}"]])",
            ret);
        test_server->addCommandResponse(
            "FCALL register 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d",
            REDIS_TEST_REPLY_ARRAY, ret, registration_id.c_str(), "", AmConfig.node_id, interface_name,
            "<sip:path1.test.com;lr>", "{}", 10);
        test_server->addCommandResponse(
            "EVALSHA %s 1 %s 3600 sip:Name1@127.0.0.1:6057 %s 0 %d %s Twinkle/1.10.2 %s %s %d", REDIS_TEST_REPLY_ARRAY,
            ret, register_script_hash, registration_id.c_str(), "", AmConfig.node_id, interface_name,
            "<sip:path1.test.com;lr>", "{}", 10);

        post_register(req, registration_id);
        wait_for_cond(registrar_client.reply_available);
        registrar_client.reset();
    }

    // check keepalive ctx
    {
        AmArg ret;
        dumpKeepAliveContexts(ret);
        GTEST_ASSERT_EQ(ret[0]["aor"], "sip:Name1@127.0.0.1:6057");
        GTEST_ASSERT_EQ(ret[0]["path"], "<sip:path1.test.com;lr>");
        GTEST_ASSERT_EQ(ret[0]["key"], "c:test:sip:Name1@127.0.0.1:6057");
    }

    unbind_all(registrar_client, registration_id, test_server);
    clear_keepalive_context();
    stop(registrar_client);
}
