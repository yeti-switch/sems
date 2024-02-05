#include <gtest/gtest.h>
#include <sip/parse_common.h>
#include <sip/sip_parser.h>
#include <sip/parse_header.h>
#include <sip/parse_nameaddr.h>
#include <AmUriParser.h>
#include <AmSdp.h>

TEST(SipParser, Parsing)
{
    sip_msg msg;
    char data[] = "INVITE sip:ivan@test.com SIP/2.0\r\n"
                  "Via: SIP/2.0/UDP test.com:5060;branch=kjkjsd54df>\r\n"
                  "To: Ivan Ivanov <sip:ivan@test.com>\r\n"
                  "From: Petr Petrov <sip:petr@test.com>;tag=1456\r\n"
                  "Call-ID: 214df25df\r\n"
                  "CSeq: 1 INVITE\r\n"
                  "Contact: <sip:ivan@test.com>\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Content-Length: 0\r\n";
    char* err;
    msg.copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(&msg, err), EXIT_SUCCESS);
    EXPECT_EQ(msg.from->type, sip_header::H_FROM);
    EXPECT_EQ(msg.to->type, sip_header::H_TO);
    EXPECT_EQ(msg.via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg.callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg.cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg.contacts.size(), 1);
    EXPECT_EQ(msg.contacts.back()->type, sip_header::H_CONTACT);
    EXPECT_EQ(msg.content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg.content_type->type, sip_header::H_CONTENT_TYPE);
    EXPECT_EQ(msg.type, SIP_REQUEST);
    EXPECT_EQ(msg.u.request->method, sip_request::INVITE);
    EXPECT_EQ(msg.u.request->ruri.scheme, sip_uri::SIP);
    EXPECT_STREQ(string(msg.u.request->ruri.user.s, msg.u.request->ruri.user.len).c_str(), string("ivan").c_str());
    EXPECT_STREQ(string(msg.u.request->ruri.host.s, msg.u.request->ruri.host.len).c_str(), string("test.com").c_str());
    msg.release();
    char data1[] = "INVITE sip:ivan@test.com SIP/0.9\r\n\r\n";
    msg.copy_msg_buf(data1, strlen(data1));
    ASSERT_NE(parse_sip_msg(&msg, err), EXIT_SUCCESS);
    msg.release();
    char data2[] = "INVITE sip:ivan@test.com HTTP/1.0\r\n\r\n";
    msg.copy_msg_buf(data2, strlen(data2));
    ASSERT_NE(parse_sip_msg(&msg, err), EXIT_SUCCESS);
    char data3[] = "GET / SIP/2.0\r\n\r\n";
    msg.copy_msg_buf(data3, strlen(data3));
    ASSERT_NE(parse_sip_msg(&msg, err), EXIT_SUCCESS);
    msg.release();
}

TEST(HttpParser, Parsing)
{
    sip_msg msg;
    char data[] = "GET /?encoding=text HTTP/1.1\r\n"
                  "Connection: Upgrade\r\n"
                  "Upgrade: websocket\r\n"
                  "Sec-WebSocket-Version: 13\r\n"
                  "Sec-WebSocket-Key: y1ceknN4VFPuHj7MkaAhVQ==\r\n";
    char* err;
    msg.copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_http_msg(&msg, err), EXIT_SUCCESS);
    msg.release();
    char data1[] = "INVITE sip:ivan@test.com HTTP/0.9\r\n\r\n";
    msg.copy_msg_buf(data1, strlen(data1));
    ASSERT_NE(parse_http_msg(&msg, err), EXIT_SUCCESS);
    msg.release();
    char data2[] = "INVITE sip:ivan@test.com HTTP/0.8\r\n\r\n";
    msg.copy_msg_buf(data2, strlen(data2));
    ASSERT_NE(parse_http_msg(&msg, err), EXIT_SUCCESS);
    char data3[] = "GET / SIP/2.0\r\n\r\n";
    msg.copy_msg_buf(data3, strlen(data3));
    ASSERT_NE(parse_http_msg(&msg, err), EXIT_SUCCESS);
    msg.release();
}

TEST(Parser, Nameaddr)
{
    sip_nameaddr sipuri;
    string uri = "\"test \\\"test\\\"\" <sip:ivan@test.com>";
    const char* url = uri.c_str();
    ASSERT_EQ(parse_nameaddr_uri(&sipuri, &url, uri.size()), EXIT_SUCCESS);
    ASSERT_EQ(strncmp(sipuri.name.s, "\"test \\\"test\\\"\"", sipuri.name.len), 0);
}

TEST(Parser, parse_nameaddr_uri)
{
    sip_nameaddr p;
    string name_addr_str =
        "test "
        "<sip:user@example.com:5080"
        ";uri_param_n_1=uri_param_v_1;uri_param_n_2=uri_param_v_2"
        "?uri_hdr_n_1=uri_hdr_v_1&uri_hdr_n_2=uri_hdr_v_2>"
        ";hdr_param_n_1=hdr_param_v_1;hdr_param_n_2=hdr_param_v_2";

    const char* s = name_addr_str.c_str();
    ASSERT_EQ(parse_nameaddr_uri(&p, &s, name_addr_str.size()), 0);

    ASSERT_EQ(c2stlstr(p.name), "test");
    ASSERT_EQ(c2stlstr(p.uri.user), "user");

    ASSERT_EQ(c2stlstr(p.uri.host), "example.com");
    ASSERT_EQ(p.uri.port, 5080);
    ASSERT_EQ(p.uri.scheme, sip_uri::SIP);

    list<sip_avp*>::iterator i;
    //uri params
    ASSERT_EQ(p.uri.params.size(), 2);
    i = p.uri.params.begin();
    ASSERT_EQ(c2stlstr((*i)->name), "uri_param_n_1");
    ASSERT_EQ(c2stlstr((*i)->value), "uri_param_v_1");
    i++;
    ASSERT_EQ(c2stlstr((*i)->name), "uri_param_n_2");
    ASSERT_EQ(c2stlstr((*i)->value), "uri_param_v_2");

    //uri headers
    ASSERT_EQ(p.uri.hdrs.size(), 2);
    i = p.uri.hdrs.begin();
    ASSERT_EQ(c2stlstr((*i)->name), "uri_hdr_n_1");
    ASSERT_EQ(c2stlstr((*i)->value), "uri_hdr_v_1");
    i++;
    ASSERT_EQ(c2stlstr((*i)->name), "uri_hdr_n_2");
    ASSERT_EQ(c2stlstr((*i)->value), "uri_hdr_v_2");

    //header params
    ASSERT_EQ(p.params.size(), 2);
    i = p.params.begin();
    ASSERT_EQ(c2stlstr((*i)->name), "hdr_param_n_1");
    ASSERT_EQ(c2stlstr((*i)->value), "hdr_param_v_1");
    i++;
    ASSERT_EQ(c2stlstr((*i)->name), "hdr_param_n_2");
    ASSERT_EQ(c2stlstr((*i)->value), "hdr_param_v_2");
}

TEST(Parser, parse_nameaddr_uri_escaping)
{
    sip_nameaddr sipuri;
    string uri = "\"test \\\"test\\\"\" <sip:ivan@test.com>";
    const char* url = uri.c_str();
    ASSERT_EQ(parse_nameaddr_uri(&sipuri, &url, uri.size()), EXIT_SUCCESS);
    ASSERT_EQ(strncmp(sipuri.name.s, "\"test \\\"test\\\"\"", sipuri.name.len), 0);
}

TEST(Parser, parse_nameaddr_tel_uri)
{
    //https://www.rfc-editor.org/rfc/rfc3966
    sip_nameaddr p;
    string name_addr_str =
        "test "
        "<tel:+1-201-555-0123"
        ";uri_param_n_1=uri_param_v_1;uri_param_n_2=uri_param_v_2"
        ">"
        ";hdr_param_n_1=hdr_param_v_1;hdr_param_n_2=hdr_param_v_2";

    const char* s = name_addr_str.c_str();
    ASSERT_EQ(parse_nameaddr_uri(&p, &s, name_addr_str.size()), 0);

    ASSERT_EQ(p.uri.scheme, sip_uri::TEL);
    ASSERT_EQ(c2stlstr(p.uri.user), "+1-201-555-0123");

    list<sip_avp*>::iterator i;
    //uri params
    ASSERT_EQ(p.uri.params.size(), 2);
    i = p.uri.params.begin();
    ASSERT_EQ(c2stlstr((*i)->name), "uri_param_n_1");
    ASSERT_EQ(c2stlstr((*i)->value), "uri_param_v_1");
    i++;
    ASSERT_EQ(c2stlstr((*i)->name), "uri_param_n_2");
    ASSERT_EQ(c2stlstr((*i)->value), "uri_param_v_2");

    //header params
    ASSERT_EQ(p.params.size(), 2);
    i = p.params.begin();
    ASSERT_EQ(c2stlstr((*i)->name), "hdr_param_n_1");
    ASSERT_EQ(c2stlstr((*i)->value), "hdr_param_v_1");
    i++;
    ASSERT_EQ(c2stlstr((*i)->name), "hdr_param_n_2");
    ASSERT_EQ(c2stlstr((*i)->value), "hdr_param_v_2");
}

TEST(Parser, AmUriParser)
{
    AmUriParser p;
    string name_addr_str =
        "test "
        "<sip:user@example.com"
        ";uri_param_n_1=uri_param_v_1;uri_param_n_2=uri_param_v_2"
        "?uri_hdr_n_1=uri_hdr_v_1&uri_hdr_n_2=uri_hdr_v_2>"
        ";hdr_param_n_1=hdr_param_v_1;hdr_param_n_2=hdr_param_v_2";

    ASSERT_EQ(p.parse_nameaddr(name_addr_str), true);

    ASSERT_EQ(p.display_name, "test");
    ASSERT_EQ(p.uri_user, "user");
    ASSERT_EQ(p.uri_host, "example.com");
    ASSERT_EQ(p.uri_port, "");
    ASSERT_EQ(p.uri_scheme, "");

    ASSERT_EQ(p.uri_param, "uri_param_n_1=uri_param_v_1;uri_param_n_2=uri_param_v_2");
    ASSERT_EQ(p.uri_headers, "uri_hdr_n_1=uri_hdr_v_1&uri_hdr_n_2=uri_hdr_v_2");

    ASSERT_EQ(p.params.size(), 2);
    ASSERT_EQ(p.params.begin()->first, "hdr_param_n_1");
    ASSERT_EQ(p.params.begin()->second, "hdr_param_v_1");
    ASSERT_EQ((++p.params.begin())->first, "hdr_param_n_2");
    ASSERT_EQ((++p.params.begin())->second, "hdr_param_v_2");
}

TEST(SdpParser, CryptoTest)
{
    string sdp_str =
    "v=0\r\n"
    "o=SBC 9476009 1001 IN IP4 141.147.136.71\r\n"
    "s=VoipCall\r\n"
    "c=IN IP4 141.147.136.71\r\n"
    "t=0 0\r\n"
    "m=audio 20786 RTP/SAVP 8 0 101\r\n"
    "c=IN IP4 141.147.136.71\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-15\r\n"
    "a=ptime:20\r\n"
    "a=maxptime:40\r\n"
    "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:5LF9Y6retIPykkWDcD49NpnJfBVE7HqVBMPba08z|2^31|1:1;inline:p5UaU+nlSPW6ey/uwj2Hapvm1GV8wE3tviVkp34I|2^31|2:1\r\n"
    "a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:TztUSnIHHtWZ8LG4XXX8CgwoL68n3QVWZu2+/U3Z|2^31|1:1\n"
    "a=crypto:3 AES_256_CM_HMAC_SHA1_80 inline:bN7rll40RDDMly5JpUB0gB4881fHtWFMrWm5nPFWoEjzmy9jLRHz+sWZ0MkeOQ==;inline:dQDxVzWfwTHNumAaPwxszQiiSMb7O467X9D9R5h8YTr1A5JBGPj/T3V0hG9MUQ==\n"
    "a=sendrecv\r\n"
    "a=rtcp:20787";

    AmSdp sdp;

    ASSERT_EQ(sdp.parse(sdp_str.c_str()), 0);

    ASSERT_EQ(sdp.media.size(), 1);
    ASSERT_EQ(sdp.media[0].crypto.size(), 3);

    auto &c1 = sdp.media[0].crypto[0];
    ASSERT_EQ(c1.keys.size(), 2);

    ASSERT_EQ(c1.keys[0].key, "5LF9Y6retIPykkWDcD49NpnJfBVE7HqVBMPba08z");
    ASSERT_EQ(c1.keys[0].lifetime, "2^31");
    ASSERT_EQ(c1.keys[0].mki.id, 1);
    ASSERT_EQ(c1.keys[0].mki.len, 1);

    ASSERT_EQ(c1.keys[1].key, "p5UaU+nlSPW6ey/uwj2Hapvm1GV8wE3tviVkp34I");
    ASSERT_EQ(c1.keys[1].lifetime, "2^31");
    ASSERT_EQ(c1.keys[1].mki.id, 2);
    ASSERT_EQ(c1.keys[1].mki.len, 1);

    ASSERT_EQ(sdp.media[0].crypto[1].keys.size(), 1);

    auto &c2 = sdp.media[0].crypto[2];
    ASSERT_EQ(c2.keys.size(), 2);
    ASSERT_EQ(c2.keys[0].mki.id, 0);
    ASSERT_EQ(c2.keys[0].mki.len, 0);
}
