#include <gtest/gtest.h>
#include <sip/parse_common.h>
#include <sip/sip_parser.h>
#include <sip/parse_header.h>
#include <sip/parse_nameaddr.h>
#include <sip/parse_from_to.h>
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

// rfc4475 3.1.1.1
TEST(SipParser, ShortTortuousTest)
{
    sip_msg msg;
    char data[] = "INVITE sip:vivekg@chair-dnrc.example.com;unknownparam SIP/2.0\r\n"
                  "TO :\r\n"
                  " sip:vivekg@chair-dnrc.example.com ;   tag    = 1918181833n\r\n"
                  "from   : \"J Rosenberg \\\\\\\"\"       <sip:jdrosen@example.com>\r\n"
                  "  ;\r\n"
                  "  tag = 98asjd8\r\n"
                  "MaX-fOrWaRdS: 0068\r\n"
                  "Call-ID: wsinv.ndaksdj@192.0.2.1\r\n"
                  "Content-Length   : 150\r\n"
                  "cseq: 0009\r\n"
                  "  INVITE\r\n"
                  "Via  : SIP  /   2.0\r\n"
                  " /UDP\r\n"
                  "    192.0.2.2;branch=390skdjuw\r\n"
                  "s :\r\n"
                  "NewFangledHeader:   newfangled value\r\n"
                  " continued newfangled value\r\n"
                  "UnknownHeaderWithUnusualValue: ;;,,;;,;\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Route:\r\n"
                  " <sip:services.example.com;lr;unknownwith=value;unknown-no-value>\r\n"
                  "v:  SIP  / 2.0  / TCP     spindle.example.com   ;\r\n"
                  "  branch  =   z9hG4bK9ikj8  ,\r\n"
                  " SIP  /    2.0   / UDP  192.168.255.111   ; branch=\r\n"
                  " z9hG4bK30239\r\n"
                  "m:\"Quoted string \\\"\\\"\" <sip:jdrosen@example.com> ; newparam =\r\n"
                  "      newvalue ;\r\n"
                  "  secondparam ; q = 0.33\r\n"
                  "\r\n"
                  "v=0\r\n"
                  "o=mhandley 29739 7272939 IN IP4 192.0.2.3\r\n"
                  "s=-\r\n"
                  "c=IN IP4 192.0.2.4\r\n"
                  "t=0 0\r\n"
                  "m=audio 49217 RTP/AVP 0 12\r\n"
                  "m=video 3227 RTP/AVP 31\r\n"
                  "a=rtpmap:31 LPC";
    char* err;
    msg.copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(&msg, err), EXIT_SUCCESS);
    EXPECT_EQ(msg.from->type, sip_header::H_FROM);
    EXPECT_EQ(msg.to->type, sip_header::H_TO);
    EXPECT_EQ(msg.via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg.callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg.cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg.route.size(), 1);
    EXPECT_EQ(msg.route.back()->type, sip_header::H_ROUTE);
    EXPECT_EQ(msg.content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg.content_type->type, sip_header::H_CONTENT_TYPE);
    EXPECT_EQ(msg.type, SIP_REQUEST);
    EXPECT_EQ(msg.u.request->method, sip_request::INVITE);
    EXPECT_EQ(msg.u.request->ruri.scheme, sip_uri::SIP);
    EXPECT_STREQ(string(msg.u.request->ruri.user.s, msg.u.request->ruri.user.len).c_str(), string("vivekg").c_str());
    EXPECT_STREQ(string(msg.u.request->ruri.host.s, msg.u.request->ruri.host.len).c_str(), string("chair-dnrc.example.com").c_str());
    msg.release();
}

// rfc4475 3.1.1.2
TEST(SipParser, WideRangeTest)
{
    sip_msg msg;
    char data[] = "!interesting-Method0123456789_*+`.%indeed'~ "
                    "sip:1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*:&it+has=1,weird!*pas$wo~d_too.(doesn't-it)"
                    "@example.com SIP/2.0\r\n"
                  "Via: SIP/2.0/TCP host1.example.com;branch=z9hG4bK-.!%66*_+`'~\r\n"
                  "To: \"BEL: NUL: DEL:\" <sip:1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*@example.com>\r\n"
                  "From: token1~` token2'+_ token3*%!.- "
                    "<sip:mundane@example.com>;fromParam''~+*_!.-%=\"работающий\";tag=_token~1'+`*%!-.\r\n"
                  "Call-ID: intmeth.word%ZK-!.*_+'@word`~)(><:\\/\"][?}{\r\n"
                  "CSeq: 139122385 !interesting-Method0123456789_*+`.%indeed'~\r\n"
                  "Max-Forwards: 255\r\n"
                  "extensionHeader-!.%*+_`'~:大停電\r\n"
                  "Content-Length: 0\r\n";
    char* err;
    msg.copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(&msg, err), EXIT_SUCCESS);
    EXPECT_EQ(msg.from->type, sip_header::H_FROM);
    EXPECT_EQ(msg.to->type, sip_header::H_TO);
    EXPECT_EQ(msg.via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg.callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg.cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg.content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg.type, SIP_REQUEST);
    EXPECT_EQ(msg.u.request->method, sip_request::OTHER_METHOD);
    EXPECT_EQ(msg.u.request->ruri.scheme, sip_uri::SIP);
    EXPECT_STREQ(string(msg.u.request->method_str.s, msg.u.request->method_str.len).c_str(),
                 string("!interesting-Method0123456789_*+`.%indeed'~").c_str());
    EXPECT_STREQ(string(msg.u.request->ruri.user.s, msg.u.request->ruri.user.len).c_str(),
                 string("1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*").c_str());
    EXPECT_STREQ(string(msg.u.request->ruri.passwd.s, msg.u.request->ruri.passwd.len).c_str(),
                 string("&it+has=1,weird!*pas$wo~d_too.(doesn't-it)").c_str());
    EXPECT_STREQ(string(msg.u.request->ruri.host.s, msg.u.request->ruri.host.len).c_str(), string("example.com").c_str());

    sip_from_to* to = (sip_from_to*)msg.to->p;
    sip_from_to* from = (sip_from_to*)msg.from->p;
    EXPECT_STREQ(string(to->nameaddr.name.s, to->nameaddr.name.len).c_str(),
                 string("\"BEL: NUL: DEL:\"").c_str());
    EXPECT_STREQ(string(from->nameaddr.name.s, from->nameaddr.name.len).c_str(),
                 string("token1~` token2'+_ token3*%!.-").c_str());
    EXPECT_STREQ(string(from->tag.s, from->tag.len).c_str(),
                 string("_token~1'+`*%!-.").c_str());
    msg.release();
}

// rfc4475 3.1.1.3
TEST(SipParser, EscapeTest)
{
    sip_msg msg;
    char data[] = "INVITE sip:sips%3Auser%40example.com@example.net SIP/2.0\r\n"
                  "To: sip:%75se%72@example.com\r\n"
                  "From: <sip:I%20have%20spaces@example.net>;tag=938\r\n"
                  "Max-Forwards: 87\r\n"
                  "Call-ID: esc01.239409asdfakjkn23onasd0-3234\r\n"
                  "CSeq: 234234 INVITE\r\n"
                  "Via: SIP/2.0/UDP host5.example.net;branch=z9hG4bKkdjuw\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Contact: <sip:cal%6Cer@host5.example.net;%6C%72;n%61me=v%61lue%25%34%31>\r\n"
                  "Content-Length: 150\r\n"
                  "\r\n"
                  "v=0\r\n"
                  "o=mhandley 29739 7272939 IN IP4 192.0.2.1\r\n"
                  "s=-\r\n"
                  "c=IN IP4 192.0.2.1\r\n"
                  "t=0 0\r\n"
                  "m=audio 49217 RTP/AVP 0 12\r\n"
                  "m=video 3227 RTP/AVP 31\r\n"
                  "a=rtpmap:31 LPC";
    char* err;
    msg.copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(&msg, err), EXIT_SUCCESS);
    EXPECT_EQ(msg.from->type, sip_header::H_FROM);
    EXPECT_EQ(msg.to->type, sip_header::H_TO);
    EXPECT_EQ(msg.via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg.callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg.cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg.content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg.type, SIP_REQUEST);
    EXPECT_EQ(msg.u.request->method, sip_request::INVITE);
    EXPECT_EQ(msg.content_type->type, sip_header::H_CONTENT_TYPE);
    EXPECT_EQ(msg.u.request->ruri.scheme, sip_uri::SIP);
    EXPECT_STREQ(string(msg.u.request->ruri.user.s, msg.u.request->ruri.user.len).c_str(),
                 string("sips%3Auser%40example.com").c_str());
    EXPECT_STREQ(string(msg.u.request->ruri.host.s, msg.u.request->ruri.host.len).c_str(), string("example.net").c_str());
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
