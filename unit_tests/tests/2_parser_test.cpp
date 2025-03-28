#include <gtest/gtest.h>
#include <sip/parse_common.h>
#include <sip/sip_parser.h>
#include <sip/parse_header.h>
#include <sip/parse_nameaddr.h>
#include <sip/parse_from_to.h>
#include <sip/parse_via.h>
#include <AmUriParser.h>
#include <AmSdp.h>

TEST(SipParser, Parsing)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;
    char data[] = "INVITE sip:ivan@test.com SIP/2.0\r\n"
                  "Via: SIP/2.0/UDP test.com:5060;branch=kjkjsd54df>\r\n"
                  "To: Ivan Ivanov <sip:ivan@test.com>\r\n"
                  "From: Petr Petrov <sip:petr@test.com>;tag=1456\r\n"
                  "Call-ID: 214df25df\r\n"
                  "CSeq: 1 INVITE\r\n"
                  "Contact: <sip:ivan@test.com>\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Content-Length: 0\r\n";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    EXPECT_EQ(msg->from->type, sip_header::H_FROM);
    EXPECT_EQ(msg->to->type, sip_header::H_TO);
    EXPECT_EQ(msg->via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg->callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg->cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg->contacts.size(), 1);
    EXPECT_EQ(msg->contacts.back()->type, sip_header::H_CONTACT);
    EXPECT_EQ(msg->content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg->content_type->type, sip_header::H_CONTENT_TYPE);
    EXPECT_EQ(msg->type, SIP_REQUEST);
    EXPECT_EQ(msg->u.request->method, sip_request::INVITE);
    EXPECT_EQ(msg->u.request->ruri.scheme, sip_uri::SIP);
    EXPECT_STREQ(string(msg->u.request->ruri.user.s, msg->u.request->ruri.user.len).c_str(), string("ivan").c_str());
    EXPECT_STREQ(string(msg->u.request->ruri.host.s, msg->u.request->ruri.host.len).c_str(), string("test.com").c_str());

    msg.reset(new sip_msg());
    msg->type = SIP_REQUEST;
    char data1[] = "INVITE sip:ivan@test.com SIP/0.9\r\n\r\n";
    msg->copy_msg_buf(data1, strlen(data1));
    ASSERT_NE(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);

    msg.reset(new sip_msg());
    msg->type = SIP_REQUEST;
    char data2[] = "INVITE sip:ivan@test.com HTTP/1.0\r\n\r\n";
    msg->copy_msg_buf(data2, strlen(data2));
    ASSERT_NE(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);

    msg.reset(new sip_msg());
    msg->type = SIP_REQUEST;
    char data3[] = "GET / SIP/2.0\r\n\r\n";
    msg->copy_msg_buf(data3, strlen(data3));
    ASSERT_NE(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
}

// rfc4475 3.1.1.1
TEST(SipParser, ShortTortuousTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;
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
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    EXPECT_EQ(msg->from->type, sip_header::H_FROM);
    EXPECT_EQ(msg->to->type, sip_header::H_TO);
    EXPECT_EQ(msg->via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg->callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg->cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg->route.size(), 1);
    EXPECT_EQ(msg->route.back()->type, sip_header::H_ROUTE);
    EXPECT_EQ(msg->content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg->content_type->type, sip_header::H_CONTENT_TYPE);
    EXPECT_EQ(msg->type, SIP_REQUEST);
    EXPECT_EQ(msg->u.request->method, sip_request::INVITE);
    EXPECT_EQ(msg->u.request->ruri.scheme, sip_uri::SIP);
    EXPECT_STREQ(string(msg->u.request->ruri.user.s, msg->u.request->ruri.user.len).c_str(), string("vivekg").c_str());
    EXPECT_STREQ(string(msg->u.request->ruri.host.s, msg->u.request->ruri.host.len).c_str(), string("chair-dnrc.example.com").c_str());
}

// rfc4475 3.1.1.2
TEST(SipParser, WideRangeTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

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
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    EXPECT_EQ(msg->from->type, sip_header::H_FROM);
    EXPECT_EQ(msg->to->type, sip_header::H_TO);
    EXPECT_EQ(msg->via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg->callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg->cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg->content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg->type, SIP_REQUEST);
    EXPECT_EQ(msg->u.request->method, sip_request::OTHER_METHOD);
    EXPECT_EQ(msg->u.request->ruri.scheme, sip_uri::SIP);
    EXPECT_STREQ(string(msg->u.request->method_str.s, msg->u.request->method_str.len).c_str(),
                 string("!interesting-Method0123456789_*+`.%indeed'~").c_str());
    EXPECT_STREQ(string(msg->u.request->ruri.user.s, msg->u.request->ruri.user.len).c_str(),
                 string("1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*").c_str());
    EXPECT_STREQ(string(msg->u.request->ruri.passwd.s, msg->u.request->ruri.passwd.len).c_str(),
                 string("&it+has=1,weird!*pas$wo~d_too.(doesn't-it)").c_str());
    EXPECT_STREQ(string(msg->u.request->ruri.host.s, msg->u.request->ruri.host.len).c_str(), string("example.com").c_str());

    sip_from_to* to = (sip_from_to*)msg->to->p;
    sip_from_to* from = (sip_from_to*)msg->from->p;
    EXPECT_STREQ(string(to->nameaddr.name.s, to->nameaddr.name.len).c_str(),
                 string("\"BEL: NUL: DEL:\"").c_str());
    EXPECT_STREQ(string(from->nameaddr.name.s, from->nameaddr.name.len).c_str(),
                 string("token1~` token2'+_ token3*%!.-").c_str());
    EXPECT_STREQ(string(from->tag.s, from->tag.len).c_str(),
                 string("_token~1'+`*%!-.").c_str());
}

// rfc4475 3.1.1.3-5
TEST(SipParser, EscapeTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "INVITE sip:sips%3Auser%40example.com@example.net SIP/2.0\r\n"
                  "To: sip:%00se%72@example.com\r\n"
                  "From: <sip:I%20have%20spaces@example.net>;tag=938\r\n"
                  "Max-Forwards: 87\r\n"
                  "Call-ID: esc01.239409asdfakjkn23onasd0-3234\r\n"
                  "CSeq: 234234 INVITE\r\n"
                  "Via: SIP/2.0/UDP host5.example.net;branch=z9hG4bKkdjuw\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Contact: <sip:cal%6Cer@host5.example.net;%6C%72;n%61me=v%61lue%00%34%31>\r\n"
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
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    EXPECT_EQ(msg->from->type, sip_header::H_FROM);
    EXPECT_EQ(msg->to->type, sip_header::H_TO);
    EXPECT_EQ(msg->via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg->callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg->cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg->content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg->type, SIP_REQUEST);
    EXPECT_EQ(msg->u.request->method, sip_request::INVITE);
    EXPECT_EQ(msg->content_type->type, sip_header::H_CONTENT_TYPE);
    EXPECT_EQ(msg->u.request->ruri.scheme, sip_uri::SIP);
    EXPECT_STREQ(string(msg->u.request->ruri.user.s, msg->u.request->ruri.user.len).c_str(),
                 string("sips%3Auser%40example.com").c_str());
    EXPECT_STREQ(string(msg->u.request->ruri.host.s, msg->u.request->ruri.host.len).c_str(), string("example.net").c_str());
}

// rfc4475 3.1.1.8
TEST(SipParser, ExtraOctetsTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    //msg->type = SIP_REQUEST;

    char data[] = "REGISTER sip:example.com SIP/2.0\r\n"
                  "To: sip:j.user@example.com\r\n"
                  "From: sip:j.user@example.com;tag=43251j3j324\r\n"
                  "Max-Forwards: 8\r\n"
                  "Call-ID: dblreq.0ha0isndaksdj99sdfafnl3lk233412\r\n"
                  "Contact: sip:j.user@host.example.com\r\n"
                  "CSeq: 8 REGISTER\r\n"
                  "Via: SIP/2.0/UDP 192.0.2.125;branch=z9hG4bKkdjuw23492\r\n"
                  "Content-Length: 0\r\n"
                  "\r\n"
                  "INVITE sip:joe@example.com SIP/2.0\r\n"
                  "To: sip:joe@example.com\r\n"
                  "From: sip:caller@example.net;tag=141334\r\n"
                  "Max-Forwards: 8\r\n"
                  "Call-ID: dblreq.0ha0isnda977644900765@192.0.2.15\r\n"
                  "CSeq: 8 INVITE\r\n"
                  "Via: SIP/2.0/UDP 192.0.2.15;branch=z9hG4bKkdjuw380234\r\n"
                  "Content-Length: 0\r\n";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    EXPECT_EQ(msg->from->type, sip_header::H_FROM);
    EXPECT_EQ(msg->to->type, sip_header::H_TO);
    EXPECT_EQ(msg->via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg->callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg->cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg->content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg->type, SIP_REQUEST);
    EXPECT_EQ(msg->u.request->method, sip_request::REGISTER);
}

// rfc4475 3.1.1.9
TEST(SipParser, SemicolonSepTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "OPTIONS sip:user;par=example.net@example.com SIP/2.0\r\n"
                  "To: sip:j_user@example.com\r\n"
                  "From: sip:caller@example.org;tag=33242\r\n"
                  "Max-Forwards: 3\r\n"
                  "Call-ID: semiuri.0ha0isndaksdj\r\n"
                  "CSeq: 8 OPTIONS\r\n"
                  "Accept: application/sdp, application/pkcs7-mime\r\n"
                  "Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKkdjuw\r\n"
                  "Content-Length: 0\r\n";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    EXPECT_EQ(msg->from->type, sip_header::H_FROM);
    EXPECT_EQ(msg->to->type, sip_header::H_TO);
    EXPECT_EQ(msg->via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg->callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg->cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg->content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg->type, SIP_REQUEST);
    EXPECT_EQ(msg->u.request->method, sip_request::OPTIONS);
    EXPECT_EQ(msg->u.request->ruri.scheme, sip_uri::SIP);
    EXPECT_STREQ(string(msg->u.request->ruri.user.s, msg->u.request->ruri.user.len).c_str(),
                 string("user;par=example.net").c_str());
    EXPECT_STREQ(string(msg->u.request->ruri.host.s, msg->u.request->ruri.host.len).c_str(), string("example.com").c_str());
}

// rfc4475 3.1.1.10
TEST(SipParser, TransportTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "OPTIONS sip:user@example.com SIP/2.0\r\n"
                  "To: sip:user@example.com\r\n"
                  "From: <sip:caller@example.com>;tag=323\r\n"
                  "Max-Forwards: 70\r\n"
                  "Call-ID:  transports.kijh4akdnaqjkwendsasfdj\r\n"
                  "Accept: application/sdp\r\n"
                  "CSeq: 60 OPTIONS\r\n"
                  "Via: SIP/2.0/UDP t1.example.com;branch=z9hG4bKkdjuw\r\n"
                  "Via: SIP/2.0/SCTP t2.example.com;branch=z9hG4bKklasjdhf\r\n"
                  "Via: SIP/2.0/TLS t3.example.com;branch=z9hG4bK2980unddj\r\n"
                  "Via: SIP/2.0/UNKNOWN t4.example.com;branch=z9hG4bKasd0f3en\r\n"
                  "Via: SIP/2.0/TCP t5.example.com;branch=z9hG4bK0a9idfnee\r\n"
                  "Content-Length: 0\r\n";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    EXPECT_EQ(msg->from->type, sip_header::H_FROM);
    EXPECT_EQ(msg->to->type, sip_header::H_TO);
    EXPECT_EQ(msg->via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg->callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg->cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg->content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg->type, SIP_REQUEST);
    EXPECT_EQ(msg->u.request->method, sip_request::OPTIONS);
    EXPECT_EQ(msg->vias.size(), 5);
    sip_via* via1 = (sip_via*)msg->via1->p;
    EXPECT_EQ(via1->parms.back()->trans.type, sip_transport::UDP);
}

// rfc4475 3.1.1.12
TEST(SipParser, ReplyReasonTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "SIP/2.0 200 = 2**3 * 5**2 но сто девяносто девять - простое\r\n"
                  "Via: SIP/2.0/UDP 192.0.2.198;branch=z9hG4bK1324923\r\n"
                  "Call-ID: unreason.1234ksdfak3j2erwedfsASdf\r\n"
                  "CSeq: 35 INVITE\r\n"
                  "From: sip:user@example.com;tag=11141343\r\n"
                  "To: sip:user@example.edu;tag=2229\r\n"
                  "Content-Length: 154\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Contact: <sip:user@host198.example.com>\r\n"
                  "\r\n"
                  "v=0\r\n"
                  "o=mhandley 29739 7272939 IN IP4 192.0.2.198\r\n"
                  "s=-\r\n"
                  "c=IN IP4 192.0.2.198\r\n"
                  "t=0 0\r\n"
                  "m=audio 49217 RTP/AVP 0 12\r\n"
                  "m=video 3227 RTP/AVP 31\r\n"
                  "a=rtpmap:31 LPC";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    EXPECT_EQ(msg->from->type, sip_header::H_FROM);
    EXPECT_EQ(msg->to->type, sip_header::H_TO);
    EXPECT_EQ(msg->via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg->callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg->cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg->content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg->type, SIP_REPLY);
    EXPECT_EQ(msg->u.reply->code, 200);
    EXPECT_STREQ(string(msg->u.reply->reason.s, msg->u.reply->reason.len).c_str(),
                 string("= 2**3 * 5**2 но сто девяносто девять - простое").c_str());
}

// rfc4475 3.1.1.13
TEST(SipParser, EmptyReasonTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    //msg->type = SIP_REPLY;

    char data[] = "SIP/2.0 100 \r\n"
                  "Via: SIP/2.0/UDP 192.0.2.198;branch=z9hG4bK1324923\r\n"
                  "Call-ID: unreason.1234ksdfak3j2erwedfsASdf\r\n"
                  "CSeq: 35 INVITE\r\n"
                  "From: sip:user@example.com;tag=11141343\r\n"
                  "To: sip:user@example.edu;tag=2229\r\n"
                  "Content-Length: 0\r\n"
                  "Contact: <sip:user@host198.example.com>";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    EXPECT_EQ(msg->from->type, sip_header::H_FROM);
    EXPECT_EQ(msg->to->type, sip_header::H_TO);
    EXPECT_EQ(msg->via1->type, sip_header::H_VIA);
    EXPECT_EQ(msg->callid->type, sip_header::H_CALL_ID);
    EXPECT_EQ(msg->cseq->type, sip_header::H_CSEQ);
    EXPECT_EQ(msg->content_length->type, sip_header::H_CONTENT_LENGTH);
    EXPECT_EQ(msg->type, SIP_REPLY);
    EXPECT_EQ(msg->u.reply->code, 100);
    EXPECT_EQ(msg->u.reply->reason.len, 0);
    EXPECT_EQ((int64_t)msg->u.reply->reason.s, 0);
}

// rfc4475 3.1.2.2
TEST(SipParser, ContentLargerTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "INVITE sip:user@example.com SIP/2.0\r\n"
                  "Max-Forwards: 80\r\n"
                  "To: sip:j.user@example.com\r\n"
                  "From: sip:caller@example.net;tag=93942939o2\r\n"
                  "Contact: <sip:caller@hungry.example.net>\r\n"
                  "Call-ID: clerr.0ha0isndaksdjweiafasdk3\r\n"
                  "CSeq: 8 INVITE\r\n"
                  "Via: SIP/2.0/UDP host5.example.com;branch=z9hG4bK-39234-23523\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Content-Length: 9999\r\n"
                  "\r\n"
                  "v=0\r\n"
                  "o=mhandley 29739 7272939 IN IP4 192.0.2.155\r\n"
                  "s=-\r\n"
                  "c=IN IP4 192.0.2.155\r\n"
                  "t=0 0\r\n"
                  "m=audio 49217 RTP/AVP 0 12\r\n"
                  "m=video 3227 RTP/AVP 31\r\n"
                  "a=rtpmap:31 LPC";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_SIP_MSG);
}

// rfc4475 3.1.2.3
TEST(SipParser, ContentNegativeTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "INVITE sip:user@example.com SIP/2.0\r\n"
                  "Max-Forwards: 254\r\n"
                  "To: sip:j.user@example.com\r\n"
                  "From: sip:caller@example.net;tag=32394234\r\n"
                  "Call-ID: ncl.0ha0isndaksdj2193423r542w35\r\n"
                  "CSeq: 0 INVITE\r\n"
                  "Via: SIP/2.0/UDP 192.0.2.53;branch=z9hG4bKkdjuw\r\n"
                  "Contact: <sip:caller@example53.example.net>\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Content-Length: -999\r\n"
                  "\r\n"
                  "v=0\r\n"
                  "o=mhandley 29739 7272939 IN IP4 192.0.2.53\r\n"
                  "s=-\r\n"
                  "c=IN IP4 192.0.2.53\r\n"
                  "t=0 0\r\n"
                  "m=audio 49217 RTP/AVP 0 12\r\n"
                  "m=video 3227 RTP/AVP 31\r\n"
                  "a=rtpmap:31 LPC";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_SIP_MSG);
}

// rfc4475 3.1.2.4-5
TEST(SipParser, ScalarTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "REGISTER sip:example.com SIP/2.0\r\n"
                  "Via: SIP/2.0/TCP host129.example.com;branch=z9hG4bK342sdfoi3\r\n"
                  "To: <sip:user@example.com>\r\n"
                  "From: <sip:user@example.com>;tag=239232jh3\r\n"
                  "CSeq: 36893488147419103232 REGISTER\r\n"
                  "Call-ID: scalar02.23o0pd9vanlq3wnrlnewofjas9ui32\r\n"
                  "Max-Forwards: 300\r\n"
                  "Expires: 1000000000\r\n"
                  "Contact: <sip:user@host129.example.com>;expires=280297596632815\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_SIP_MSG);
}

TEST(SipParser, ScalarCSeqOverlargeTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "REGISTER sip:example.com SIP/2.0\r\n"
                  "Via: SIP/2.0/TCP host129.example.com;branch=z9hG4bK342sdfoi3\r\n"
                  "To: <sip:user@example.com>\r\n"
                  "From: <sip:user@example.com>;tag=239232jh3\r\n"
                  "CSeq: 36893488147419103232 REGISTER\r\n"
                  "Call-ID: scalar02.23o0pd9vanlq3wnrlnewofjas9ui32\r\n"
                  "Max-Forwards: 70\r\n"
                  "Expires: 3600\r\n"
                  "Contact: <sip:user@host129.example.com>;expires=3600\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_SIP_MSG);
}

TEST(SipParser, ScalarMaxForwardsAcceptableTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "REGISTER sip:example.com SIP/2.0\r\n"
                  "Via: SIP/2.0/TCP host129.example.com;branch=z9hG4bK342sdfoi3\r\n"
                  "To: <sip:user@example.com>\r\n"
                  "From: <sip:user@example.com>;tag=239232jh3\r\n"
                  "CSeq: 1 REGISTER\r\n"
                  "Call-ID: scalar02.23o0pd9vanlq3wnrlnewofjas9ui32\r\n"
                  "Max-Forwards: 70\r\n"
                  "Expires: 3600\r\n"
                  "Contact: <sip:user@host129.example.com>;expires=3600\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    ASSERT_NE(msg->max_forwards, nullptr);
    ASSERT_STREQ(msg->max_forwards->value.toString().c_str(), "70");
}

TEST(SipParser, ScalarMaxForwardsOverlargeTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    //msg->type = SIP_REQUEST;

    char data[] = "REGISTER sip:example.com SIP/2.0\r\n"
                  "Via: SIP/2.0/TCP host129.example.com;branch=z9hG4bK342sdfoi3\r\n"
                  "To: <sip:user@example.com>\r\n"
                  "From: <sip:user@example.com>;tag=239232jh3\r\n"
                  "CSeq: 1 REGISTER\r\n"
                  "Call-ID: scalar02.23o0pd9vanlq3wnrlnewofjas9ui32\r\n"
                  "Max-Forwards: 300\r\n"
                  "Expires: 3600\r\n"
                  "Contact: <sip:user@host129.example.com>;expires=3600\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    ASSERT_STREQ(msg->max_forwards->value.toString().c_str(), "300");
}

TEST(SipParser, ScalarExpiresOverlargeTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    //msg->type = SIP_REQUEST;

    char data[] = "REGISTER sip:example.com SIP/2.0\r\n"
                  "Via: SIP/2.0/TCP host129.example.com;branch=z9hG4bK342sdfoi3\r\n"
                  "To: <sip:user@example.com>\r\n"
                  "From: <sip:user@example.com>;tag=239232jh3\r\n"
                  "CSeq: 1 REGISTER\r\n"
                  "Call-ID: scalar02.23o0pd9vanlq3wnrlnewofjas9ui32\r\n"
                  "Max-Forwards: 70\r\n"
                  "Expires: 4294967296\r\n"
                  "Contact: <sip:user@host129.example.com>;expires=3600\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    ASSERT_STREQ(msg->expires->value.toString().c_str(), "4294967296");
}

TEST(SipParser, ScalarContactExpiresOverlargeTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    char data[] = "REGISTER sip:example.com SIP/2.0\r\n"
                  "Via: SIP/2.0/TCP host129.example.com;branch=z9hG4bK342sdfoi3\r\n"
                  "To: <sip:user@example.com>\r\n"
                  "From: <sip:user@example.com>;tag=239232jh3\r\n"
                  "CSeq: 1 REGISTER\r\n"
                  "Call-ID: scalar02.23o0pd9vanlq3wnrlnewofjas9ui32\r\n"
                  "Max-Forwards: 70\r\n"
                  "Expires: 3600\r\n"
                  "Contact: <sip:user@host129.example.com>;expires=280297596632815\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), EXIT_SUCCESS);
    const sip_header* contact = msg->contacts.empty() ? nullptr : *msg->contacts.begin();
    ASSERT_NE(contact, nullptr);
    ASSERT_STREQ(contact->value.toString().c_str(),
        "<sip:user@host129.example.com>;expires=280297596632815");
}

// rfc4475 3.1.2.7
TEST(SipParser, EnclosingTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "INVITE <sip:user@example.com> SIP/2.0\r\n"
                  "To: sip:user@example.com\r\n"
                  "From: sip:caller@example.net;tag=39291\r\n"
                  "Max-Forwards: 23\r\n"
                  "Call-ID: ltgtruri.1@192.0.2.5\r\n"
                  "CSeq: 1 INVITE\r\n"
                  "Via: SIP/2.0/UDP 192.0.2.5\r\n"
                  "Contact: <sip:caller@host5.example.net>\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_FLINE);
}

// rfc4475 3.1.2.8
TEST(SipParser, EmbeddedLwsTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "INVITE sip:user@example.com; lr SIP/2.0\r\n"
                  "To: sip:user@example.com;tag=3xfe-9921883-z9f\r\n"
                  "From: sip:caller@example.net;tag=231413434\r\n"
                  "Max-Forwards: 5\r\n"
                  "Call-ID: lwsruri.asdfasdoeoi2323-asdfwrn23-asd834rk423\r\n"
                  "CSeq: 2130706432 INVITE\r\n"
                  "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKkdjuw2395\r\n"
                  "Contact: <sip:caller@host1.example.net>\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_FLINE);
}

// rfc4475 3.1.2.9
TEST(SipParser, MultipleSPTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "INVITE  sip:user@example.com  SIP/2.0\r\n"
                  "To: sip:user@example.com;tag=3xfe-9921883-z9f\r\n"
                  "From: sip:caller@example.net;tag=231413434\r\n"
                  "Max-Forwards: 5\r\n"
                  "Call-ID: lwsruri.asdfasdoeoi2323-asdfwrn23-asd834rk423\r\n"
                  "CSeq: 2130706432 INVITE\r\n"
                  "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKkdjuw2395\r\n"
                  "Contact: <sip:caller@host1.example.net>\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_FLINE);
}

// rfc4475 3.1.2.10
TEST(SipParser, SPCharactersTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    //msg->type = SIP_REQUEST;

    char data[] = "OPTIONS sip:remote-target@example.com SIP/2.0  \r\n"
                  "Via: SIP/2.0/TCP host1.example.com;branch=z9hG4bK299342093\r\n"
                  "To: <sip:remote-target@example.com>\r\n"
                  "From: <sip:local-resource@example.com>;tag=329429089\r\n"
                  "Call-ID: trws.oicu34958239neffasdhr2345r\r\n"
                  "Accept: application/sdp\r\n"
                  "CSeq: 238923 OPTIONS\r\n"
                  "Max-Forwards: 70\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_FLINE);
}

// rfc4475 3.1.2.11
TEST(SipParser, EscapedHeadersTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    //msg->type = SIP_REQUEST;

    char data[] = "INVITE sip:user@example.com?Route=%3Csip:example.com%3E SIP/2.0\r\n"
                  "Via: SIP/2.0/TCP host1.example.com;branch=z9hG4bK299342093\r\n"
                  "To: <sip:remote-target@example.com>\r\n"
                  "From: <sip:local-resource@example.com>;tag=329429089\r\n"
                  "Call-ID: trws.oicu34958239neffasdhr2345r\r\n"
                  "Accept: application/sdp\r\n"
                  "CSeq: 149209342 INVITE\r\n"
                  "Max-Forwards: 70\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), 0);
    //assert that escaped Request-URI headers are not translated to the msg headers
    for(const auto &h: msg->hdrs) {
        ASSERT_NE(h->type, sip_header::H_ROUTE);
        ASSERT_NE(h->name.toString(), "Route");
    }
}

// rfc4475 3.1.2.16
TEST(SipParser, UnknownProtocolVersionTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    //msg->type = SIP_REQUEST;

    char data[] = "OPTIONS sip:t.watson@example.org SIP/7.0\r\n"
                  "Via:     SIP/7.0/UDP c.example.com;branch=z9hG4bKkdjuw\r\n"
                  "Max-Forwards:     70\r\n"
                  "From:    A. Bell <sip:a.g.bell@example.com>;tag=qweoiqpe\r\n"
                  "To:      T. Watson <sip:t.watson@example.org>\r\n"
                  "Call-ID: badvers.31417@c.example.com\r\n"
                  "CSeq:    1 OPTIONS\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_FLINE);
}

// rfc4475 3.1.2.17-18
TEST(SipParser, MethodsMismatchTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    //msg->type = SIP_REQUEST;

    char data[] = "OPTIONS sip:user@example.com SIP/2.0\r\n"
                  "To: sip:j.user@example.com\r\n"
                  "From: sip:caller@example.net;tag=34525\r\n"
                  "Max-Forwards: 6\r\n"
                  "Call-ID: mismatch01.dj0234sxdfl3\r\n"
                  "CSeq: 8 INVITE\r\n"
                  "Via: SIP/2.0/UDP host.example.com;branch=z9hG4bKkdjuw\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_SIP_MSG);
}

// rfc4475 3.1.2.19
TEST(SipParser, OverloadResponceCodeTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    //msg->type = SIP_REQUEST;

    char data[] = "SIP/2.0 4294967301 better not break the receiver\r\n"
                  "Via: SIP/2.0/UDP 192.0.2.105;branch=z9hG4bK2398ndaoe\r\n"
                  "Call-ID: bigcode.asdof3uj203asdnf3429uasdhfas3ehjasdfas9i\r\n"
                  "CSeq: 353494 INVITE\r\n"
                  "From: <sip:user@example.com>;tag=39ansfi3\r\n"
                  "To: <sip:user@example.edu>;tag=902jndnke3\r\n"
                  "Contact: <sip:user@host105.example.com>\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_FLINE);
}

// rfc4475 3.3.1
TEST(SipParser, MissingRequiredTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;
    char data[] = "INVITE sip:user@example.com SIP/2.0\r\n"
                  "CSeq: 193942 INVITE\r\n"
                  "Via: SIP/2.0/UDP 192.0.2.95;branch=z9hG4bKkdj.insuf\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), INCOMPLETE_SIP_MSG);
}

// rfc4475 3.3.2-4
TEST(SipParser, UnknownSchemeTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;
    char data[] = "OPTIONS nobodyKnowsThisScheme:totallyopaquecontent SIP/2.0\r\n"
                  "To: sip:user@example.com\r\n"
                  "From: sip:caller@example.net;tag=384\r\n"
                  "Max-Forwards: 3\r\n"
                  "Call-ID: unkscm.nasdfasser0q239nwsdfasdkl34\r\n"
                  "CSeq: 3923423 OPTIONS\r\n"
                  "Via: SIP/2.0/TCP host9.example.com;branch=z9hG4bKkdjuw39234\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_FLINE);
}

// rfc4475 3.3.8-9
TEST(SipParser, MultipleValuesTest)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    //msg->type = SIP_REQUEST;
    char data[] = "OPTIONS sip:example.com SIP/2.0\r\n"
                  "To: sip:user@example.com\r\n"
                  "From: sip:caller@example.net;tag=384\r\n"
                  "Max-Forwards: 3\r\n"
                  "Call-ID: multi01.98asdh@192.0.2.1\r\n"
                  "CSeq: 59 OPTIONS\r\n"
                  "Call-ID: multi01.98asdh@192.0.2.2\r\n"
                  "Via: SIP/2.0/TCP host9.example.com;branch=z9hG4bKkdjuw39234\r\n"
                  "Content-Length: 0";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_sip_msg(msg.get(), err), MALFORMED_SIP_MSG);
}

TEST(HttpParser, Parsing)
{
    std::unique_ptr<sip_msg> msg(new sip_msg());
    msg->type = SIP_REQUEST;

    char data[] = "GET /?encoding=text HTTP/1.1\r\n"
                  "Connection: Upgrade\r\n"
                  "Upgrade: websocket\r\n"
                  "Sec-WebSocket-Version: 13\r\n"
                  "Sec-WebSocket-Key: y1ceknN4VFPuHj7MkaAhVQ==\r\n";
    const char* err;
    msg->copy_msg_buf(data, strlen(data));
    ASSERT_EQ(parse_http_msg(msg.get(), err), EXIT_SUCCESS);

    msg.reset(new sip_msg());
    msg->type = SIP_REQUEST;
    char data1[] = "INVITE sip:ivan@test.com HTTP/0.9\r\n\r\n";
    msg->copy_msg_buf(data1, strlen(data1));
    ASSERT_NE(parse_http_msg(msg.get(), err), EXIT_SUCCESS);

    msg.reset(new sip_msg());
    msg->type = SIP_REQUEST;
    char data2[] = "INVITE sip:ivan@test.com HTTP/0.8\r\n\r\n";
    msg->copy_msg_buf(data2, strlen(data2));
    ASSERT_NE(parse_http_msg(msg.get(), err), EXIT_SUCCESS);

    msg.reset(new sip_msg());
    msg->type = SIP_REQUEST;
    char data3[] = "GET / SIP/2.0\r\n\r\n";
    msg->copy_msg_buf(data3, strlen(data3));
    ASSERT_NE(parse_http_msg(msg.get(), err), EXIT_SUCCESS);
}

TEST(Parser, Nameaddr)
{
    sip_nameaddr sipuri;
    string uri = "\"test \\\"test\\\"\" <sip:ivan@test.com>";
    const char* url = uri.c_str();
    ASSERT_EQ(parse_nameaddr_uri(&sipuri, &url, uri.size()), EXIT_SUCCESS);
    ASSERT_EQ(strncmp(sipuri.name.s, "\"test \\\"test\\\"\"", sipuri.name.len), 0);
}

// rfc4475 3.1.1.6
TEST(Parser, WithoutSpaceTest)
{
    sip_nameaddr sipuri;
    string uri = "caller<sip:caller@example.com>;tag=323";
    const char* url = uri.c_str();
    ASSERT_EQ(parse_nameaddr_uri(&sipuri, &url, uri.size()), EXIT_SUCCESS);
    ASSERT_EQ(strncmp(sipuri.name.s, "caller", sipuri.name.len), 0);
}

// rfc4475 3.1.2.1
TEST(Parser, SeparatorTest)
{
    sip_via sipvia;
    string via = "SIP/2.0/UDP 192.0.2.15;;,;,,";
    const char* via_ = via.c_str();
    ASSERT_EQ(parse_via(&sipvia, via_, via.size()), MALFORMED_SIP_MSG);
}

// rfc4475 3.1.2.6
TEST(Parser, UnterminatedQuotedTest)
{
    sip_nameaddr p;
    string name_addr_str =
        "\"Mr J. User <sip:j.user@example.com> <sip:realj@example.net>";

    const char* s = name_addr_str.c_str();
    ASSERT_EQ(parse_nameaddr_uri(&p, &s, name_addr_str.size()), UNDEFINED_ERR);
}

// rfc4475 3.1.2.13
// be liberal on no ambiguity. parse parameter as uri_header
TEST(Parser, EscapingEncloseNameaddrTest)
{
    sip_nameaddr p;
    string name_addr_str =
        "sip:user@example.com?Route=%3Csip:sip.example.com%3E";

    const char* s = name_addr_str.c_str();
    ASSERT_EQ(parse_nameaddr_uri(&p, &s, name_addr_str.size()), 0);
    ASSERT_EQ(p.uri.hdrs.size(), 1);
    ASSERT_EQ((*p.uri.hdrs.begin())->name.toString(), "Route");
    ASSERT_EQ((*p.uri.hdrs.begin())->value.toString(), "%3Csip:sip.example.com%3E");
}

// rfc4475 3.1.2.14
TEST(Parser, SpacesAddrSpecTest)
{
    sip_nameaddr p;
    string name_addr_str =
        "\"Watson, Thomas\" < sip:t.watson@example.org >";

    const char* s = name_addr_str.c_str();
    ASSERT_EQ(parse_nameaddr_uri(&p, &s, name_addr_str.size()), UNDEFINED_ERR);
}

// rfc4475 3.1.2.15
// be liberal. accept unquoted non-token characters in the display name
TEST(Parser, NonTokenTest)
{
    sip_nameaddr p;
    string name_addr_str =
        "Bell, Alexander <sip:a.g.bell@example.com>;tag=43";

    const char* s = name_addr_str.c_str();
    ASSERT_EQ(parse_nameaddr_uri(&p, &s, name_addr_str.size()), 0);
    ASSERT_EQ(p.name.toString(), "Bell, Alexander");
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

TEST(SdpParser, SimpleTest)
{
    string sdp_str =
            "v=0\r\n"
            "o=- 3615077380 3615077398 IN IP4 192.168.0.110\r\n"
            "s=-\r\n"
            "c=IN IP4 192.168.0.110\r\n"
            "t=0 0\r\n"
            "m=audio 21964 RTP/AVP 0 101\r\n"
            "a=sendrecv\r\n"
            "a=ptime:20\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:101 telephone-event/8000\r\n"
            "a=fmtp:101 0-15";
    AmSdp sdp;
    ASSERT_EQ(sdp.parse(sdp_str.c_str()), 0);

    ASSERT_EQ(sdp.media.size(), 1);
    ASSERT_EQ(sdp.origin.sessV, 3615077398);
    ASSERT_EQ(sdp.origin.sessId, 3615077380);
    ASSERT_EQ(sdp.origin.user, "-");
    ASSERT_EQ(sdp.origin.conn.address, "192.168.0.110");
    ASSERT_EQ(sdp.origin.conn.network, NT_IN);
    ASSERT_EQ(sdp.origin.conn.addrType, AT_V4);

    ASSERT_EQ(sdp.conn.address, "192.168.0.110");
    ASSERT_EQ(sdp.conn.network, NT_IN);
    ASSERT_EQ(sdp.conn.addrType, AT_V4);

    ASSERT_EQ(sdp.media[0].type, MT_AUDIO);
    ASSERT_EQ(sdp.media[0].port, 21964);
    ASSERT_EQ(sdp.media[0].transport, TP_RTPAVP);
    ASSERT_EQ(sdp.media[0].payloads.size(), 2);
    ASSERT_EQ(sdp.media[0].payloads[0].payload_type, 0);
    ASSERT_EQ(sdp.media[0].payloads[1].payload_type, 101);
    ASSERT_EQ(sdp.media[0].payloads[0].encoding_name, "PCMU");
    ASSERT_EQ(sdp.media[0].payloads[1].encoding_name, "telephone-event");
}

TEST(SdpParser, EmptyLastLineTest)
{
    string sdp_str =
            "v=0\r\n"
            "o=- 3615077380 3615077398 IN IP4 192.168.0.110\r\n"
            "s=-\r\n"
            "c=IN IP4 192.168.0.110\r\n"
            "t=0 0\r\n"
            "m=audio 21964 RTP/AVP 0 101\r\n"
            "a=sendrecv\r\n"
            "a=ptime:20\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:101 telephone-event/8000\r\n"
            "a=fmtp:101 0-15\r\n";
    AmSdp sdp;
    ASSERT_EQ(sdp.parse(sdp_str.c_str()), 0);

    ASSERT_EQ(sdp.media.size(), 1);
    ASSERT_EQ(sdp.origin.sessV, 3615077398);
    ASSERT_EQ(sdp.origin.sessId, 3615077380);
    ASSERT_EQ(sdp.origin.user, "-");
    ASSERT_EQ(sdp.origin.conn.address, "192.168.0.110");
    ASSERT_EQ(sdp.origin.conn.network, NT_IN);
    ASSERT_EQ(sdp.origin.conn.addrType, AT_V4);

    ASSERT_EQ(sdp.conn.address, "192.168.0.110");
    ASSERT_EQ(sdp.conn.network, NT_IN);
    ASSERT_EQ(sdp.conn.addrType, AT_V4);

    ASSERT_EQ(sdp.media[0].type, MT_AUDIO);
    ASSERT_EQ(sdp.media[0].port, 21964);
    ASSERT_EQ(sdp.media[0].transport, TP_RTPAVP);
    ASSERT_EQ(sdp.media[0].payloads.size(), 2);
    ASSERT_EQ(sdp.media[0].payloads[0].payload_type, 0);
    ASSERT_EQ(sdp.media[0].payloads[1].payload_type, 101);
    ASSERT_EQ(sdp.media[0].payloads[0].encoding_name, "PCMU");
    ASSERT_EQ(sdp.media[0].payloads[1].encoding_name, "telephone-event");
}

TEST(SdpParser, SessVMaxValueTest)
{
    string sdp_str =
            "v=0\r\n"
            "o=- 18446744073709551615 18446744073709551615 IN IP4 192.168.0.110\r\n"
            "s=-\r\n"
            "c=IN IP4 192.168.0.110\r\n"
            "t=0 0\r\n";
    AmSdp sdp;
    ASSERT_EQ(sdp.parse(sdp_str.c_str()), 0);

    ASSERT_EQ(sdp.origin.sessV, 18446744073709551615UL);
    ASSERT_EQ(sdp.origin.sessId, 18446744073709551615UL);
    ASSERT_EQ(sdp.origin.user, "-");
    ASSERT_EQ(sdp.origin.conn.address, "192.168.0.110");
    ASSERT_EQ(sdp.origin.conn.network, NT_IN);
    ASSERT_EQ(sdp.origin.conn.addrType, AT_V4);

    ASSERT_EQ(sdp.conn.address, "192.168.0.110");
    ASSERT_EQ(sdp.conn.network, NT_IN);
    ASSERT_EQ(sdp.conn.addrType, AT_V4);

    string sdp_out;
    sdp.print(sdp_out);
    ASSERT_EQ(sdp_out, sdp_str);
}
