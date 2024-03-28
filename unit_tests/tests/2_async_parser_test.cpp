#include <gtest/gtest.h>
#include <sip/parse_common.h>
#include <sip/sip_parser_async.h>

static char data[] =
    "INVITE sip:1234567890@127.0.0.1:5060 SIP/2.0\r\n"
    "Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bK03a5\r\n"
    "From: \"1234567890\" <sip:1234567890@127.0.0.1:5060>;tag=gK0e11bd2b\r\n"
    "To: <sip:1234567890@127.0.0.1:5060>\r\n"
    "Call-ID: random@id\r\n"
    "CSeq: 731823 INVITE\r\n"
    "Max-Forwards: 67\r\n"
    "Allow: INVITE,ACK,CANCEL,BYE,REGISTER,REFER,INFO,SUBSCRIBE,NOTIFY,PRACK,UPDATE,OPTIONS,MESSAGE,PUBLISH\r\n"
    "Accept: application/sdp, application/isup, application/dtmf, application/dtmf-relay, multipart/mixed\r\n"
    "Content-Length:   300\r\n"
    "Content-Type: application/sdp\r\n"
    "Contact: <sip:user@127.0.0.1>\r\n"
    "\r\n"
    "v=0\r\n"
    "o=Sonus_UAC 530375 497752 IN IP4 127.0.0.1\r\n"
    "s=SIP Media Capabilities\r\n"
    "c=IN IP4 127.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 58002 RTP/AVP 0 8 18 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:18 G729/8000\r\n"
    "a=fmtp:18 annexb=no\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-15\r\n"
    "a=sendrecv\r\n"
    "a=ptime:20\r\n"
    "SIP/2.0 100 Trying\r\n"
    "Via: SIP/2.0/TCP 127.0.0.1:46910;received=127.0.0.1;branch=z9hG4bK.iA06RhlZm;rport=46910\r\n"
    "From: <sip:42@domain.invalid>;tag=5yAazpscM\r\n"
    "To: sip:42@domain.invalid\r\n"
    "CSeq: 21 INVITE\r\n"
    "Call-ID: random@id2\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

#define FULL_MSG_LEN 1095

char *end = data + sizeof(data) - 1;

char *first_msg_end = strstr(data, "SIP/2.0 100 Trying");
char *first_msg_headers_end = strstr(data, "v=0\r\n");
char *first_msg_header_partial_Accept_name = strstr(data, "ccept");
char *first_msg_header_partial_Contact_value = strstr(data, "er@127.0.0.1");
char *first_msg_sdp_aline_partial_value = strstr(data, "8 G729");

char *second_msg_start = first_msg_end;
char *second_msg_header_partial_From_value = strstr(data, ";tag=5yAazpscM");

TEST(AsyncSipParser, SingleMsg_FullBuf)
{
    parser_state st;

    st.reset(data);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_end), 0);
    ASSERT_EQ(st.c, first_msg_headers_end);
}

TEST(AsyncSipParser, SingleMsg_Headers_Sdp)
{
    parser_state st;

    st.reset(data);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_headers_end), UNEXPECTED_EOT);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_end), 0);

    ASSERT_EQ(st.c, first_msg_headers_end);
}

TEST(AsyncSipParser, SingleMsg_HeadersNoNewline_Sdp)
{
    parser_state st;

    st.reset(data);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_headers_end - 2), UNEXPECTED_EOT);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_end), 0);

    ASSERT_EQ(st.c, first_msg_headers_end);
}

TEST(AsyncSipParser, SingleMsg_HeadersAfterNewline_Sdp)
{
    parser_state st;

    st.reset(data);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_headers_end + 2), UNEXPECTED_EOT);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_end), 0);

    ASSERT_EQ(st.c, first_msg_headers_end);
}

TEST(AsyncSipParser, SingleMsg_HeadersAndSdpPartial_SdpTail)
{
    parser_state st;

    st.reset(data);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_sdp_aline_partial_value), UNEXPECTED_EOT);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_end), 0);

    ASSERT_EQ(st.c, first_msg_headers_end);
}

TEST(AsyncSipParser, SingleMsg_PartialHeadersName_PartialHeadersValue_HeadersAndSdp)
{
    parser_state st;

    st.reset(data);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_header_partial_Accept_name), UNEXPECTED_EOT);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_header_partial_Contact_value), UNEXPECTED_EOT);
    ASSERT_EQ(skip_sip_msg_async(&st, first_msg_end), 0);

    ASSERT_EQ(st.c, first_msg_headers_end);
}

TEST(AsyncSipParser, TwoMessages_FullBuf_FullBuf)
{
    parser_state st;

    st.reset(data);
    ASSERT_EQ(skip_sip_msg_async(&st, end), 0);
    ASSERT_EQ(st.c, first_msg_headers_end);

    int msg_len = st.get_msg_len();
    ASSERT_EQ(msg_len, first_msg_end - data);

    st.reset(data + msg_len);
    ASSERT_EQ(skip_sip_msg_async(&st, end), 0);

    ASSERT_EQ(st.c, end);
}

TEST(AsyncSipParser, TwoMessages_FullBuf_PartialHeaders_PartialHeaders)
{
    parser_state st;

    st.reset(data);
    ASSERT_EQ(skip_sip_msg_async(&st, end), 0);

    int msg_len = st.get_msg_len();
    ASSERT_EQ(msg_len, first_msg_end - data);

    st.reset(data + msg_len);
    ASSERT_EQ(skip_sip_msg_async(&st, second_msg_header_partial_From_value), UNEXPECTED_EOT);
    ASSERT_EQ(skip_sip_msg_async(&st, end), 0);

    ASSERT_EQ(st.c, end);
}
