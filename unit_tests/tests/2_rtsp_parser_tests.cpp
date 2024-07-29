#include <gtest/gtest.h>
#include <RtspConnection.h>

TEST(RtspParser, IncorrectMessage)
{
    static char data[] =
        "RTSP/1.0 455 Method Not Valid In This State\r\n"
        "CSeq: 197\r\n"
        "Session:\r\n"
        "\0006905240\r\n"
        "\r\n";

    Rtsp::RtspMsg st(Rtsp::RTSP_REPLY, data);
    ASSERT_EQ(st.type, Rtsp::RTSP_REPLY);
    ASSERT_EQ(st.reason, "Method Not Valid In This State");
    ASSERT_EQ(st.code, 455);
    ASSERT_EQ(st.cseq, 197);
    ASSERT_EQ(st.version, "RTSP/1.0");
    ASSERT_TRUE(st.session_id.empty());
}
