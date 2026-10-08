#include <gtest/gtest.h>
#include <AmSipMsg.h>
#include <sip/parse_header.h>

TEST(SipHeaders, getHeader_single)
{
    AmSipHeaderMap hdrs{
        { "Supported", "100rel" },
        { "Supported",  "timer" },
        {     "Allow", "INVITE" }
    };
    ASSERT_EQ(getHeader(hdrs, "supported", true), "100rel");
    ASSERT_EQ(getHeader(hdrs, "Allow", true), "INVITE");
    ASSERT_EQ(getHeader(hdrs, "Require", true), "");
}

TEST(SipHeaders, getHeader_multi)
{
    AmSipHeaderMap hdrs{
        { "Supported", "100rel" },
        { "Supported",  "timer" },
        {     "Allow", "INVITE" }
    };
    ASSERT_EQ(getHeader(hdrs, "SUPPORTED"), "100rel, timer");
    ASSERT_EQ(getHeader(hdrs, "Allow"), "INVITE");
    ASSERT_EQ(getHeader(hdrs, "Require"), "");
}

TEST(SipHeaders, hasHeader)
{
    AmSipHeaderMap hdrs{
        { "Supported", "100rel" }
    };
    ASSERT_TRUE(hasHeader(hdrs, "supported"));
    ASSERT_FALSE(hasHeader(hdrs, "Require"));
}

TEST(SipHeaders, removeHeader)
{
    AmSipHeaderMap hdrs{
        { "Supported", "100rel" },
        { "Supported",  "timer" },
        {     "Allow", "INVITE" }
    };
    ASSERT_TRUE(removeHeader(hdrs, "supported"));
    ASSERT_FALSE(hasHeader(hdrs, "Supported"));
    ASSERT_EQ(hdrs.size(), 1);
    ASSERT_FALSE(removeHeader(hdrs, "Supported"));
    ASSERT_EQ(hdrs.size(), 1);
}

TEST(SipHeaders, addOptionTag_new_header)
{
    AmSipHeaderMap hdrs;
    addOptionTag(hdrs, "Supported", "timer");
    ASSERT_EQ(hdrs.size(), 1);
    ASSERT_EQ(getHeader(hdrs, "Supported"), "timer");
}

TEST(SipHeaders, addOptionTag_no_duplicate)
{
    AmSipHeaderMap hdrs{
        { "Supported", "100rel, timer" }
    };
    addOptionTag(hdrs, "Supported", "timer");
    ASSERT_EQ(hdrs.size(), 1);
    ASSERT_EQ(getHeader(hdrs, "Supported"), "100rel, timer");
}

TEST(SipHeaders, addOptionTag_joins_same_name)
{
    AmSipHeaderMap hdrs{
        { "Supported", "100rel" },
        { "Supported",  "timer" },
        {     "Allow", "INVITE" }
    };
    addOptionTag(hdrs, "Supported", "replaces");
    ASSERT_EQ(hdrs.count("Supported"), 1);
    ASSERT_EQ(getHeader(hdrs, "Supported"), "replaces, 100rel, timer");
    ASSERT_EQ(getHeader(hdrs, "Allow"), "INVITE");
}

TEST(SipHeaders, addOptionTags_keeps_vector_order)
{
    AmSipHeaderMap hdrs;
    addOptionTags(hdrs, "Supported", { "100rel", "timer", "replaces" });
    ASSERT_EQ(hdrs.count("Supported"), 1);
    ASSERT_EQ(getHeader(hdrs, "Supported"), "100rel, timer, replaces");
}

TEST(SipHeaders, removeOptionTag_middle)
{
    AmSipHeaderMap hdrs{
        { "Supported", "100rel, timer, replaces" }
    };
    removeOptionTag(hdrs, "Supported", "timer");
    ASSERT_EQ(getHeader(hdrs, "Supported"), "100rel, replaces");
}

TEST(SipHeaders, removeOptionTag_joins_same_name)
{
    AmSipHeaderMap hdrs{
        { "Supported",   "100rel" },
        { "Supported",    "timer" },
        { "Supported", "replaces" }
    };
    removeOptionTag(hdrs, "Supported", "timer");
    ASSERT_EQ(hdrs.count("Supported"), 1);
    ASSERT_EQ(getHeader(hdrs, "Supported"), "100rel, replaces");
}

TEST(SipHeaders, removeOptionTag_last_tag_removes_header)
{
    AmSipHeaderMap hdrs{
        { "Supported",  "timer" },
        {     "Allow", "INVITE" }
    };
    removeOptionTag(hdrs, "Supported", "timer");
    ASSERT_FALSE(hasHeader(hdrs, "Supported"));
    ASSERT_EQ(hdrs.size(), 1);
}

TEST(SipHeaders, addHeader_expands_compact_name)
{
    AmSipHeaderMap hdrs;
    addHeader(hdrs, sip_header(sip_header::H_OTHER, cstring("k"), cstring("100rel")));
    addHeader(hdrs, sip_header(sip_header::H_OTHER, cstring("X"), cstring("1800")));
    ASSERT_EQ(getHeader(hdrs, "Supported"), "100rel");
    ASSERT_EQ(getHeader(hdrs, "Session-Expires"), "1800");
    ASSERT_FALSE(hasHeader(hdrs, "k"));
}

TEST(SipHeaders, addHeader_folds_line_breaks)
{
    AmSipHeaderMap hdrs;
    addHeader(hdrs, sip_header(sip_header::H_OTHER, cstring("Subject"),
                               cstring("I know you're there,\r\n\t  pick up\n the phone")));
    ASSERT_EQ(getHeader(hdrs, "Subject"), "I know you're there, pick up the phone");
}

TEST(SipHeaders, parseHeadersString)
{
    AmSipHeaderMap hdrs;
    ASSERT_TRUE(parseHeadersString("Supported: 100rel\r\nk: timer\r\nX-Empty:\r\nAllow: INVITE", hdrs));
    ASSERT_EQ(getHeader(hdrs, "Supported"), "100rel, timer");
    ASSERT_EQ(getHeader(hdrs, "Allow"), "INVITE");
    ASSERT_FALSE(hasHeader(hdrs, "X-Empty"));
    ASSERT_EQ(hdrs.size(), 3);

    ASSERT_TRUE(parseHeadersString("", hdrs));
    ASSERT_EQ(hdrs.size(), 3);

    ASSERT_FALSE(parseHeadersString("no colon here", hdrs));
    ASSERT_EQ(hdrs.size(), 3);
}
