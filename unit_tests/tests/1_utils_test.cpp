#include <gtest/gtest.h>
#include <AmUtils.h>

TEST(Utils, escape_dquoted_basic)
{
    auto escaped = escape_dquoted("\"head\"\r\ntail\\");
    ASSERT_EQ(escaped, R"-(\"head\"  tail\\)-");
}

TEST(Utils, escape_dquoted_already_escaped)
{
    // it's expected to double-escape for now. we assume that input is not escaped
    auto escaped = escape_dquoted(R"-(\"-\\)-");
    ASSERT_EQ(escaped, R"-(\\\"-\\\\)-");
}
