#include <gtest/gtest.h>
#include <AmUtils.h>


TEST(ParseHostPort, empty)
{
    auto ret = parse_hostport("");
    EXPECT_FALSE(ret.has_value());
}

TEST(ParseHostPort, valid_ipv4)
{
    auto ret = parse_hostport("127.0.0.1:6379");
    EXPECT_TRUE(ret.has_value());
    EXPECT_EQ(ret.value().first, "127.0.0.1");
    EXPECT_EQ(ret.value().second, 6379);
}

TEST(ParseHostPort, valid_ipv6)
{
    auto ret = parse_hostport("[::1]:6379");
    EXPECT_TRUE(ret.has_value());
    EXPECT_EQ(ret.value().first, "::1");
    EXPECT_EQ(ret.value().second, 6379);
}

TEST(ParseHostPort, valid_fqdn)
{
    auto ret = parse_hostport("domain.invalid:1234", true);
    EXPECT_TRUE(ret.has_value());
    EXPECT_EQ(ret.value().first, "domain.invalid");
    EXPECT_EQ(ret.value().second, 1234);
}

TEST(ParseHostPort, invalid_ipv6)
{
    auto ret = parse_hostport("::1:6379");
    EXPECT_FALSE(ret.has_value());
    ret = parse_hostport("fe80::1:6379");
    EXPECT_FALSE(ret.has_value());
    ret = parse_hostport("80::1:6379");
    EXPECT_FALSE(ret.has_value());
}

TEST(ParseHostPort, port_overflow)
{
    auto ret = parse_hostport("[::1]:65536");
    EXPECT_FALSE(ret.has_value());
}

TEST(ParseHostPort, no_port_ipv4)
{
    auto ret = parse_hostport("127.0.0.1");
    EXPECT_FALSE(ret.has_value());
    ret = parse_hostport("127.0.0.1:");
    EXPECT_FALSE(ret.has_value());
}

TEST(ParseHostPort, no_port_ipv6)
{
    auto ret = parse_hostport("[::1]");
    EXPECT_FALSE(ret.has_value());
    ret = parse_hostport("[::1]:");
    EXPECT_FALSE(ret.has_value());
}

TEST(ParseHostPort, wrong_port_chars)
{
    auto ret = parse_hostport("127.0.0.1:abcd");
    EXPECT_FALSE(ret.has_value());
}

TEST(ParseHostPort, invalid_ipv4_address)
{
    auto ret = parse_hostport("127.0.0.8888:1234");
    EXPECT_FALSE(ret.has_value());
}

TEST(ParseHostPort, invalid_ipv6_address)
{
    auto ret = parse_hostport("[::fffff]:1234");
    EXPECT_FALSE(ret.has_value());
}

TEST(ParseHostPort, disabled_fqdn)
{
    auto ret = parse_hostport("domain.invalid:1234");
    EXPECT_FALSE(ret.has_value());
}
