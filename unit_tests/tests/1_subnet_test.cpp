#include <gtest/gtest.h>
#include <AmSubnet.h>
#include <arpa/inet.h>
#include <sip/ip_util.h>

TEST(Common, SubnetTask)
{
    AmSubnet subnet;
    std::string a("fe80::5632:aa5e:45ff:fea7:cbf6/64");
    subnet.parse(a);
    sockaddr_storage at, af;
    am_inet_pton("fe80::5632:aa5e:45ff:fea7:cbf6", &at);
    am_inet_pton("fe80::5532:aa5e:45ff:fea7:cbf6", &af);
    EXPECT_TRUE(subnet.contains(at));
    EXPECT_FALSE(subnet.contains(af));
    std::string b("fe80::5632:aa5e:45ff:fea7:cbf6/128");
    subnet.parse(b);
    am_inet_pton("fe80::5632:aa5e:45ff:fea7:cbf6", &at);
    EXPECT_TRUE(subnet.contains(at));
    EXPECT_FALSE(subnet.contains(af));
    std::string c("fe80::5632:aa5e:45ff:fea7:cbf6/96");
    subnet.parse(c);
    am_inet_pton("fe80::5632:aa5e:45ff:fda7:cbf6", &at);
    am_inet_pton("fe80::5632:aa5e:45ef:fea7:cbf6", &af);
    EXPECT_TRUE(subnet.contains(at));
    EXPECT_FALSE(subnet.contains(af));
    std::string d("fe80:652d:3254:5632:aa5e:45ff:fea7:cbf6/32");
    subnet.parse(d);
    am_inet_pton("fe80:652d:3254:5732:aa5e:45ff:f4a7:cbf6", &at);
    am_inet_pton("fe80:653d:3254:5632:aa5e:45ff:fea7:cbf6", &af);
    EXPECT_TRUE(subnet.contains(at));
    EXPECT_FALSE(subnet.contains(af));
}
