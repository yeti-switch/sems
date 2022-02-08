#include <gtest/gtest.h>
#include <sip/resolver.h>
#include <sip/ip_util.h>
#include <sip/socket_ssl.h>

TEST(Resolver, SipTargetResolve)
{
    sip_target t;
    sockaddr_ssl &sa_ssl = *reinterpret_cast<sockaddr_ssl*>(&t.ss);

    //IPv4
    t.ss.ss_family = AF_INET;
    SAv4(&t.ss)->sin_addr.s_addr = INADDR_ANY;

    t.resolve("udp",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("tcp",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::tcp_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("tls",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::tls_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, true);

    t.resolve("ws",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::ws_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("wss",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::wss_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, true);

    //failover for wrong transport
    t.resolve("qwe",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    //IPv6
    t.ss.ss_family = AF_INET6;
    SAv6(&t.ss)->sin6_addr = IN6ADDR_ANY_INIT;

    t.resolve("udp",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("tcp",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::tcp_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("tls",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::tls_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, true);

    t.resolve("ws",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::ws_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("wss",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::wss_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, true);

    //sips scheme
    t.resolve("tcp",true);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::tcp_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, true);

    //failover for wrong transport
    t.resolve("qwe",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    //test sip_target::resolve failed branches for transport
    t.resolve("u",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("udQ",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("tqw",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("tcq",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("tlq",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("wq",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("wsq",false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
}
