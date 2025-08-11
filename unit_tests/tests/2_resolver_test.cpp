#include <gtest/gtest.h>
#include <sip/resolver.h>
#include <sip/ip_util.h>
#include <sip/socket_ssl.h>
#include "dns_dump.h"

TEST(Resolver, SipTargetResolve)
{
    sip_target    t;
    sockaddr_ssl &sa_ssl = *reinterpret_cast<sockaddr_ssl *>(&t.ss);

    // IPv4
    t.ss.ss_family               = AF_INET;
    SAv4(&t.ss)->sin_addr.s_addr = INADDR_ANY;

    t.resolve("udp", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("tcp", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::tcp_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("tls", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::tls_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, true);

    t.resolve("ws", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::ws_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("wss", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::wss_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, true);

    // failover for wrong transport
    t.resolve("qwe", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv4);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    // IPv6
    t.ss.ss_family         = AF_INET6;
    SAv6(&t.ss)->sin6_addr = IN6ADDR_ANY_INIT;

    t.resolve("udp", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("tcp", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::tcp_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("tls", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::tls_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, true);

    t.resolve("ws", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::ws_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    t.resolve("wss", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::wss_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, true);

    // sips scheme
    t.resolve("tcp", true);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::tcp_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, true);

    // failover for wrong transport
    t.resolve("qwe", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    GTEST_ASSERT_EQ(sa_ssl.ssl_marker, false);

    // test sip_target::resolve failed branches for transport
    t.resolve("u", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("udQ", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("tqw", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("tcq", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("tlq", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("wq", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
    t.resolve("wsq", false);
    GTEST_ASSERT_EQ(t.trsp, trsp_socket::udp_ipv6);
}


using TestNSResolverFDataType = std::tuple<string, dns_priority, string>;


static string addr2str(sockaddr_storage *addr)
{
    char ntop_buffer[INET6_ADDRSTRLEN];

    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        if (!inet_ntop(AF_INET, &sin->sin_addr, ntop_buffer, INET6_ADDRSTRLEN)) {
            ERROR("Could not convert IPv4 address to string: %s", strerror(errno));
            return "unknown";
        }
        return string(ntop_buffer);
    }

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
    if (!inet_ntop(AF_INET6, &sin6->sin6_addr, ntop_buffer, INET6_ADDRSTRLEN)) {
        ERROR("Could not convert IPv6 address to string: %s", strerror(errno));
        return "unknown";
    }

    return string(ntop_buffer);
}


class ResolverF : public testing::TestWithParam<TestNSResolverFDataType> {
  protected:
    string       host, expected_result;
    dns_priority priority;

    void SetUp() override
    {
        mock_res_search = dns_dump_res_search;
        resolver::instance()->clear_cache();
        const auto &param = GetParam();
        host              = std::get<0>(param);
        priority          = std::get<1>(param);
        expected_result   = std::get<2>(param);
    }
    void TearDown() override { mock_res_search = nullptr; }
};

TEST_P(ResolverF, resolve_name)
{
    sockaddr_storage sa;
    dns_handle       dh;
    dns_rr_type      rr_type = host[0] == '_' ? dns_r_srv : dns_r_ip;

    GTEST_ASSERT_EQ(resolver::instance()->resolve_name(host.c_str(), &dh, &sa, priority, rr_type), 1)
        << "resolve_name('" << host << "') " << priority << " failed";

    string result = addr2str(&sa);

    GTEST_ASSERT_EQ(expected_result, result) << "resolve_name('" << host << "') " << priority << " failed,\n"
                                             << "expected " << expected_result << ", got " << result;
}

/** Testing cases:
 *  recursive SRV resolving when SRV entry is FQDN
 *  resolving to A, AAAA with zero TTL
 *  filtering/ordering by the priority */

INSTANTIATE_TEST_SUITE_P(NS, ResolverF,
                         testing::Values(std::make_tuple("_sip._udp.test.invalid", IPv4_only, "42.42.42.42"),
                                         std::make_tuple("_sip._udp.test.invalid", IPv6_only, "::1"),
                                         std::make_tuple("test.invalid.", IPv4_only, "42.42.42.42"),
                                         std::make_tuple("test.invalid.", IPv6_only, "::1"),
                                         std::make_tuple("test.invalid.", Dualstack, "42.42.42.42"),
                                         std::make_tuple("test.invalid.", IPv4_pref, "42.42.42.42"),
                                         std::make_tuple("test.invalid.", IPv6_pref, "::1")));
