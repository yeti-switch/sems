#include <gtest/gtest.h>
#include <AmShallowUriParser.h>
#include <string>

using std::string;
using std::string_view;

// parse_uri

TEST(ShallowUriParser, parse_uri_basic)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.get_uri_scheme(), sip_uri::SIP);
    ASSERT_EQ(p.get_uri_user(), "user");
    ASSERT_EQ(p.get_uri_host(), "host");
    ASSERT_EQ(p.get_uri_port(), 5060);
}

TEST(ShallowUriParser, parse_uri_full)
{
    string             input = "sip:user@host:5060;transport=tcp;lr";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.get_uri_scheme(), sip_uri::SIP);
    ASSERT_EQ(p.get_uri_user(), "user");
    ASSERT_EQ(p.get_uri_host(), "host");
    ASSERT_EQ(p.get_uri_port(), 5060);
    ASSERT_EQ(p.get_uri_params().size(), 2);
    ASSERT_EQ(p.get_uri_params().at("transport"), "tcp");
    ASSERT_TRUE(p.get_uri_params().count("lr"));
}

TEST(ShallowUriParser, parse_uri_sips_scheme)
{
    string             input = "sips:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.get_uri_scheme(), sip_uri::SIPS);
}

TEST(ShallowUriParser, parse_uri_tel_scheme)
{
    string             input = "tel:+1234567890";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.get_uri_scheme(), sip_uri::TEL);
    ASSERT_EQ(p.get_uri_user(), "+1234567890");
}

TEST(ShallowUriParser, parse_uri_ipv6_host)
{
    string             input = "sip:user@[::1]:60900";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.get_uri_user(), "user");
    ASSERT_EQ(p.get_uri_host(), "[::1]");
    ASSERT_EQ(p.get_uri_port(), 60900);
}

TEST(ShallowUriParser, parse_uri_no_user)
{
    string             input = "sip:host:5060";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.get_uri_scheme(), sip_uri::SIP);
    ASSERT_TRUE(p.get_uri_user().empty());
    ASSERT_EQ(p.get_uri_host(), "host");
    ASSERT_EQ(p.get_uri_port(), 5060);
}

TEST(ShallowUriParser, parse_uri_with_headers)
{
    string             input = "sip:user@host?Replaces=callid&To=tag";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.get_uri_user(), "user");
    ASSERT_EQ(p.get_uri_host(), "host");
    ASSERT_EQ(p.get_uri_headers().size(), 2);
    ASSERT_EQ(p.get_uri_headers().at("Replaces"), "callid");
    ASSERT_EQ(p.get_uri_headers().at("To"), "tag");
}

TEST(ShallowUriParser, parse_uri_tel_with_params)
{
    string             input = "tel:+1234567890;phone-context=example.com;lr";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.get_uri_scheme(), sip_uri::TEL);
    ASSERT_EQ(p.get_uri_user(), "+1234567890");
    ASSERT_EQ(p.get_uri_params().size(), 2);
    ASSERT_EQ(p.get_uri_params().at("phone-context"), "example.com");
    ASSERT_TRUE(p.get_uri_params().contains("lr"));
    ASSERT_TRUE(p.get_uri_params().at("lr").empty());
}

TEST(ShallowUriParser, parse_uri_unknown_scheme)
{
    string             input = "http:invalid";
    AmShallowUriParser p;
    ASSERT_FALSE(p.parse_uri(input));
}

TEST(ShallowUriParser, parse_uri_ipv6_not_closed)
{
    string             input = "sip:[::1";
    AmShallowUriParser p;
    ASSERT_FALSE(p.parse_uri(input));
}

TEST(ShallowUriParser, parse_uri_string_view_points_to_input)
{
    string             input = "sip:user@host:5060";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));

    ASSERT_GT(p.get_uri_user().data(), input.data());
    ASSERT_LT(p.get_uri_user().data() + p.get_uri_user().size(), input.data() + input.size());

    ASSERT_GT(p.get_uri_host().data(), input.data());
    ASSERT_LT(p.get_uri_host().data() + p.get_uri_host().size(), input.data() + input.size());
}

// parse_nameaddr

TEST(ShallowUriParser, parse_nameaddr_no_brackets)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    ASSERT_EQ(p.get_uri_user(), "user");
    ASSERT_EQ(p.get_uri_host(), "host");
}

TEST(ShallowUriParser, parse_nameaddr_brackets)
{
    string             input = "<sip:user@host>";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    ASSERT_EQ(p.get_uri_user(), "user");
    ASSERT_EQ(p.get_uri_host(), "host");
    ASSERT_TRUE(p.get_display_name().empty());
}

TEST(ShallowUriParser, parse_nameaddr_display_name)
{
    string             input = "\"Mr. Watson\" <sip:watson@host.com>";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    ASSERT_EQ(p.get_uri_user(), "watson");
    ASSERT_EQ(p.get_uri_host(), "host.com");
    ASSERT_EQ(p.get_display_name(), "Mr. Watson");
}

TEST(ShallowUriParser, parse_nameaddr_with_header_params)
{
    string             input = "<sip:user@host>;tag=abc;lr";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    ASSERT_EQ(p.get_uri_user(), "user");
    ASSERT_EQ(p.get_uri_host(), "host");
    ASSERT_EQ(p.get_header_params().size(), 2);
    ASSERT_EQ(p.get_header_params().at("tag"), "abc");
    ASSERT_TRUE(p.get_header_params().count("lr"));
}

TEST(ShallowUriParser, parse_nameaddr_uri_params)
{
    string             input = "<sip:user@host;transport=tcp>";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    ASSERT_EQ(p.get_uri_user(), "user");
    ASSERT_EQ(p.get_uri_host(), "host");
    ASSERT_EQ(p.get_uri_params().at("transport"), "tcp");
}

TEST(ShallowUriParser, parse_nameaddr_ipv6)
{
    string             input = "<sip:user@[::1]:60900>";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    ASSERT_EQ(p.get_uri_user(), "user");
    ASSERT_EQ(p.get_uri_host(), "[::1]");
    ASSERT_EQ(p.get_uri_port(), 60900);
}

TEST(ShallowUriParser, parse_nameaddr_full)
{
    string input = "\"Alice\" <sip:alice@atlanta.com:5060;w=0.2;transport=tcp?Replaces=3v8hvc3j>;tag=123;q=0.5";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));

    ASSERT_EQ(p.get_display_name(), "Alice");
    ASSERT_EQ(p.get_uri_scheme(), sip_uri::SIP);
    ASSERT_EQ(p.get_uri_user(), "alice");
    ASSERT_EQ(p.get_uri_host(), "atlanta.com");
    ASSERT_EQ(p.get_uri_port(), 5060);

    ASSERT_EQ(p.get_uri_params().size(), 2);
    ASSERT_EQ(p.get_uri_params().at("transport"), "tcp");
    ASSERT_EQ(p.get_uri_params().at("w"), "0.2");

    ASSERT_EQ(p.get_uri_headers().size(), 1);
    ASSERT_EQ(p.get_uri_headers().at("Replaces"), "3v8hvc3j");

    ASSERT_EQ(p.get_header_params().at("tag"), "123");
    ASSERT_EQ(p.get_header_params().at("q"), "0.5");
}

// uri_str

TEST(ShallowUriParser, canon_uri_str_basic)
{
    string             input = "sip:user@host:5060;transport=tcp";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.canon_uri_str(), "sip:user@host");
}

TEST(ShallowUriParser, canon_uri_str_no_user)
{
    string             input = "sip:host:5060";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.canon_uri_str(), "sip:host");
}

TEST(ShallowUriParser, canon_uri_str_sips)
{
    string             input = "sips:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.canon_uri_str(), "sips:user@host");
}

TEST(ShallowUriParser, canon_uri_str_tel)
{
    string             input = "tel:42";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.canon_uri_str(), "tel:42");
}

TEST(ShallowUriParser, uri_str_with_params)
{
    string             input = "sip:user@host:5060;transport=tcp;lr";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    string result = p.uri_str();
    ASSERT_EQ(result, "sip:user@host;lr;transport=tcp");
}

TEST(ShallowUriParser, uri_str_with_headers)
{
    string             input = "sip:user@host?Replaces=callid&To=tag";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    string result = p.uri_str();
    ASSERT_TRUE(result.find("sip:user@host") == 0);
    ASSERT_NE(result.find("Replaces=callid"), string::npos);
    ASSERT_NE(result.find("To=tag"), string::npos);
}

// nameaddr_str

TEST(ShallowUriParser, nameaddr_str_basic)
{
    string             input = "<sip:user@host>";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    ASSERT_EQ(p.nameaddr_str(), "<sip:user@host>");
}

TEST(ShallowUriParser, nameaddr_str_display_name)
{
    string             input = "\"Alice\" <sip:alice@atlanta.com>";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    ASSERT_EQ(p.nameaddr_str(), "\"Alice\" <sip:alice@atlanta.com>");
}

TEST(ShallowUriParser, nameaddr_str_with_header_params)
{
    string             input = "<sip:user@host>;tag=abc";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    ASSERT_EQ(p.nameaddr_str(), "<sip:user@host>;tag=abc");
}

TEST(ShallowUriParser, nameaddr_str_full)
{
    string             input = "\"Alice\" <sip:alice@atlanta.com:5060?Replaces=v3f773h;transport=tcp>;tag=123;q=0.5";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    string result = p.nameaddr_str();
    ASSERT_EQ(result, "\"Alice\" <sip:alice@atlanta.com?Replaces=v3f773h;transport=tcp>;q=0.5;tag=123");
}

// mutation tests

TEST(ShallowUriParser, set_uri_host)
{
    string             input = "sip:user@host:5060";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    p.set_uri_host("newhost.com");
    ASSERT_EQ(p.get_uri_host(), "newhost.com");
    ASSERT_EQ(p.canon_uri_str(), "sip:user@newhost.com");
}

TEST(ShallowUriParser, set_uri_user)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    p.set_uri_user("alice");
    ASSERT_EQ(p.get_uri_user(), "alice");
    ASSERT_EQ(p.canon_uri_str(), "sip:alice@host");
}

TEST(ShallowUriParser, set_uri_port)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    p.set_uri_port(5080);
    ASSERT_EQ(p.canon_uri_str(), "sip:user@host:5080");
}

TEST(ShallowUriParser, set_uri_scheme)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    p.set_uri_scheme(sip_uri::SIPS);
    ASSERT_EQ(p.canon_uri_str(), "sips:user@host");
}

TEST(ShallowUriParser, set_uri_scheme_by_name)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    p.set_uri_scheme_by_name("sips");
    ASSERT_EQ(p.canon_uri_str(), "sips:user@host");
}


TEST(ShallowUriParser, set_display_name)
{
    string             input = "<sip:user@host>";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    p.set_display_name("Bob");
    ASSERT_EQ(p.nameaddr_str(), "\"Bob\" <sip:user@host>");
}

TEST(ShallowUriParser, set_uri_param_add_new)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    p.set_uri_param("transport", "tcp");
    ASSERT_EQ(p.get_uri_params().size(), 1);
    ASSERT_EQ(p.uri_str(), "sip:user@host;transport=tcp");
}

TEST(ShallowUriParser, set_uri_param_overwrite)
{
    string             input = "sip:user@host;transport=udp";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.get_uri_params().at("transport"), "udp");
    p.set_uri_param("transport", "tcp");
    ASSERT_EQ(p.get_uri_params().size(), 1);
    ASSERT_EQ(p.uri_str(), "sip:user@host;transport=tcp");
}

TEST(ShallowUriParser, set_uri_param_flag)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    p.set_uri_param("lr");
    ASSERT_EQ(p.get_uri_params().size(), 1);
    ASSERT_EQ(p.uri_str(), "sip:user@host;lr");
}

TEST(ShallowUriParser, erase_uri_param)
{
    string             input = "sip:user@host;transport=tcp;lr";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_EQ(p.get_uri_params().size(), 2);
    p.erase_uri_param("transport");
    ASSERT_EQ(p.get_uri_params().size(), 1);
    ASSERT_EQ(p.uri_str(), "sip:user@host;lr");
}

TEST(ShallowUriParser, erase_uri_param_nonexistent)
{
    string             input = "sip:user@host;lr";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    p.erase_uri_param("transport");
    ASSERT_EQ(p.get_uri_params().size(), 1);
}

TEST(ShallowUriParser, set_uri_header_add)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    p.set_uri_header("Replaces", "callid");
    ASSERT_EQ(p.uri_str(), "sip:user@host?Replaces=callid");
}

TEST(ShallowUriParser, erase_uri_header)
{
    string             input = "sip:user@host?Replaces=callid&To=tag";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    p.erase_uri_header("Replaces");
    ASSERT_EQ(p.get_uri_headers().size(), 1);
    ASSERT_EQ(p.uri_str(), "sip:user@host?To=tag");
}

TEST(ShallowUriParser, set_header_param_add)
{
    string             input = "<sip:user@host>";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    p.set_header_param("tag", "xyz");
    ASSERT_EQ(p.nameaddr_str(), "<sip:user@host>;tag=xyz");
}

TEST(ShallowUriParser, set_header_param_overwrite)
{
    string             input = "<sip:user@host>;tag=old";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    p.set_header_param("tag", "new");
    ASSERT_EQ(p.nameaddr_str(), "<sip:user@host>;tag=new");
}

TEST(ShallowUriParser, erase_header_param)
{
    string             input = "<sip:user@host>;tag=abc;lr";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_nameaddr(input));
    p.erase_header_param("tag");
    ASSERT_EQ(p.get_header_params().size(), 1);
    ASSERT_EQ(p.nameaddr_str(), "<sip:user@host>;lr");
}

TEST(ShallowUriParser, mutation_survives_input_destruction)
{
    AmShallowUriParser p;
    {
        string input = "sip:user@host";
        ASSERT_TRUE(p.parse_uri(input));
        // mutate all fields so they point into storage_, not input
        p.set_uri_scheme(sip_uri::SIPS);
        p.set_uri_user("alice");
        p.set_uri_host("example.com");
        p.set_uri_port(5061);
        p.set_uri_param("transport", "tls");
    }
    // input is destroyed; owned storage must still be valid
    ASSERT_EQ(p.get_uri_scheme(), sip_uri::SIPS);
    ASSERT_EQ(p.get_uri_user(), "alice");
    ASSERT_EQ(p.get_uri_host(), "example.com");
    ASSERT_EQ(p.get_uri_port(), 5061);
    ASSERT_EQ(p.canon_uri_str(), "sips:alice@example.com:5061");
}

TEST(ShallowUriParser, multiple_mutations_same_field)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    p.set_uri_host("first.com");
    p.set_uri_host("second.com");
    p.set_uri_host("third.com");
    ASSERT_EQ(p.get_uri_host(), "third.com");
    ASSERT_EQ(p.canon_uri_str(), "sip:user@third.com");
}

TEST(ShallowUriParser, shallow_mutators)
{
    AmShallowUriParser p;
    string_view name{ "Test" }, user{ "user" }, host{ "example.com" }, up1{ "up1" }, upv1{ "upv1" }, uh1{ "uh1" },
        uhv1{ "uhv1" }, h1{ "h1" }, hv1{ "hv1" };

    p.set_display_name_shallow(name);
    p.set_uri_scheme(sip_uri::SIP);
    p.set_uri_user_shallow(user);
    p.set_uri_host_shallow(host);
    p.set_uri_param_shallow(up1, upv1);
    p.set_uri_header_shallow(uh1, uhv1);
    p.set_header_param_shallow(h1, hv1);

    ASSERT_EQ(p.nameaddr_str(), "\"Test\" <sip:user@example.com;up1=upv1?uh1=uhv1>;h1=hv1");

    ASSERT_EQ(p.get_display_name().data(), name.data());
    ASSERT_EQ(p.get_uri_user().data(), user.data());
    ASSERT_EQ(p.get_uri_host().data(), host.data());

    ASSERT_EQ(p.get_uri_params().find(up1)->first.data(), up1.data());
    ASSERT_EQ(p.get_uri_params().at(up1).data(), upv1.data());

    ASSERT_EQ(p.get_uri_headers().find(uh1)->first.data(), uh1.data());
    ASSERT_EQ(p.get_uri_headers().at(uh1).data(), uhv1.data());

    ASSERT_EQ(p.get_header_params().find(h1)->first.data(), h1.data());
    ASSERT_EQ(p.get_header_params().at(h1).data(), hv1.data());

    // ensure we do not overwrite map key storage on rewrites
    p.set_uri_param_shallow("up1", "upv2");
    ASSERT_EQ(p.get_uri_params().find(up1)->first.data(), up1.data());
}

TEST(ShallowUriParser, convert_to_deep_copy)
{
    AmShallowUriParser p;
    {
        string input = "sip:user@host";
        ASSERT_TRUE(p.parse_uri(input));
        p.convert_to_deep_copy();
    }
    string result = p.uri_str();
}

// patch_uri_transport

TEST(ShallowUriParser, patch_uri_transport_param_udp)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_TRUE(p.patch_uri_transport_param(sip_transport::UDP));
    ASSERT_EQ(p.uri_str(), input);
}

TEST(ShallowUriParser, patch_uri_transport_param_udp_overwrite)
{
    string             input = "sip:user@host;transport=tcp";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_TRUE(p.patch_uri_transport_param(sip_transport::UDP, true));
    ASSERT_EQ(p.uri_str(), "sip:user@host");
}

TEST(ShallowUriParser, patch_uri_transport_param_tls)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_TRUE(p.patch_uri_transport_param(sip_transport::TLS));
    ASSERT_EQ(p.uri_str(), "sip:user@host;transport=tls");
}

TEST(ShallowUriParser, patch_uri_transport_param_existent_param)
{
    string             input = "sip:user@host;transport=tcp";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_FALSE(p.patch_uri_transport_param(sip_transport::TLS));
    ASSERT_EQ(p.uri_str(), input);
}

TEST(ShallowUriParser, patch_uri_transport_param_existent_param_overwrite)
{
    string             input = "sip:user@host;transport=tcp";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_TRUE(p.patch_uri_transport_param(sip_transport::TLS, true));
    ASSERT_EQ(p.uri_str(), "sip:user@host;transport=tls");
}

TEST(ShallowUriParser, patch_uri_transport_param_wrong_transport_id)
{
    string             input = "sip:user@host";
    AmShallowUriParser p;
    ASSERT_TRUE(p.parse_uri(input));
    ASSERT_TRUE(p.patch_uri_transport_param(sip_transport::OTHER));
    ASSERT_EQ(p.uri_str(), "sip:user@host");
}
