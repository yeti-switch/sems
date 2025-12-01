#include <gtest/gtest.h>
#include <AmUriParser.h>
#include <AmUtils.h>

TEST(UriParser, angle)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("<sip:u@d>", 0, end));
    ASSERT_TRUE(p.uri_user == "u");
    ASSERT_TRUE(p.uri_host == "d");
};

TEST(UriParser, ip6)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("<sip:u@[2a01:ad00:2:1::19]:60900>", 0, end));
    ASSERT_TRUE(p.uri_user == "u");
    ASSERT_TRUE(p.uri_host == "[2a01:ad00:2:1::19]");
    ASSERT_TRUE(p.uri_port == "60900");
};

TEST(UriParser, angle_param)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("<sip:u@d>;tag=123", 0, end));
    ASSERT_TRUE(p.uri_user == "u");
    ASSERT_TRUE(p.uri_host == "d");
    ASSERT_TRUE(p.params["tag"] == "123");
};

TEST(UriParser, uri_param)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("<sip:u@d;tag=123>", 0, end));
    ASSERT_TRUE(p.uri_user == "u");
    ASSERT_TRUE(p.uri_host == "d");
    ASSERT_TRUE(p.uri_param == "tag=123");
};

TEST(UriParser, params_nobracket)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("sip:u@d;tag=123", 0, end));
    ASSERT_TRUE(p.uri_user == "u");
    ASSERT_TRUE(p.uri_host == "d");
    ASSERT_TRUE(p.params["tag"] == "123");
};

TEST(UriParser, params_dname)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("hu <sip:u@d;tag=123>", 0, end));
    ASSERT_TRUE(p.display_name == "hu");
    ASSERT_TRUE(p.uri_user == "u");
    ASSERT_TRUE(p.uri_host == "d");
};

TEST(UriParser, params_dname2)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("  hu bar <sip:u@d;tag=123>", 0, end));
    ASSERT_TRUE(p.display_name == "hu bar");
    ASSERT_TRUE(p.uri_user == "u");
    ASSERT_TRUE(p.uri_host == "d");
};

TEST(UriParser, params_dname3)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("  \"hu bar\" <sip:u@d;tag=123>", 0, end));
    ASSERT_TRUE(p.display_name == "hu bar");
    ASSERT_TRUE(p.uri_user == "u");
    ASSERT_TRUE(p.uri_host == "d");
};

TEST(UriParser, params_dname4)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("  \"hu bar\\\\ \" <sip:u@d;tag=123>", 0, end));
    ASSERT_TRUE(p.display_name == "hu bar\\\\ ");
    ASSERT_TRUE(p.uri_user == "u");
    ASSERT_TRUE(p.uri_host == "d");
};

TEST(UriParser, params_dname5)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("\"Mr. Watson\" <mailto:watson@bell-telephone.com> ;q=0.1", 0, end));
    ASSERT_TRUE(p.display_name == "Mr. Watson");
    ASSERT_TRUE(p.uri_user == "watson");
    ASSERT_TRUE(p.uri_host == "bell-telephone.com");
};

TEST(UriParser, headers)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact(
        "\"Mr. Watson\" "
        "<mailto:watson@bell-telephone.com?Replaces:%20lkancskjd%3Bto-tag=3123141ab%3Bfrom-tag=kjhkjcsd> ;q=0.1",
        0, end));
    ASSERT_TRUE(p.display_name == "Mr. Watson");
    ASSERT_TRUE(p.uri_user == "watson");
    ASSERT_TRUE(p.uri_host == "bell-telephone.com");
    ASSERT_TRUE(p.uri_headers == "Replaces:\%20lkancskjd%3Bto-tag=3123141ab%3Bfrom-tag=kjhkjcsd");
};

TEST(UriParser, headers_str)
{
    AmUriParser p;
    string      orig_str =
        "\"Mr. Watson\" "
        "<sip:watson@bell-telephone.com?Replaces:%20lkancskjd%3Bto-tag=3123141ab%3Bfrom-tag=kjhkjcsd>;q=0.1";
    ASSERT_TRUE(p.parse_nameaddr(orig_str));
    ASSERT_TRUE(p.display_name == "Mr. Watson");
    ASSERT_TRUE(p.uri_user == "watson");
    ASSERT_TRUE(p.uri_host == "bell-telephone.com");
    ASSERT_TRUE(p.uri_headers == "Replaces:\%20lkancskjd%3Bto-tag=3123141ab%3Bfrom-tag=kjhkjcsd");
    string a_str = p.nameaddr_str();
    ASSERT_TRUE(orig_str == a_str);
};

TEST(UriParser, url_escape)
{
    string src = "Replaces: CSADFSD;from-tag=31241231abc;to-tag=235123";
    string dst = "Replaces%3A%20CSADFSD%3Bfrom-tag%3D31241231abc%3Bto-tag%3D235123";
    ASSERT_TRUE(URL_decode(dst) == src);
    ASSERT_TRUE(URL_encode(src) == dst);
    ASSERT_TRUE(URL_decode(URL_encode(src)) == src);
};

TEST(UriParser, params_dname6)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("<sip:alice@atlanta.com>;q=\"0.1\";param", 0, end));
    ASSERT_TRUE(p.params.size() == 2);
};

TEST(UriParser, params_dname7)
{
    AmUriParser p;
    size_t      end;
    ASSERT_TRUE(p.parse_contact("<sip:alice@atlanta.com>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi."
                                "mmtel\";video;mobility=\"mobile\"",
                                0, end));
    ASSERT_TRUE(p.params.size() == 3);
};
