#include "IdentityValidatorTests.h"
#include "../IdentityValidator.h"
#include <botan/data_src.h>

string cert_with_TNAuthList = "-----BEGIN CERTIFICATE-----\
MIIDBDCCAqqgAwIBAgIUYTCTlxQtIe18LLsPvlgefvARxdswCgYIKoZIzj0EAwIw\
gYUxCzAJBgNVBAYTAlVTMSkwJwYDVQQKDCBOZXVzdGFyIEluZm9ybWF0aW9uIFNl\
cnZpY2VzIEluYzEZMBcGA1UECwwQd3d3LmNjaWQubmV1c3RhcjEwMC4GA1UEAwwn\
TmV1c3RhciBDZXJ0aWZpZWQgQ2FsbGVyIElEIFNIQUtFTiBDQS0yMB4XDTIyMTIw\
NjE5NDM0M1oXDTIzMTIwNjE5NDM0M1owPjELMAkGA1UEBhMCVVMxGTAXBgNVBAoM\
EFBlZXJsZXNzIE5ldHdvcmsxFDASBgNVBAMMC1NIQUtFTiAwNjNFMFkwEwYHKoZI\
zj0CAQYIKoZIzj0DAQcDQgAEbjJCYP8dmbmYa06ZXwJZn9faG+F+Ir7OfS0dDCn0\
TErI+GpFqsuDlBguI0EWxo/Maijcmn8ePguOrQBPSdFybqOCATwwggE4MBYGCCsG\
AQUFBwEaBAowCKAGFgQwNjNFMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgk4V\
//6famdR5MiXx210w/xlRXgwFwYDVR0gBBAwDjAMBgpghkgBhv8JAQEDMIGmBgNV\
HR8EgZ4wgZswgZigOqA4hjZodHRwczovL2F1dGhlbnRpY2F0ZS1hcGkuaWNvbmVj\
dGl2LmNvbS9kb3dubG9hZC92MS9jcmyiWqRYMFYxFDASBgNVBAcMC0JyaWRnZXdh\
dGVyMQswCQYDVQQIDAJOSjETMBEGA1UEAwwKU1RJLVBBIENSTDELMAkGA1UEBhMC\
VVMxDzANBgNVBAoMBlNUSS1QQTAdBgNVHQ4EFgQUx02JRjhN+ZkafxzquOZHuSXI\
4L0wDgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMCA0gAMEUCIQCetzGpSQBLwHP+\
KChWuu7YJFa6QKJQMaZw5NO3GkJlIgIgSW5romYNlkhZhBs9U11Emk6jS+iPy20C\
sOJ3a2u10F4=\
-----END CERTIFICATE-----";

TEST_F(IdentityValidatorTest, parseTNAuthList)
{
    AmArg a;

    Botan::DataSource_Memory in(cert_with_TNAuthList);
    Botan::X509_Certificate  cert(in);

    IdentityValidator::serializeCert2AmArg(cert, a);
    ASSERT_EQ(a["tn_auth_list"][0]["spc"], "063E");
}

TEST_F(IdentityValidatorTest, parseCrlDistPoints)
{
    vector<string> in;
    vector<string> out;

    // single dist point (1)
    in = { "URI:http://example.com/crl.pem" };
    IdentityValidator::parse_crl_dist_points(in, out);
    ASSERT_EQ(out[0], "http://example.com/crl.pem");

    // single dist point (2)
    in = { "URI: http://example.com/crl.pem " };
    IdentityValidator::parse_crl_dist_points(in, out);
    ASSERT_EQ(out[0], "http://example.com/crl.pem");

    // single dist point but with multiple URIs
    string multi_dp = "URI: ldap://ldap.example.com/CN=CA,CN=CDP,CN=Certificates "
                      "URI: http://example.com/crl1.pem "
                      "URI: http://example.com/crl2.pem ";
    in              = {
        multi_dp,
    };
    IdentityValidator::parse_crl_dist_points(in, out);
    ASSERT_EQ(out[0], "http://example.com/crl1.pem");

    // multiple dist points
    in = { "URI: ldap://ldap.example.com/CN=CA,CN=CDP,CN=Certificates ", "URI: http://example.com/crl1.pem ",
           "URI: http://example.com/crl2.pem " };
    IdentityValidator::parse_crl_dist_points(in, out);
    ASSERT_EQ(out[0], "http://example.com/crl1.pem");
}