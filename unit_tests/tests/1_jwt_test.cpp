#include <gtest/gtest.h>
#include <AmJwt.h>
#include <botan/x509cert.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <log.h>
#include <jsonArg.h>
#include <fstream>

TEST(AmJwt, ParseES256)
{
    std::string last_error;

    std::string token("eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6"
                      "Ly9jdXJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
                      "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
                      "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
                      "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w");

    AmJwt jwt;
    EXPECT_TRUE(jwt.parse(token));
    EXPECT_EQ(jwt.get_iat(), 1602055742);

    AmArg &header = jwt.get_header();
    EXPECT_STREQ(header["alg"].asCStr(), "ES256");
}

TEST(AmJwt, VerifyES256)
{
    bool        ret;
    std::string last_error;

    std::string token("eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6"
                      "Ly9jdXJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
                      "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
                      "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
                      "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w");

    AmJwt jwt;
    ASSERT_TRUE(jwt.parse(token));

    Botan::X509_Certificate crt("./unit_tests/test.pem");

    EXPECT_FALSE(jwt.verify(crt.subject_public_key().get(), time(0) - jwt.get_iat() - 2));
    EXPECT_TRUE(ret = jwt.verify(crt.subject_public_key().get(), time(0) - jwt.get_iat() + 2));
    if (!ret) {
        jwt.get_last_error(last_error);
        ERROR("verify: %s", last_error.data());
    }
}

TEST(AmJwt, GenerateAndVerifyES256)
{
    std::string last_error;

    std::ifstream ifs("./unit_tests/test.key.pem");
    ASSERT_TRUE(ifs.is_open());

    Botan::DataSource_Stream datasource(ifs);
    auto                     key = Botan::PKCS8::load_key(datasource, std::string_view());

    AmJwt jwt;
    jwt.get_header()["alg"]  = "ES256";
    jwt.get_payload()["sub"] = "test";
    jwt.get_payload()["iat"] = (int)time(0);

    std::string token = jwt.generate(key.get());
    EXPECT_FALSE(token.empty());

    AmJwt jwt2;
    ASSERT_TRUE(jwt2.parse(token));
    EXPECT_STREQ(jwt2.get_header()["alg"].asCStr(), "ES256");
    EXPECT_STREQ(jwt2.get_payload()["sub"].asCStr(), "test");

    Botan::X509_Certificate crt("./unit_tests/test.pem");
    EXPECT_TRUE(jwt2.verify(crt.subject_public_key().get(), 1000));
}

TEST(AmJwt, GenerateAndVerifyHS256)
{
    std::string secret = "my-test-secret-key";

    AmJwt jwt;
    jwt.get_header()["typ"]  = "JWT";
    jwt.get_payload()["sub"] = "user123";
    jwt.get_payload()["iat"] = (int)time(0);

    std::string token = jwt.generate(secret);
    EXPECT_FALSE(token.empty());

    AmJwt jwt2;
    ASSERT_TRUE(jwt2.parse(token));
    EXPECT_STREQ(jwt2.get_header()["alg"].asCStr(), "HS256");
    EXPECT_STREQ(jwt2.get_payload()["sub"].asCStr(), "user123");
    EXPECT_TRUE(jwt2.verify(secret));

    // wrong secret must fail
    EXPECT_FALSE(jwt2.verify("wrong-secret"));
}

TEST(AmJwt, ParseErrors)
{
    AmJwt       jwt;
    std::string last_error;

    EXPECT_FALSE(jwt.parse("..signature"));
    EXPECT_EQ(jwt.get_last_error(last_error), ERR_COMPACT_FORM);

    EXPECT_FALSE(jwt.parse("header.payloadsignature"));
    EXPECT_EQ(jwt.get_last_error(last_error), ERR_JWT_VALUE);

    EXPECT_FALSE(jwt.parse("headerpayload"));
    EXPECT_EQ(jwt.get_last_error(last_error), ERR_JWT_VALUE);

    EXPECT_FALSE(jwt.parse(".cGF5bG9hZA.c2ln"));
    EXPECT_EQ(jwt.get_last_error(last_error), ERR_JWT_VALUE);

    EXPECT_FALSE(jwt.parse("aGVhZGVy..c2ln"));
    EXPECT_EQ(jwt.get_last_error(last_error), ERR_JWT_VALUE);

    EXPECT_FALSE(jwt.parse("aGVhZGVy.cGF5bG9hZA."));
    EXPECT_EQ(jwt.get_last_error(last_error), ERR_JWT_VALUE);
}

TEST(AmJwt, IsSupportedAlg)
{
    EXPECT_TRUE(AmJwt::is_supported_alg("ES256"));
    EXPECT_TRUE(AmJwt::is_supported_alg("HS256"));
    EXPECT_TRUE(AmJwt::is_supported_alg("RS256"));
    EXPECT_FALSE(AmJwt::is_supported_alg("ES384"));
    EXPECT_FALSE(AmJwt::is_supported_alg("none"));
    EXPECT_FALSE(AmJwt::is_supported_alg(""));
}

TEST(AmJwt, WrongKeyType)
{
    std::ifstream ifs("./unit_tests/test_rsa.key.pem");
    ASSERT_TRUE(ifs.is_open());

    Botan::DataSource_Stream datasource(ifs);
    auto                     key = Botan::PKCS8::load_key(datasource, std::string_view());

    AmJwt jwt;
    jwt.get_header()["alg"]  = "ES256";
    jwt.get_payload()["sub"] = "test";

    EXPECT_THROW(
        {
            try {
                jwt.generate(key.get());
            } catch (Botan::Exception &e) {
                EXPECT_STREQ("unexpected key type RSA", e.what());
                throw;
            }
        },
        Botan::Exception);
}
