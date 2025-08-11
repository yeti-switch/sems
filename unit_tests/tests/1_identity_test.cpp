#include <gtest/gtest.h>
#include <AmIdentity.h>
#include <botan/x509_ca.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <log.h>
#include <jsonArg.h>
#include <fstream>

TEST(AmIdentity, ParseAndVerify)
{
    bool        ret;
    int         last_errcode;
    std::string last_error;

    std::string identity_value("eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6"
                               "Ly9jdXJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
                               "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
                               "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
                               "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w"
                               ";info=<https://curl.haxx.se/ca/cacert.pem>;alg=ES256;ppt=shaken");
    AmIdentity  identity;
    EXPECT_TRUE(ret = identity.parse(identity_value));
    if (!ret) {
        last_errcode = identity.get_last_error(last_error);
        ERROR("%d: %s", last_errcode, last_error.data());
    }

    Botan::X509_Certificate crt("./unit_tests/test.pem");

    EXPECT_FALSE(identity.verify(crt.subject_public_key().get(), time(0) - identity.get_created() - 2));
    EXPECT_TRUE(ret = identity.verify(crt.subject_public_key().get(), time(0) - identity.get_created() + 2));
    if (!ret) {
        last_errcode = identity.get_last_error(last_error);
        ERROR("%d: %s", last_errcode, last_error.data());
    }

    // ppt:div
    identity_value = "eyJhbGciOiJFUzI1NiIsInBwdCI6ImRpdiIsInR5cCI6InBhc3Nwb3J0I"
                     "iwieDV1IjoiaHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vY2VydC5jZXIifQ.eyJkZXN0"
                     "Ijp7InRuIjpbIjEyMTU1NTUxMjE0Il19LCJkaXYiOnsidG4iOiIxMjE1NTU1NTEyMT"
                     "MifSwiaWF0IjoxNDQzMjA4MzQ1LCJvcmlnIjp7InRuIjoiMTIxNTU1NTEyMTIifX0."
                     "xBHWipDEEJ8a6TsdX6xUXAnblsFiGUiAxwLiv0HLC9IICj6eG9jQd6WzeSSjHRBwxm"
                     "ChHhVIiMTSqIlk3yCNkg;"
                     "info=<https://www.example.com/cert.cer>;ppt=\"div\"";
    EXPECT_TRUE(ret = identity.parse(identity_value));
    if (!ret) {
        last_errcode = identity.get_last_error(last_error);
        ERROR("%d: %s", last_errcode, last_error.data());
    }

    identity_value = "o=<https://cert.stir.t-mobile.com/"
                     "cc6bc455afa94a1c63b057624c048db030ad80e061e609e598877470b317443f>;alg=ES256;ppt=\"shaken\"";
    EXPECT_FALSE(ret = identity.parse(identity_value));
}

TEST(AmIdentity, SignAndVerify)
{
    bool        ret;
    int         last_errcode;
    std::string last_error;

    AmIdentity identity;
    identity.set_x5u_url("https://curl.haxx.se/ca/cacert.pem");
    identity.set_attestation(AmIdentity::AT_C);

    auto          rng = std::make_shared<Botan::AutoSeeded_RNG>();
    std::ifstream ifs;
    ifs.open("./unit_tests/test.key.pem");

    EXPECT_TRUE(ifs.is_open());

    Botan::DataSource_Stream datasource(ifs);
    auto                     key = Botan::PKCS8::load_key(datasource, std::string_view());

    std::string identity_value = identity.generate(key.get());
    EXPECT_TRUE(identity.parse(identity_value));

    Botan::X509_Certificate crt("./unit_tests/test.pem");
    EXPECT_TRUE(ret = identity.verify(crt.subject_public_key().get(), 1000));

    if (!ret) {
        last_errcode = identity.get_last_error(last_error);
        ERROR("%d: %s", last_errcode, last_error.data());
    }
}

TEST(AmIdentity, ParseErrors)
{
    AmIdentity  identity;
    std::string identity_value, last_error;

    identity_value = "..lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkPiy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_COMPACT_FORM);

    identity_value =
        "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6"
        "Ly9jdXJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
        "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
        "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
        "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/cacert.pem>;alg=ES25;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_UNSUPPORTED);

    identity_value =
        "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6"
        "Ly9jdXJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
        "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
        "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
        "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/cacert.pem>;alg=ES256;ppt=shake";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_UNSUPPORTED);

    identity_value =
        "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6"
        "Ly9jdXJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
        "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
        "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
        "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/caert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_EQUAL_X5U);

    identity_value =
        "eyJhbGciOiJFUzI2NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jd"
        "XJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
        "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
        "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
        "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/cacert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_UNSUPPORTED);

    identity_value =
        "eyJhbGciOiJFUzI2NSIsInBwdCI6InNoYWtlYyIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jd"
        "XJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
        "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
        "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
        "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/cacert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_UNSUPPORTED);

    identity_value =
        "eyJhbGciOiJFUzI2NSIsInBwdCI6InNoYWtlYyIsInR5cCI6InBhc3Nwb3JkIiwieDV1IjoiaHR0cHM6Ly9jd"
        "XJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
        "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
        "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
        "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/cacert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_UNSUPPORTED);

    identity_value =
        "eyJhbGciOiJFUzI2NSIsInBwdCI6InNoYWtlbiAsInR5cCI6InBhc3Nwb3JkIiwieDV1IjoiaHR0cHM6Ly9jd"
        "XJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
        "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
        "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
        "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/cacert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_JWT_VALUE);

    identity_value =
        "eyJhbGciOkVTMjY1LCJwcHQiOnNoYWtlbiwidHlwIjpwYXNzcG9yZCwieDV1IjoiaHR0cHM6Ly9jdXJsLmhhe"
        "Hguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
        "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
        "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
        "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/cacert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_JWT_VALUE);

    identity_value =
        "eyJhbGciOlsiRVMyNjUiXSwicHB0IjpbInNoYWtlbiJdLCJ0eXAiOlsicGFzc3BvcmQiXSwieDV1IjoiaHR0c"
        "HM6Ly9jdXJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
        "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
        "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
        "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/cacert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_JWT_VALUE);

    identity_value =
        "eyJhbGciOiJFUzI2NSIsInBkdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3JkIiwieDV1IjoiaHR0cHM6Ly9jd"
        "XJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0biI6WyI"
        "iXX0sImlhdCI6MTYwMjA1NTc0Miwib3JpZyI6eyJ0biI6IiJ9LCJvcmlnaWQiOiJjOTlkOWU3Zi1kMWI"
        "zLTRjOTItYjMzMy1lNWU1ZWZmMDNhZjEifQ.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkP"
        "iy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/cacert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_JWT_VALUE);

    identity_value = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6"
                     "Ly9jdXJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6ImRzcy"
                     "IsImlhIjoxNjAyMDU1NzQyLCJvcmlnIjp7InRuIjoiIn0sIm9yaWdpZCI6ImM5OWQ5ZTdmLWQxY"
                     "jMtNGM5Mi1iMzMzLWU1ZTVlZmYwM2FmMSJ9.lj2311mNk23vinNsceeWNvVtElsuvEVCHO_hpT8eUOkPiy01PD85pFx"
                     "KfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/cacert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_JWT_VALUE);

    identity_value = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6"
                     "Ly9jdXJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJDIiwiZGVzdCI6eyJ0bi"
                     "I6ImRzIn0sImlhIjoxNjAyMDU1NzQyLCJvcmlnIjp7InRuIjoiIn0sIm9yaWdpZCI6ImM5OWQ5Z"
                     "TdmLWQxYjMtNGM5Mi1iMzMzLWU1ZTVlZmYwM2FmMSJ9.lj2311mNk23vinNsceeWNvVtElsuvEV"
                     "CHO_hpT8eUOkPiy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/"
                     "cacert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_JWT_VALUE);

    identity_value = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6"
                     "Ly9jdXJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJOIiwiZGVzdCI6eyJ0bi"
                     "I6ImQifSwiaWF0IjoxNjAyMDU1NzQyLCJvcmlnIjp7InRuIjoiIn0sIm9yaWdpZCI6ImM5OWQ5Z"
                     "TdmLWQxYjMtNGM5Mi1iMzMzLWU1ZTVlZmYwM2FmMSJ9.lj2311mNk23vinNsceeWNvVtElsuvEV"
                     "CHO_hpT8eUOkPiy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/"
                     "cacert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_UNSUPPORTED);

    identity_value = "eyJhbGciOiJFUzI1NiIsInBwdCI6InNoYWtlbiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6"
                     "Ly9jdXJsLmhheHguc2UvY2EvY2FjZXJ0LnBlbSJ9.eyJhdHRlc3QiOiJCIiwiZGVzdCI6eyJ0bi"
                     "I6e319LCJpYXQiOjE2MDIwNTU3NDIsIm9yaWciOnsidG4iOnt9fSwib3JpZ2lkIjoiYzk5c2Q5Z"
                     "TdmLWQxYjMtNGM5Mi1iMzMzLWU1ZTVlZmYwM2FmMSJ9.lj2311mNk23vinNsceeWNvVtElsuvEV"
                     "CHO_hpT8eUOkPiy01PD85pFxKfPcVb0BolCZOlXsBsncXt3lNvcsW7w;info=<https://curl.haxx.se/ca/"
                     "cacert.pem>;alg=ES256;ppt=shaken";
    EXPECT_FALSE(identity.parse(identity_value));
    EXPECT_EQ(identity.get_last_error(last_error), ERR_JWT_VALUE);
}

TEST(AmIdentity, NonArrayDest)
{
    AmIdentity identity;
    identity.set_x5u_url("https://curl.haxx.se/ca/cacert.pem");
    identity.set_attestation(AmIdentity::AT_C);

    identity.get_payload()["dest"]["tn"] = "test";

    auto          rng = std::make_shared<Botan::AutoSeeded_RNG>();
    std::ifstream ifs;
    ifs.open("./unit_tests/test.key.pem");

    EXPECT_TRUE(ifs.is_open());

    Botan::DataSource_Stream datasource(ifs);
    auto                     key = Botan::PKCS8::load_key(datasource, std::string_view());

    std::string identity_value = identity.generate(key.get());
    EXPECT_FALSE(identity.parse(identity_value));
}

TEST(AmIdentity, WrongKeyType)
{
    AmIdentity identity;
    identity.set_x5u_url("https://curl.haxx.se/ca/cacert.pem");
    identity.set_attestation(AmIdentity::AT_C);

    identity.get_payload()["dest"]["tn"] = "test";

    auto          rng = std::make_shared<Botan::AutoSeeded_RNG>();
    std::ifstream ifs;
    ifs.open("./unit_tests/test_rsa.key.pem");

    EXPECT_TRUE(ifs.is_open());

    Botan::DataSource_Stream datasource(ifs);
    auto                     key = Botan::PKCS8::load_key(datasource, std::string_view());
    EXPECT_THROW(
        {
            try {
                identity.generate(key.get());
            } catch (Botan::Exception &e) {
                EXPECT_STREQ("unexpected key type RSA", e.what());
                throw;
            }
        },
        Botan::Exception);
}
