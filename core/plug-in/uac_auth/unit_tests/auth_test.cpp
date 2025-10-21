#include <gtest/gtest.h>
#include "../UACAuth.h"

#define DEFAULT_NONCE_EXPIRE 300

TEST(UACAuth, nonce_gen)
{
    MD5_Hash    hash;
    std::string secret = "1234secret";
    std::string nonce  = hash.calcNonce(secret);
    //      DBG("nonce '%s'", nonce.c_str());
    ASSERT_TRUE(hash.checkNonce(nonce, secret, DEFAULT_NONCE_EXPIRE));
}

TEST(UACAuth, nonce_wrong_secret)
{
    MD5_Hash    hash;
    std::string secret = "1234secret";
    std::string nonce  = hash.calcNonce(secret);
    ASSERT_FALSE(hash.checkNonce(nonce, secret + "asd", DEFAULT_NONCE_EXPIRE) == NCR_OK);
}

TEST(UACAuth, nonce_wrong_nonce)
{
    MD5_Hash    hash;
    std::string secret = "1234secret";
    std::string nonce  = hash.calcNonce(secret);
    nonce[0]           = 0;
    nonce[1]           = 0;
    ASSERT_FALSE(hash.checkNonce(nonce, secret, DEFAULT_NONCE_EXPIRE) == NCR_OK);
}

TEST(UACAuth, nonce_wrong_nonce1)
{
    MD5_Hash    hash;
    std::string secret = "1234secret";
    std::string nonce  = hash.calcNonce(secret);
    nonce += "hallo";
    ASSERT_FALSE(hash.checkNonce(nonce, secret, DEFAULT_NONCE_EXPIRE) == NCR_OK);
}

TEST(UACAuth, nonce_wrong_nonce2)
{
    MD5_Hash    hash;
    std::string secret = "1234secret";
    std::string nonce  = hash.calcNonce(secret);

    auto idx                = nonce.find_last_not_of(nonce[nonce.size() - 1], nonce.size() - 2);
    nonce[nonce.size() - 1] = nonce[idx];
    ASSERT_FALSE(hash.checkNonce(nonce, secret, DEFAULT_NONCE_EXPIRE) == NCR_OK);
}

TEST(UACAuth, t_cmp_len)
{
    std::string s1 = "1234secret";
    std::string s2 = "1234s3ecret";
    ASSERT_FALSE(UACAuth::tc_isequal(s1, s2));
}

TEST(UACAuth, t_cmp_eq)
{
    std::string s1 = "1234secret";
    std::string s2 = "1234secret";
    ASSERT_TRUE(UACAuth::tc_isequal(s1, s2));
}


TEST(UACAuth, t_cmp_empty)
{
    ASSERT_TRUE(UACAuth::tc_isequal("", ""));
}

TEST(UACAuth, t_cmp_uneq)
{
    ASSERT_FALSE(UACAuth::tc_isequal("1234secret", "2134secret"));
}

TEST(UACAuth, t_cmp_uneq_chr)
{
    ASSERT_FALSE(UACAuth::tc_isequal("1234secret", "2134secret", 10));
}

TEST(UACAuth, t_cmp_eq_charptr)
{
    ASSERT_TRUE(UACAuth::tc_isequal("1234secret", "1234secret", 10));
}

TEST(UACAuth, parseTest)
{
    char                           data[] = "Digest realm=\"http-auth@example.org\", "
                                            "qop=\"auth, auth-int\", algorithm=SHA-256, "
                                            "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", "
                                            "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
    vector<UACAuthDigestChallenge> challenge;
    ASSERT_TRUE(UACAuthDigestChallenge::parse(data, challenge));

    challenge.clear();
    char data1[] = "Digest realm=\"http-auth@example.org\", "
                   "qop=\"auth, auth-int\", algorithm=SHA-256, "
                   "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", "
                   "Digest realm=\"http-auth@example.org\", "
                   "qop=\"auth, auth-int\", algorithm=MD5, "
                   "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\"";
    ASSERT_TRUE(UACAuthDigestChallenge::parse(data1, challenge));
}
