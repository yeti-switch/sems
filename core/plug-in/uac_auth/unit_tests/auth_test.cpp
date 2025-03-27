#include <gtest/gtest.h>
#include "../UACAuth.h"

TEST(UACAuth, nonce_gen) {
      std::string secret = "1234secret";
      std::string nonce = UACAuth::calcNonce();
      //      DBG("nonce '%s'", nonce.c_str());
      ASSERT_TRUE(UACAuth::checkNonce(nonce));
}

TEST(UACAuth, nonce_wrong_secret) {
    std::string secret = "1234secret";
    UACAuth::setServerSecret(secret);
    std::string nonce = UACAuth::calcNonce();

    UACAuth::setServerSecret(secret+"asd");
    ASSERT_FALSE(UACAuth::checkNonce(nonce) == UACAuth::NCR_OK);
}

TEST(UACAuth, nonce_wrong_nonce) {
    std::string secret = "1234secret";
    std::string nonce = UACAuth::calcNonce();
    nonce[0]=0;
    nonce[1]=0;
    ASSERT_FALSE(UACAuth::checkNonce(nonce) == UACAuth::NCR_OK);
}

TEST(UACAuth, nonce_wrong_nonce1) {
    std::string secret = "1234secret";
    std::string nonce = UACAuth::calcNonce();
    nonce+="hallo";
    ASSERT_FALSE(UACAuth::checkNonce(nonce) == UACAuth::NCR_OK);
}

TEST(UACAuth, nonce_wrong_nonce2) {
    std::string secret = "1234secret";
    std::string nonce = UACAuth::calcNonce();
    nonce[nonce.size()-1]=nonce[nonce.size()-2];
    ASSERT_FALSE(UACAuth::checkNonce(nonce) == UACAuth::NCR_OK);
}

TEST(UACAuth, t_cmp_len) {
    std::string s1 = "1234secret";
    std::string s2 = "1234s3ecret";
    ASSERT_FALSE(UACAuth::tc_isequal(s1,s2) );
}

TEST(UACAuth, t_cmp_eq) {
    std::string s1 = "1234secret";
    std::string s2 = "1234secret";
    ASSERT_TRUE( UACAuth::tc_isequal(s1,s2) );
}


TEST(UACAuth, t_cmp_empty) {
    ASSERT_TRUE( UACAuth::tc_isequal("","") );
}

TEST(UACAuth, t_cmp_uneq) {
    ASSERT_FALSE(UACAuth::tc_isequal("1234secret","2134secret") );
}

TEST(UACAuth, t_cmp_uneq_chr) {
    ASSERT_FALSE(UACAuth::tc_isequal("1234secret","2134secret", 10) );
}

TEST(UACAuth, t_cmp_eq_charptr) {
    ASSERT_TRUE( UACAuth::tc_isequal("1234secret","1234secret", 10) );
}
