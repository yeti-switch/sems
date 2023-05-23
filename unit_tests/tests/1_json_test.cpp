#include <gtest/gtest.h>

#include <log.h>
#include <AmArg.h>
#include <jsonArg.h>

TEST(json, json2argEmptyString)
{
    //test added because of infinite loop
    std::string s(" ");
    AmArg a;
    json2arg(s,a);
}
