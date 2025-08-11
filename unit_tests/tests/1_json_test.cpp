#include <gtest/gtest.h>

#include <log.h>
#include <AmArg.h>
#include <jsonArg.h>

TEST(Json, jsonParseEscaped)
{
    std::string s = "{\"jsonrpc\": \"2.0\", \"id\": \"11\", \"error\": {\"message\": \"(1062, \\\"Duplicate entry "
                    "'5447' for key 'PRIMARY'\\\")\", \"code\": -32603}},";
    AmArg       a;
    ASSERT_TRUE(json2arg(s.c_str(), a));
}

TEST(Json, emptyStructParse)
{
    std::string s = "{\"result\": {}}";
    AmArg       rpc_params;
    ASSERT_TRUE(json2arg(s.c_str(), rpc_params));
    ASSERT_TRUE(isArgStruct(rpc_params["result"]));
};

TEST(Json, empty_array_parse)
{
    std::string s = "{\"result\": []}";
    AmArg       rpc_params;
    ASSERT_TRUE(json2arg(s.c_str(), rpc_params));
    ASSERT_TRUE(isArgArray(rpc_params["result"]));
};

TEST(Json, error_array_parse)
{
    std::string s = "{\"result\": [ :1]}";
    AmArg       rpc_params;
    ASSERT_TRUE(!json2arg(s.c_str(), rpc_params));
};

TEST(Json, error_object_parse)
{
    std::string s = "{\"result\": { :1}}";
    AmArg       rpc_params;
    ASSERT_TRUE(!json2arg(s.c_str(), rpc_params));
};

TEST(Json, empty_string_key_parse)
{
    std::string s = "{\"result\": {\"\" :1}}";
    AmArg       rpc_params;
    ASSERT_TRUE(json2arg(s.c_str(), rpc_params));
    ASSERT_TRUE(rpc_params["result"][""].asInt() == 1);
};
/*
TEST(Json, number_e_parse) {
    std::string s = "{\"result\": 0E1}";
    AmArg rpc_params;
    ASSERT_TRUE(json2arg(s.c_str(), rpc_params));
    ASSERT_TRUE(isArgInt(rpc_params["result"]));
    ASSERT_TRUE(rpc_params["result"].asInt() == 0);
};*/
/*
TEST(Json, number_e_pow) {
    std::string s = "{\"result\": 1E1}";
    AmArg rpc_params;
    ASSERT_TRUE(json2arg(s.c_str(), rpc_params));
    ASSERT_TRUE(isArgInt(rpc_params["result"]) && rpc_params["result"].asInt() == 10);
};*/
/*
TEST(Json, number_e_pow2) {
    std::string s = "{\"result\": 5e0}";
    AmArg rpc_params;
    ASSERT_TRUE(json2arg(s.c_str(), rpc_params));
    ASSERT_TRUE(isArgInt(rpc_params["result"]) && rpc_params["result"].asInt() == 5);
};*/

TEST(Json, number_e_wrong)
{
    std::string s = "{\"result\": 1E}";
    AmArg       rpc_params;
    ASSERT_TRUE(!json2arg(s.c_str(), rpc_params));
};

TEST(Json, number_e_powneg1)
{
    std::string s = "{\"result\": 1E-1}";
    AmArg       rpc_params;
    ASSERT_TRUE(json2arg(s.c_str(), rpc_params));

    ASSERT_TRUE(isArgDouble(rpc_params["result"]));
    ASSERT_TRUE(isArgDouble(rpc_params["result"]) && rpc_params["result"].asDouble() == 0.1);
};

TEST(Json, number_float_parse)
{
    std::string s = "{\"result\": 1.21}";
    AmArg       rpc_params;
    ASSERT_TRUE(json2arg(s.c_str(), rpc_params));

    ASSERT_TRUE(isArgDouble(rpc_params["result"]));
    ASSERT_TRUE(isArgDouble(rpc_params["result"]) && rpc_params["result"].asDouble() == 1.21);
};

TEST(Json, tofro_equality)
{
    AmArg a1;
    a1["test"] = 1;
    a1["test2"].push("asdf");
    a1["test2"].push(1);

    std::string s = arg2json(a1);
    AmArg       a2;
    bool        back_conversion_result = json2arg(s, a2);
    ASSERT_TRUE(back_conversion_result);
};
