#include <gtest/gtest.h>
#include "PGHandler.h"

#include "../query/QueryParam.h"

TEST_F(PostgresqlTest, ParameterTest)
{
    QueryParam param((int16_t)10);
    AmArg res = get_result(param.get_oid(), param.is_binary_format(), param.get_value());
    ASSERT_TRUE(res == AmArg((int16_t)10));
    QueryParam param1((int32_t)20);
    AmArg res1 = get_result(param1.get_oid(), param1.is_binary_format(), param1.get_value());
    ASSERT_TRUE(res1 == AmArg((int32_t)20));
    QueryParam param2((int64_t)30);
    AmArg res2 = get_result(param2.get_oid(), param2.is_binary_format(), param2.get_value());
    ASSERT_TRUE(res2 == AmArg((int64_t)30));
    QueryParam param_1((uint16_t)10);
    AmArg res_1 = get_result(param_1.get_oid(), param_1.is_binary_format(), param_1.get_value());
    ASSERT_TRUE(res_1 == AmArg((int32_t)10));
    QueryParam param1_1((uint32_t)20);
    AmArg res1_1 = get_result(param1_1.get_oid(), param1_1.is_binary_format(), param1_1.get_value());
    ASSERT_TRUE(res1_1 == AmArg((int64_t)20));
    QueryParam param3((float)5.5);
    AmArg res3 = get_result(param3.get_oid(), param3.is_binary_format(), param3.get_value());
    ASSERT_TRUE(res3 == AmArg((double)5.5));
    QueryParam param4((double)8.5);
    AmArg res4 = get_result(param4.get_oid(), param4.is_binary_format(), param4.get_value());
    ASSERT_TRUE(res4 == AmArg((double)8.5));
    QueryParam param5("test");
    AmArg res5 = get_result(param5.get_oid(), param5.is_binary_format(), param5.get_value());
    ASSERT_TRUE(res5 == AmArg("test"));
}
