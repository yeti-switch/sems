#include <gtest/gtest.h>
#include <AmUtils.h>

using TestUtf8ValidateDataType = std::tuple<string, bool, string>;

class Validator
  : public testing::TestWithParam<TestUtf8ValidateDataType>
{
  protected:
    string string_to_check, expected_fixup_result;
    bool expected_to_be_valid;

    void SetUp() override {
        const auto &param = GetParam();
        string_to_check = std::get<0>(param);
        expected_to_be_valid = std::get<1>(param);
        expected_fixup_result = std::get<2>(param);
    }

    void TearDown() override { }
};

TEST_P(Validator, validate)
{
    ASSERT_EQ(is_valid_utf8(string_to_check), expected_to_be_valid);
}

TEST_P(Validator, fixup)
{
    bool replaced = fixup_utf8_inplace(string_to_check);
    ASSERT_EQ(replaced, !expected_to_be_valid);
    ASSERT_EQ(string_to_check, expected_fixup_result);
}

INSTANTIATE_TEST_SUITE_P(
    Utf8,
    Validator,
    testing::Values(
        std::make_tuple("<>", true, "<>"),
        std::make_tuple("\xF5>", false, ">"),
        std::make_tuple("<\xF5>", false, "<>"),
        std::make_tuple("<\xF5\xF5>", false, "<>"),
        std::make_tuple("<\xC3\xA6>", true, "<\xC3\xA6>"),
        std::make_tuple("<\xC3\x70>", false, "<p>"),
        std::make_tuple("<\xE0\xA0\x70>", false, "<p>"),
        std::make_tuple("\xE0\xA0\x70>", false, "p>"),
        std::make_tuple("<\xF0\x90\x80\x80>", true, "<\xF0\x90\x80\x80>"),
        std::make_tuple("<\xF0\x89\x80\x80>", false, "<>"),
        std::make_tuple("<\xF0\x90\x79\x80>", false, "<y>"),
        std::make_tuple("<\xF0\x90\x80\x79>", false, "<y>"),
        std::make_tuple("<\xE4>", false, "<>"),
        std::make_tuple("<\xE4|\xE4>", false, "<|>"),
        std::make_tuple("\xF0", false, ""),
        std::make_tuple("<\xF0", false, "<"),
        std::make_tuple("<\xF0\x90", false, "<"),
        std::make_tuple("<\xF0\x90\x80", false, "<"),
        std::make_tuple("\xF0\x90\x80", false, "")
    ));
