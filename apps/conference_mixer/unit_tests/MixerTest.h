#pragma once

#include <singleton.h>
#include <gtest/gtest.h>

#include <string>
using std::string;

class MixerTest : public testing::Test {
  public:
    MixerTest();
    void SetUp() override;
};
