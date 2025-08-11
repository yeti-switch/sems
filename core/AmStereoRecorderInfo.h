#pragma once

#include <string>
using std::string;

#include <vector>

struct StereoRecorderInfo {
    string recorder_id;
    int    channel_id;

    StereoRecorderInfo(const string &recorder_id, int channel_id)
        : recorder_id(recorder_id)
        , channel_id(channel_id)
    {
    }
};

class StereoRecordersList : public std::vector<StereoRecorderInfo> {
  public:
    void add(const string &recorder_id, int channel_id);
    bool del(const string &recorder_id, int channel_id);
    void put(unsigned long long ts, const unsigned char *samples, size_t len, int input_sample_rate);
};
