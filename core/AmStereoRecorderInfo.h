#pragma once

#include <string>
using std::string;

#include <vector>

struct StereoRecorderInfo {
    string recorder_id;
    int channel_id;

    StereoRecorderInfo(const string &recorder_id, int channel_id)
      : recorder_id(recorder_id),
        channel_id(channel_id)
    {}
};

class StereoRecordersList
  : public std::vector<StereoRecorderInfo>
{
  public:
    void add(const string &recorder_id, int channel_id)
    {
        for(const auto &i : *this) {
            if(i.recorder_id == recorder_id && i.channel_id == channel_id)
                return;
        }
        emplace_back(recorder_id,channel_id);
    }

    bool del(const string &recorder_id, int channel_id) {
        for(const auto i = begin(); i != end();) {
            if(i->recorder_id == recorder_id && i->channel_id == channel_id)
                erase(i);
        }
        return !empty();
    }

    void put(unsigned long long  ts, const unsigned char *samples, size_t len, int input_sample_rate);
};

