#pragma once

class AmInbandDetector
{
 public:
  virtual ~AmInbandDetector() { }
  virtual int streamPut(const unsigned char* samples, unsigned int size, unsigned long long system_ts) = 0;
};
