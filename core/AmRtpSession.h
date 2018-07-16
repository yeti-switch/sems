#pragma once

class AmRtpSession {
  public:
    virtual ~AmRtpSession() { }
    virtual void recvPacket(int fd) = 0;
};
