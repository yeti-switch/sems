#pragma once

#include <atomic>
#include <functional>
#include <cstdint>
#include <string>

#include <limits.h>

#include "AmStatistics.h"
#include "bitops.h"

class PortMap {
  private:
    DECLARE_BITMAP_ALIGNED(ports_state, (USHRT_MAX + BYTES_PER_LONG + 1));
    unsigned long               *ports_state_start_addr, *ports_state_end_addr;
    std::atomic<unsigned long *> ports_state_current_addr;
    unsigned short               start_edge_bit_it, start_edge_bit_it_parity, end_edge_bit_it;
    bool                         rtp_bit_parity;

    AtomicCounter *opened_ports_counter;

    unsigned short   low_port, high_port;
    std::string      address;
    sockaddr_storage saddr;

    std::function<void(unsigned short)> portBind;
    std::function<void(unsigned short)> portUnbind;

  public:
    PortMap();
    PortMap(const PortMap &) = delete;
    PortMap(PortMap &&)      = delete;
    typedef std::function<void(const std::function<void(unsigned short)> &bind_f,
                               const std::function<void(unsigned short)> &unbind_f)>
        portCallbackRegistrator;

    unsigned short getNextRtpPort();
    void           freeRtpPort(unsigned int port);
    void           iterateUsedPorts(std::function<void(const std::string &, unsigned short, unsigned short)> cl);

    void registerPortCallbacks(const std::function<void(unsigned short)> &bind_f,
                               const std::function<void(unsigned short)> &unbind_f)
    {
        portBind   = std::move(bind_f);
        portUnbind = std::move(unbind_f);
    }

    /* initialize variables for RTP ports pool management and validate ports range
     * returns 0 on success, 1 otherwise */
    int prepare(const std::string &iface_name, unsigned short lo, unsigned short hi, const std::string &family,
                const std::string &transport);

    void copy_addr(sockaddr_storage &ss);
    bool match_addr(const sockaddr_storage &ss);

    void                    setAddress(const string &address_) { address = address_; }
    string                  getAddress() { return address; }
    const sockaddr_storage &getSockAddr() const { return saddr; }
};
