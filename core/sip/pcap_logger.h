#ifndef __PCAP_LOGGER_H
#define __PCAP_LOGGER_H

#include <stdio.h>
#include <string>

#include "msg_logger.h"

/** class for logging sent/received data in PCAP format */
class pcap_logger : public file_msg_logger {
  protected:
    int write_file_header();

    friend class _PcapFileRecorderProcessor;
    int logv4(const char *data, int data_len, struct sockaddr_storage *src, struct sockaddr_storage *dst,
              size_t addr_len, struct timeval &event_time);
    int logv6(const char *data, int data_len, struct sockaddr_storage *src, struct sockaddr_storage *dst,
              size_t addr_len, struct timeval &event_time);

  public:
    pcap_logger();

    int log(const char *buf, int len, sockaddr_storage *src_ip, sockaddr_storage *dst_ip, cstring method,
            int reply_code = 0);
};

#endif
