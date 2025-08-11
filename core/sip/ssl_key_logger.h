#ifndef SSLKEY_LOGGER_H
#define SSLKEY_LOGGER_H

#include "sip/msg_logger.h"
#include <memory>

class SSLKeyLogger : public file_msg_logger {
  private:
    bool is_enable;

    int log(const char *buf, int len, sockaddr_storage *src_ip, sockaddr_storage *dst_ip, cstring method,
            int reply_code = 0) override;

    int write_file_header() override { return 0; }

  public:
    SSLKeyLogger(const string &path, bool upload = false);
    ~SSLKeyLogger();

    void log(const char *label, const string &client_random, const string &secret);
    void stop();
};

std::shared_ptr<SSLKeyLogger> ssl_key_logger();
std::shared_ptr<SSLKeyLogger> restart_ssl_key_logger(const string &path);

#endif /*SSLKEY_LOGGER_H*/
