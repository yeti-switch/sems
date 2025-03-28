#include "ssl_key_logger.h"
#include <AmLcConfig.h>

SSLKeyLogger::SSLKeyLogger(const std::string& path, bool upload)
: is_enable(true)
{
    if(path.empty()) is_enable = false;
    else is_enable = (open(path.c_str()) == 0);
    if(upload && !AmConfig.skl_upload_queue_name.empty()) {
        upload_destination = &AmConfig.skl_upload_queue_name;
    }
}

SSLKeyLogger::~SSLKeyLogger()
{
    DBG("~SSLKeyLogger()");
    struct stat buf;
    if(stat(path.c_str(), &buf) || !buf.st_size) {
        unlink(path.c_str());
        upload_destination = nullptr;
        return;
    }
}

int SSLKeyLogger::log(const char* buf, int len, sockaddr_storage*, sockaddr_storage*, cstring, int)
{
    fd_mut.lock();
    write(buf, len);
    fd_mut.unlock();
    return 0;
}

void SSLKeyLogger::log(const char* label, const std::string& client_random, const std::string& secret)
{
    if(!is_enable) return;
    string data(label);
    data += " ";
    data += client_random;
    data += " ";
    data += secret;
    data += "\n";
    log(data.c_str(), data.size(), 0, 0, {0, 0});
}

void SSLKeyLogger::stop()
{
    is_enable = false;
}

std::atomic<std::shared_ptr<SSLKeyLogger>> _ssl_key_logger;

std::shared_ptr<SSLKeyLogger> ssl_key_logger()
{
    return _ssl_key_logger.load();
}

std::shared_ptr<SSLKeyLogger> restart_ssl_key_logger(const string& path)
{
    _ssl_key_logger.store(std::make_shared<SSLKeyLogger>(path));
    return _ssl_key_logger.load(std::memory_order_acquire);
}
