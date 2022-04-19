#include "AmLCContainers.h"

#include <utility>
#include "sip/ip_util.h"

MEDIA_info::MEDIA_info(MEDIA_type type)
  : IP_info(),
    mtype(type),
    low_port(RTP_LOWPORT),
    high_port(RTP_HIGHPORT)
{}

MEDIA_info::~MEDIA_info()
{ }

int MEDIA_info::prepare(const std::string& iface_name)
{
    if(low_port < 1) {
        ERROR("%s: invalid port range: %hu-%hu. low_port should be greater than zero",
              iface_name.data(),low_port,high_port);
        return 1;
    }
    if(low_port%2) {
        ERROR("%s: invalid port range: %hu-%hu. low_port should be even",
              iface_name.data(),low_port,high_port);
        return 1;
    }
    if(!(high_port%2)) {
        ERROR("%s: invalid port range: %hu-%hu. high_port should be odd",
              iface_name.data(),low_port,high_port);
        return 1;
    }
    if(high_port <= low_port) {
        ERROR("%s:invalid port range: %hu-%hu. high_port should be greater than low_port",
              iface_name.data(),low_port,high_port);
        return 1;
    }
    if((high_port - low_port) < 3) {
        ERROR("%s: invalid port range: %hu-%hu. specified range is to small for even one B2B call. "
              "actual range is: %d",
              iface_name.data(),low_port,high_port,high_port-low_port);
        return 1;
    }

    return 0;
}

void RTP_info::addMediaAddress(const std::string &address)
{
    addresses.emplace_back();
    addresses.back().setAddress(address);
}

int RTP_info::prepare(const std::string& iface_name)
{
    if(MEDIA_info::prepare(iface_name)) return 1;
    for(auto& it : addresses) {
        if(it.prepare(iface_name, low_port, high_port,
                      ipTypeToStr(), transportToStr()))
            return 1;
    }
    single_address = addresses.size()==1;
    return 0;
}

bool RTP_info::getNextRtpAddress(sockaddr_storage& ss)
{ 
    unsigned short port;

    if(single_address) {
        if((port = addresses.begin()->getNextRtpPort())) {
            addresses.begin()->copy_addr(ss);
            am_set_port(&ss, port);
            return true;
        }
        return false;
    }

    for(auto &it : addresses) {
        if((port = it.getNextRtpPort())) {
            it.copy_addr(ss);
            am_set_port(&ss, port);
            return true;
        }
    }

    return false;
}

void RTP_info::freeRtpAddress(const sockaddr_storage& ss)
{
    if(single_address) {
        addresses.begin()->freeRtpPort(am_get_port(&ss));
        return;
    }

    for(auto& it : addresses) {
        if(it.match_addr(ss)) {
            it.freeRtpPort(am_get_port(&ss));
            break;
        }
    }
}

void RTP_info::iterateUsedPorts(std::function<void (const std::string &, unsigned short, unsigned short)> cl)
{
    for(auto& it : addresses) {
        it.iterateUsedPorts(cl);
    }
}

int RTSP_info::prepare(const std::string& iface_name)
{
    if(MEDIA_info::prepare(iface_name)) return 1;
    portmap.setAddress(local_ip);
    return portmap.prepare(iface_name, low_port, high_port,
                           ipTypeToStr(), transportToStr());
}

bool RTSP_info::getNextRtpAddress(sockaddr_storage& ss)
{
    portmap.copy_addr(ss);
    unsigned short port;
    if(!(port = portmap.getNextRtpPort()))
        return false;
    am_set_port(&ss, port);
    return true;
}

void RTSP_info::freeRtpAddress(const sockaddr_storage& ss)
{
    portmap.freeRtpPort(am_get_port(&ss));
}

void RTSP_info::iterateUsedPorts(std::function<void(const std::string&,unsigned short, unsigned short)> cl)
{
    portmap.iterateUsedPorts(cl);
}

