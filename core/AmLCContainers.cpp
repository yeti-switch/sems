#include "AmLCContainers.h"

#include <utility>
#include "sip/ip_util.h"
#include "AmSession.h"

#define USED_PORT2IDX(PORT) (PORT >> _BITOPS_LONG_SHIFT)

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

MEDIA_info::PortMap::PortMap(MEDIA_info& info_)
  : opened_ports_counter(nullptr),
    info(info_)
{
    memset(ports_state, 0, sizeof(ports_state));
}

int MEDIA_info::PortMap::prepare(const std::string &iface_name)
{
    if(!address.empty()) {
        if((address[0] == '[') &&
          (address[address.size() - 1] == ']') ) {
            address.pop_back();
            address.erase(address.begin());
        }

        if(!am_inet_pton(address.c_str(), &saddr))
            throw string("prepare: Invalid IP address: %s", address.c_str());
    }

    unsigned short ports_state_begin_it = USED_PORT2IDX(info.low_port);
    ports_state_current_addr = ports_state_start_addr = &ports_state[ports_state_begin_it];

    unsigned short ports_state_end_it = USED_PORT2IDX(info.high_port) + !!(info.high_port%BITS_PER_LONG);
    ports_state_end_addr = &ports_state[ports_state_end_it];

    start_edge_bit_it =
        (ports_state_begin_it*BITS_PER_LONG > info.low_port) ?
            0 : info.low_port%BITS_PER_LONG;
    start_edge_bit_it_parity = start_edge_bit_it%2;

    end_edge_bit_it =
        (ports_state_end_it*BITS_PER_LONG > info.high_port) ?
            info.high_port%BITS_PER_LONG + 1 : BITS_PER_LONG;

    //flag to determine RTCP ports to ignore in freeRtpPort
    rtp_bit_parity = start_edge_bit_it % 2;

    bzero(&ports_state,sizeof(ports_state));
    //set all bits for RTCP ports to make working optimization checks like if(~(*it))
    int mask = rtp_bit_parity ? 0x55 : 0xAA;
    memset(ports_state_start_addr, mask,
           (ports_state_end_addr - ports_state_start_addr)*sizeof(unsigned long));

    ports_state_end_addr--;

    //set all leading bits before start_edge_bit_it in first bitmap element
    if(start_edge_bit_it) {
        *ports_state_start_addr |= (~(ULONG_MAX<<(start_edge_bit_it - 1)));
    }
    //set all trailing bits after end_edge_bit_it in last bitmap element
    *ports_state_end_addr |= (~(ULONG_MAX>>(BITS_PER_LONG - end_edge_bit_it)));

    opened_ports_counter = &stat_group(Gauge,"core","media_ports_opened")
        .addAtomicCounter()
        .addLabel("interface",iface_name)
        .addLabel("address",address)
        .addLabel("family",info.ipTypeToStr())
        .addLabel("type",info.transportToStr());

    return 0;
}

unsigned short MEDIA_info::PortMap::getNextRtpPort()
{
    unsigned short i = 0;
    unsigned long *it, *current_it, *next_it;

    // try to aquire port in range [ports_state_current_addr,end]
    current_it = it = ports_state_current_addr;

    //process head
    if(it==ports_state_start_addr && ~(*it)) {
        for(i = start_edge_bit_it; i < BITS_PER_LONG; i += 2) {
            if(!test_and_set_bit(i, it)) {
                goto bit_is_aquired;
            }
        }
        it++;
    }

    //common cycle
    for(; it < ports_state_end_addr; it++) {
        if (!(~(*it))) // all bits set
            continue;
        for(i = start_edge_bit_it_parity; i < BITS_PER_LONG; i += 2) {
            if(!test_and_set_bit(i, it)) {
                goto bit_is_aquired;
            }
        }
    }

    //process tail
    if (it==ports_state_end_addr && ~(*it)) {
        for(i = start_edge_bit_it_parity; i < end_edge_bit_it; i += 2) {
            if(!test_and_set_bit(i, it)) {
                goto bit_is_aquired;
            }
        }
    }

    /* no free port found in range [ports_state_current_addr,end]
     * try to aquire port in range [start,ports_state_current_addr) */

    if(current_it==ports_state_start_addr) {
        //ports_state_current_addr was equal to ports_state_start_addr
        return 0;
    }
    it = ports_state_start_addr;

    //process head
    if(~(*it)) {
        for(i = start_edge_bit_it; i < BITS_PER_LONG; i += 2) {
            if(!test_and_set_bit(i, it)) {
                goto bit_is_aquired;
            }
        }
    }
    it++;

    //common cycle
    for(; it < current_it; it++) {
        if (!(~(*it))) // all bits set
            continue;
        for(i = start_edge_bit_it_parity; i < BITS_PER_LONG; i += 2) {
            if(!test_and_set_bit(i, it)) {
                goto bit_is_aquired;
            }
        }
    }

    //no tail checking because if we are here, then it has already been checked

    return 0;

  bit_is_aquired:
    //shift ports_state_current_addr to avoid aquiring of the freshly freed port
    next_it = it+1;
    if(next_it > ports_state_end_addr) next_it = ports_state_start_addr;

    ports_state_current_addr.compare_exchange_strong(
        current_it, next_it);

    opened_ports_counter->inc(2);

    return (static_cast<unsigned short>(it-ports_state) << _BITOPS_LONG_SHIFT)  + i;
}

void MEDIA_info::PortMap::freeRtpPort(unsigned int port)
{
    if(port < info.low_port || port > info.high_port) {
        ERROR("error to free unexpected port: %u", port);
        return;
    }

    //ignore RTCP ports
    if(rtp_bit_parity ^ (port%2))
        return;

    opened_ports_counter->dec(2);
    clear_bit(port%BITS_PER_LONG, &ports_state[USED_PORT2IDX(port)]);
    __sync_synchronize();
}


void MEDIA_info::PortMap::iterateUsedPorts(std::function<void(const std::string&,unsigned short, unsigned short, const std::string& )> cl)
{
    for(unsigned short port = info.low_port; port <= info.high_port; port+=2) {
        if(constant_test_bit(port%BITS_PER_LONG, &ports_state[USED_PORT2IDX(port)]) == true) {
            //AmLock lock(lp);
            cl(address, port, port+1, localtag_ports[port]);
        }
    }
}

void MEDIA_info::PortMap::copy_addr(sockaddr_storage& ss) {
    memcpy(&ss, &saddr, sizeof(sockaddr_storage));
}

bool MEDIA_info::PortMap::match_addr(const sockaddr_storage& ss)
{
    if(ss.ss_family != saddr.ss_family)
        return false;
    if(ss.ss_family == AF_INET) {
        return SAv4(&ss)->sin_addr.s_addr==SAv4(&saddr)->sin_addr.s_addr;
    } else if(ss.ss_family == AF_INET6) {
        return IN6_ARE_ADDR_EQUAL(
            &(SAv6(&ss))->sin6_addr,
            &(SAv6(&saddr))->sin6_addr);
    }
    return false;
}

void RTP_info::addMediaAddress(std::string &address)
{
    addresses.emplace_back(*this);
    addresses.back().setAddress(address);
}

int RTP_info::prepare(const std::string& iface_name)
{
    if(MEDIA_info::prepare(iface_name)) return 1;
    for(auto& it : addresses) {
        if(it.prepare(iface_name))
            return 1;
    }
    single_address = addresses.size()==1;
    return 0;
}

bool RTP_info::getNextRtpAddress(sockaddr_storage& ss)
{ 
    unsigned short port;
    std::string localtag = reinterpret_cast<sockaddr_stream&>(ss).session->getLocalTag();

    if(single_address) {
        if((port = addresses.begin()->getNextRtpPort())) {
            addresses.begin()->copy_addr(ss);
            am_set_port(&ss, port);

            //AmLock lock(addresses.begin()->lp);
            strcpy(addresses.begin()->localtag_ports[port], localtag.c_str());

            return true;
        }
        return false;
    }

    for(auto &it : addresses) {
        if((port = it.getNextRtpPort())) {
            it.copy_addr(ss);
            am_set_port(&ss, port);

            //AmLock lock(addresses.begin()->lp);
            strcpy(addresses.begin()->localtag_ports[port], localtag.c_str());

            return true;
        }
    }

    return false;
}

void RTP_info::freeRtpAddress(const sockaddr_storage& ss)
{
    if(single_address) {
        addresses.begin()->freeRtpPort(am_get_port(&ss));

//         AmLock lock(addresses.begin()->lp);
//         addresses.begin()->localtag_ports.erase(am_get_port(&ss));
        return;
    }

    for(auto& it : addresses) {
        if(it.match_addr(ss)) {
            it.freeRtpPort(am_get_port(&ss));

//             AmLock lock(addresses.begin()->lp);
//             addresses.begin()->localtag_ports.erase(am_get_port(&ss));
            break;
        }
    }
}

void RTP_info::iterateUsedPorts(std::function<void (const std::string &, unsigned short, unsigned short, const std::string& )> cl)
{
    for(auto& it : addresses) {
        it.iterateUsedPorts(cl);
    }
}

int RTSP_info::prepare(const std::string& iface_name)
{
    if(MEDIA_info::prepare(iface_name)) return 1;
    portmap.setAddress(local_ip);
    return portmap.prepare(iface_name);
}

bool RTSP_info::getNextRtpAddress(sockaddr_storage& ss)
{
    std::string localtag = reinterpret_cast<sockaddr_stream&>(ss).session->getLocalTag();

    portmap.copy_addr(ss);
    unsigned short port;
    if(!(port = portmap.getNextRtpPort()))
        return false;
    am_set_port(&ss, port);

//    AmLock lock(portmap.lp);
    //portmap.localtag_ports.emplace(port, localtag);
    strcpy(portmap.localtag_ports[port], localtag.c_str());
    return true;
}

void RTSP_info::freeRtpAddress(const sockaddr_storage& ss)
{
    portmap.freeRtpPort(am_get_port(&ss));

//     AmLock lock(portmap.lp);
//     portmap.localtag_ports.erase(am_get_port(&ss));
}

void RTSP_info::iterateUsedPorts(std::function<void(const std::string&,unsigned short, unsigned short, const std::string& )> cl)
{
    portmap.iterateUsedPorts(cl);
}

