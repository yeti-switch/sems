#include "AmLCContainers.h"

#include <utility>

#define USED_PORT2IDX(PORT) (PORT >> _BITOPS_LONG_SHIFT)

MEDIA_info::MEDIA_info(MEDIA_type type)
  : IP_info(),
    mtype(type),
    low_port(RTP_LOWPORT),
    high_port(RTP_HIGHPORT),
    opened_ports_counter(nullptr)
{
    memset(ports_state, 0, sizeof(ports_state));
}

MEDIA_info::~MEDIA_info()
{ }

int MEDIA_info::prepare(const std::string &iface_name)
{

    if(high_port <= low_port) {
        ERROR("invalid port range: %hu-%hu. high_port should be greater than low_port",
              low_port,high_port);
        return 1;
    }

    if((high_port - low_port) < 4) {
        ERROR("invalid port range: %hu-%hu. specified range is to small for even one B2B call. "
              "actual range is: %d",
              low_port,high_port,high_port-low_port);
        return 1;
    }

    if((high_port - low_port) % 2 != 0) {
        ERROR("invalid port range: %hu-%hu. range must be multiple of 2 "
              "to correctly allocate both RTP and RTCP ports. actual range is: %d",
              low_port,high_port,high_port-low_port);
        return 1;
    }

    unsigned short ports_state_begin_it = USED_PORT2IDX(low_port);
    ports_state_begin_addr = &ports_state[ports_state_begin_it];

    unsigned short ports_state_end_it = USED_PORT2IDX(high_port) + !!(high_port%BITS_PER_LONG);
    ports_state_end_addr = &ports_state[ports_state_end_it];

    start_edge_bit_it =
        (ports_state_begin_it*BITS_PER_LONG > low_port) ?
            0 : low_port%BITS_PER_LONG;
    start_edge_bit_it_parity = start_edge_bit_it%2;

    end_edge_bit_it =
        (ports_state_end_it*BITS_PER_LONG > high_port) ?
            high_port%BITS_PER_LONG + 1 : BITS_PER_LONG;

    //flag to determine RTCP ports to ignore in freeRtpPort
    rtp_bit_parity = start_edge_bit_it % 2;

    bzero(&ports_state,sizeof(ports_state));
    //set all bits for RTCP ports to make working optimization checks like if(~(*it))
    int mask = rtp_bit_parity ? 0x55 : 0xAA;
    memset(ports_state_begin_addr, mask,
           (ports_state_end_addr - ports_state_begin_addr)*sizeof(unsigned long));

    ports_state_end_addr--;

    //set all leading bits before start_edge_bit_it in first bitmap element
    if(start_edge_bit_it) {
        *ports_state_begin_addr |= (~(ULONG_MAX<<(start_edge_bit_it - 1)));
    }
    //set all trailing bits after end_edge_bit_it in last bitmap element
    *ports_state_end_addr |= (~(ULONG_MAX>>(BITS_PER_LONG - end_edge_bit_it)));

    opened_ports_counter = &stat_group(Gauge,"core","media_ports_opened")
        .addAtomicCounter()
        .addLabel("interface",iface_name)
        .addLabel("family",ipTypeToStr())
        .addLabel("type",transportToStr());

    return 0;
}

unsigned short MEDIA_info::getNextRtpPort()
{
    unsigned short i = 0;
    unsigned long *it = ports_state_begin_addr;

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

    //no free port found
    return 0;

  bit_is_aquired:
    opened_ports_counter->inc(2);
    return (static_cast<unsigned short>(it-ports_state) << _BITOPS_LONG_SHIFT)  + i;
}

void MEDIA_info::freeRtpPort(unsigned int port)
{
    if(port < low_port || port > high_port) {
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


void MEDIA_info::iterateUsedPorts(std::function<void(unsigned short, unsigned short)> cl)
{
    for(unsigned short port = low_port; port <= high_port; port+=2) {
        if(constant_test_bit(port%BITS_PER_LONG, &ports_state[USED_PORT2IDX(port)]) == true) {
            cl(port, port+1);
        }
    }
}

