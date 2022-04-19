#include "PortMap.h"
#include "sip/ip_util.h"

#define USED_PORT2IDX(PORT) (PORT >> _BITOPS_LONG_SHIFT)

PortMap::PortMap()
  : opened_ports_counter(nullptr)
{
    memset(ports_state, 0, sizeof(ports_state));
}

int PortMap::prepare(
    const std::string &iface_name,
    unsigned short lo,
    unsigned short hi,
    const std::string &family,
    const std::string &transport)
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

    low_port = lo;
    high_port = hi;

    unsigned short ports_state_begin_it = USED_PORT2IDX(low_port);
    ports_state_current_addr = ports_state_start_addr = &ports_state[ports_state_begin_it];

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
        .addLabel("family",family)
        .addLabel("type",transport);

    return 0;
}

unsigned short PortMap::getNextRtpPort()
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

void PortMap::freeRtpPort(unsigned int port)
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


void PortMap::iterateUsedPorts(std::function<void(const std::string&,unsigned short, unsigned short)> cl)
{
    for(unsigned int port = low_port; port <= high_port; port+=2) {
        if(constant_test_bit(port%BITS_PER_LONG, &ports_state[USED_PORT2IDX(port)]) == true) {
            cl(address, port, port+1);
        }
    }
}

void PortMap::copy_addr(sockaddr_storage& ss) {
    memcpy(&ss, &saddr, sizeof(sockaddr_storage));
}

bool PortMap::match_addr(const sockaddr_storage& ss)
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
