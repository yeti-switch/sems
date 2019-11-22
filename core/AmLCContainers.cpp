#include "AmLCContainers.h"

#include <utility>

#include "bitops.h"

#define BITS_PER_LONG   64

MEDIA_info::MEDIA_info(MEDIA_type type)
  : mtype(type),
    low_port(RTP_LOWPORT),
    high_port(RTP_HIGHPORT)
{
    memset(ports_state, 0, sizeof(ports_state));
}

MEDIA_info::MEDIA_info(MEDIA_info&& info)
  : IP_info(std::move(info)),
    mtype(info.mtype),
    low_port(info.low_port),
    high_port(info.high_port),
    ports_state_begin_it(info.ports_state_begin_it),
    ports_state_end_it(info.ports_state_end_it),
    start_edge_bit_it(info.start_edge_bit_it),
    end_edge_bit_it(info.end_edge_bit_it)
{
    memcpy(ports_state, info.ports_state, sizeof(ports_state));
}

MEDIA_info::~MEDIA_info()
{ }

void MEDIA_info::prepare()
{
    ports_state_begin_it = USED_PORT2IDX(low_port);

    ports_state_end_it = USED_PORT2IDX(high_port) + !!(high_port%BITS_PER_LONG);

    start_edge_bit_it =
        (ports_state_begin_it*BITS_PER_LONG > low_port) ?
            0 : low_port%BITS_PER_LONG;

    end_edge_bit_it =
        ((ports_state_end_it-1)*BITS_PER_LONG > high_port) ?
            high_port%BITS_PER_LONG + 1 : BITS_PER_LONG;
}

unsigned short MEDIA_info::getNextRtpPort()
{
    unsigned short it = ports_state_begin_it;
    unsigned short i = 0;

    //process head
    if(~(ports_state[it])) {
        for(i = start_edge_bit_it; i < BITS_PER_LONG; i += 2) {
            if(!test_and_set_bit(i, &ports_state[it])) {
                goto bit_is_aquired;
            }
        }
    }

    //common cycle
    for(; it < ports_state_end_it; it++) {
        if (!(~(ports_state[it]))) // all bits set
            continue;
        for(unsigned short i = 0; i < BITS_PER_LONG; i += 2) {
            if(!test_and_set_bit(i, &ports_state[it])) {
                goto bit_is_aquired;
            }
        }
    }

    //process tail
    if (~(ports_state[it])) {
        for(i = 0; i < end_edge_bit_it; i += 2) {
            if(!test_and_set_bit(i, &ports_state[it])) {
                goto bit_is_aquired;
            }
        }
    }
    return 0;

  bit_is_aquired:
    return it*BITS_PER_LONG + i;
}

void MEDIA_info::freeRtpPort(unsigned int port)
{
    if(port < low_port || port > high_port) {
        ERROR("error to free unexpected port: %i", port);
        return;
    }

    clear_bit(port%64, &ports_state[USED_PORT2IDX(port)]);
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

