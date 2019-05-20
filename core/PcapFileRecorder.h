#ifndef PCAP_FILE_RECORDER_H
#define PCAP_FILE_RECORDER_H

#include <string>
#include <list>
#include <netinet/in.h>

#include "AmEventFdQueue.h"
#include "sip/pcap_logger.h"
#include "singleton.h"

struct PcapRecorderEvent
{
    pcap_logger *logger;
    std::vector<char> data;
    struct sockaddr_storage srcaddr;
    struct sockaddr_storage dstaddr;
    struct timeval event_time;
    PcapRecorderEvent(pcap_logger* logger, std::vector<char> data,
                      struct sockaddr *src, struct sockaddr *dst)
      : logger(logger)
      , data(data)
    {
        if(((sockaddr_in*)src)->sin_family == AF_INET) {
            memcpy(&srcaddr, src, sizeof(sockaddr_in));
        } else if(((sockaddr_in6*)src)->sin6_family == AF_INET6) {
            memcpy(&srcaddr, src, sizeof(sockaddr_in6));
        }

        if(((sockaddr_in6*)dst)->sin6_family == AF_INET) {
            memcpy(&dstaddr, dst, sizeof(sockaddr_in));
        } else if(((sockaddr_in6*)dst)->sin6_family == AF_INET6) {
            memcpy(&dstaddr, dst, sizeof(sockaddr_in6));
        }

        inc_ref(logger);

        gettimeofday(&event_time, NULL);
    }

    ~PcapRecorderEvent()
    {
        dec_ref(logger);
    }
};

class _PcapFileRecorderProcessor
    : public AmThread
    , AmEventHandler
    , AmEventFdQueue
{
    int epoll_fd;
    AmEventFd pcap_events_ready, stop_event;
    typedef std::list<PcapRecorderEvent *> PcapEventsQueue;

    PcapEventsQueue pcap_events;
    AmMutex pcap_events_lock;
    AmCondition<bool> stopped;

public:
    _PcapFileRecorderProcessor();
    ~_PcapFileRecorderProcessor();

    //AmThread
    void run() override;
    void on_stop() override;
    
    //singleton
    void dispose(){}

    //AmEventHandler
    void process(AmEvent *ev) override;
    void processRecorderEvent(PcapRecorderEvent &ev);
    void putEvent(PcapRecorderEvent *event);
};

typedef singleton<_PcapFileRecorderProcessor> PcapFileRecorderProcessor;


#endif/*PCAP_FILE_RECORDER_H*/
