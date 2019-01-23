#include "PcapFileRecorder.h"
#include "AmEventDispatcher.h"

#define PCAP_QUEUE_NAME "PcapFileRecorder"
#define EPOLL_MAX_EVENTS  2048

_PcapFileRecorderProcessor::_PcapFileRecorderProcessor()
  : AmEventFdQueue(this),
    pcap_events_ready(false),
    stopped(false)
{
}

_PcapFileRecorderProcessor::~_PcapFileRecorderProcessor()
{
}

//AmThread
void _PcapFileRecorderProcessor::run()
{
    int ret;
    bool running = true;
    struct epoll_event events[EPOLL_MAX_EVENTS];
    PcapEventsQueue pcap_events_local;

    setThreadName("pcap recorder");

    AmEventDispatcher::instance()->addEventQueue(PCAP_QUEUE_NAME, this);
    if((epoll_fd = epoll_create(10)) == -1){
        ERROR("epoll_create call failed");
        throw std::string("epoll_create call failed");
    }

    epoll_link(epoll_fd);
    pcap_events_ready.link(epoll_fd);
    stop_event.link(epoll_fd);

    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);
        if(ret == -1 && errno != EINTR){
            ERROR("epoll_wait: %s\n",strerror(errno));
        }

        if(ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            int f = e.data.fd;

            if(f== -queue_fd()){
                processEvents();
                clear_pending();
            } else if(f==pcap_events_ready){
                pcap_events_ready.read();

                pcap_events_lock.lock();
                pcap_events_local.swap(pcap_events);
                pcap_events_lock.unlock();
                while(!pcap_events_local.empty()){
                    PcapRecorderEvent *rec_ev = pcap_events_local.front();
                    processRecorderEvent(*rec_ev);
                    pcap_events_local.pop_front();
                    delete rec_ev;
                }
            } else if(f==stop_event) {
                running = false;
                break;
            }
        }
    } while(running);

    AmEventDispatcher::instance()->delEventQueue(PCAP_QUEUE_NAME);

    pcap_events_lock.lock();
    DBG("%ld unprocessed events on stop",pcap_events.size());
    for(PcapEventsQueue::iterator it = pcap_events.begin();
        it!=pcap_events.end();++it)
    {
        delete *it;
    }
    pcap_events_lock.unlock();

    DBG("pcap recorder stopped");
    stopped.set(true);
}

void _PcapFileRecorderProcessor::on_stop()
{
    stopped.wait_for();
}

void _PcapFileRecorderProcessor::process(AmEvent *ev)
{
    if (ev->event_id == E_SYSTEM) {
        AmSystemEvent* sys_ev = dynamic_cast<AmSystemEvent*>(ev);
        if(sys_ev && sys_ev->sys_event == AmSystemEvent::ServerShutdown){
            stop_event.fire();
        }
        return;
    }
}

void _PcapFileRecorderProcessor::processRecorderEvent(PcapRecorderEvent &ev)
{
    if(((sockaddr_in*)&ev.srcaddr)->sin_family == AF_INET) {
        ev.logger->logv4(ev.data.data(), ev.data.size(), &ev.srcaddr, &ev.dstaddr, sizeof(sockaddr_in));
    } else if(((sockaddr_in6*)&ev.srcaddr)->sin6_family == AF_INET6) {
        ev.logger->logv6(ev.data.data(), ev.data.size(), &ev.srcaddr, &ev.dstaddr, sizeof(sockaddr_in6));
    }
}

void _PcapFileRecorderProcessor::putEvent(PcapRecorderEvent *event)
{
    pcap_events_lock.lock();
    pcap_events.push_back(event);
    pcap_events_lock.unlock();

    pcap_events_ready.fire();
}

