#pragma once


class EventFD
{
        int event_fd;

    public:
        EventFD();
        ~EventFD();

        bool init(int epoll_fd, int flags, int ev_data_fd);
        void handler();
        void pushEvent(void);
};
