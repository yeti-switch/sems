#include <AmEvent.h>
#include <AmEventFdQueue.h>
#include <ampi/SipRegistrarApi.h>

#include <vector>
using std::vector;

#define REGISTRAR_HANDLER_QUEUE "registrar_handler_queue"

class RegistrarHandler
    : public AmThread
    , public AmEventFdQueue
    , public AmEventHandler
{
private:
    static RegistrarHandler* _instance;
    int epoll_fd;
    AmEventFd stop_event;
    AmCondition<bool> stopped;

protected:
    /* AmThread */
    void run() override;
    void on_stop() override;

    /* AmEventHandler */
    void process(AmEvent* e) override;

public:
    RegistrarHandler();
    RegistrarHandler(const RegistrarHandler&) = delete;
    virtual ~RegistrarHandler();

    static RegistrarHandler* instance();
    static void dispose();

    void (*handle_event)(AmEvent* e);
};
