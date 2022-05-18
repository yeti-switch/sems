#include <sys/socket.h>
#include <netinet/in.h>
#include <gtest/gtest.h>
#include <string>
#include "../WorkersManager.h"
#include "../Config.h"
#include <AmSessionContainer.h>
#include <ampi/HttpClientAPI.h>
#include <sip/sip_parser.h>

class HttpServerTask : public ITask
{
    int server_fd;
public:
    HttpServerTask() {
        server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(test_config::instance()->http_port);
        if (bind(server_fd, (sockaddr*)&addr, sizeof(sockaddr_in)) ||
            listen(server_fd, 0)) {
                throw std::runtime_error("server creation failed");
        }
    }
    ~HttpServerTask () {
        stop();
    }

    void stop() override
    {
        if(server_fd) {
            close(server_fd);
            server_fd = 0;
        }
    }

    int execute() override
    {
        fd_set rfds;
        timeval tv = {0};
        while(true) {
            FD_ZERO(&rfds);
            FD_SET(server_fd, &rfds);
            tv.tv_sec = 1;
            int ret = 0;
            if(!server_fd || (ret = select(server_fd + 1, &rfds, NULL, NULL, &tv)) == -1)
                return EXIT_FAILURE;
            DBG("%d\n", errno);
            if(ret != 0) {
                DBG("%d\n", ret);
            }
            if (FD_ISSET(server_fd, &rfds)) {
                sleep(3);
                sockaddr_in addr = {0};
                socklen_t addrlen = sizeof(addr);
                int client_fd;
                if((client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen)) == -1)
                {
                    return EXIT_FAILURE;
                }

                char buf[8046] = {0};
                recv(client_fd, buf, 8046, 0);
                DBG("%s", buf);
                close(client_fd);
                return EXIT_SUCCESS;
            }
        }
        return EXIT_FAILURE;
    }
};

TEST(HttpTest, DISABLED_ConnectDelayTest)
{
    HttpServerTask serverTask;
    worker_manager::instance()->run_task(&serverTask);

    AmSessionContainer::instance()->postEvent(
        HTTP_EVENT_QUEUE,
        new HttpPostEvent(test_config::instance()->http_destination, "test", ""));

    serverTask.join(5000);
    serverTask.stop();
    serverTask.join();
    EXPECT_EQ(serverTask.ret_, 0);
}
