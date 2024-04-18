#include "../Config.h"
#include <sip/ws_trsp.h>
#include <AmLcConfig.h>
#include <gtest/gtest.h>
#include <string>
#include <AmSipDialog.h>
#include <sip/sip_parser.h>

using std::string;

class ws_input_test : public ws_input
{
public:
    ws_input_test(ws_output* output, bool server) : ws_input(output, server){}

    void on_parsed_received_msg(tcp_base_trsp * socket, sip_msg * s_msg) override
    {
        if(is_connected()) {
            if(is_server) {
                char data[] = "SIP/2.0 200 OK\r\n"
                            "Via: SIP/2.0/UDP test.com:5060;branch=kjkjsd54df>\r\n"
                            "To: Ivan Ivanov <sip:ivan@test.com>\r\n"
                            "From: Petr Petrov <sip:petr@test.com>;tag=1456\r\n"
                            "Call-ID: 214df25df\r\n"
                            "CSeq: 1 INVITE\r\n"
                            "Contact: <sip:ivan@test.com>\r\n"
                            "Content-Type: application/sdp\r\n"
                            "Content-Length: 0\r\n\r\n";
                sockaddr_storage sa;
                dynamic_cast<ws_trsp_socket*>(output)->copy_peer_addr(&sa);
                dynamic_cast<ws_trsp_socket*>(output)->send(&sa, data, sizeof(data), 0);
                return;
            } else {
                output->on_ws_close();
                return;
            }
        }
        ws_input::on_parsed_received_msg(socket, s_msg);
    }
};

class ws_trsp_test : public ws_trsp_socket
{
    void on_ws_close() override
    {
        ws_trsp_socket::on_ws_close();
        event_base_loopbreak(evbase);
    }
public:
    ws_trsp_test(trsp_server_socket* server_sock, trsp_worker* server_worker, int sd,
                    const sockaddr_storage* sa, socket_transport transport, event_base* evbase)
    : ws_trsp_socket(server_sock, server_worker, sd, sa, transport, evbase) {
        input = new ws_input_test(this, sd != -1);
    }
};

class ws_factory_test : public trsp_socket_factory
{
public:
    ws_factory_test(tcp_base_trsp::socket_transport transport)
    : trsp_socket_factory(transport)
    {}

    tcp_base_trsp* create_socket(trsp_server_socket* server_sock, trsp_worker* server_worker,
                                                    int sd, const sockaddr_storage* sa, event_base* evbase)
    {
        return new ws_trsp_test(server_sock, server_worker, sd, sa, transport, evbase);
    }
};

class ws_server_test : public trsp_server_socket
{
public:
    ws_server_test()
    : trsp_server_socket(0, 0, 0, new ws_factory_test(trsp_socket::socket_transport::ws_ipv4),
                         new stream_statistics::stream_st_base(trsp_socket::socket_transport::ws_ipv4, 0, 0))
    {
        
    }

    const char* get_transport() const override{ return "ws"; }
};

TEST(TransportTest, WebSocket)
{
    unsigned int idx = AmConfig.sip_if_names[test_config::instance()->signalling_interface];
    string ip;
    if(AmConfig.sip_ifs[idx].proto_info.size()) ip = AmConfig.sip_ifs[idx].proto_info[0]->getIP();
    ASSERT_FALSE(ip.empty());

    trsp_worker worker;
    worker.start();
    trsp trsp_server;

    ws_server_test server;
    server.set_idle_timeout(DEFAULT_IDLE_TIMEOUT);
    server.set_connect_timeout(DEFAULT_TCP_CONNECT_TIMEOUT);
    ASSERT_FALSE(server.bind(ip, AmConfig.sip_ifs[idx].proto_info[0]->local_port) < 0);
    trsp_worker* workers = &worker;
    server.add_workers(&workers, 1);
    trsp_server.add_socket(&server);
    
    trsp_server.start();

    sockaddr_storage sa;
    server.copy_addr_to(&sa);
    char data[] = "INVITE sip:ivan@test.com SIP/2.0\r\n"
                  "Via: SIP/2.0/UDP test.com:5060;branch=kjkjsd54df>\r\n"
                  "To: Ivan Ivanov <sip:ivan@test.com>\r\n"
                  "From: Petr Petrov <sip:petr@test.com>;tag=1456\r\n"
                  "Call-ID: 214df25df\r\n"
                  "CSeq: 1 INVITE\r\n"
                  "Contact: <sip:ivan@test.com>\r\n"
                  "Content-Type: application/sdp\r\n"
                  "Content-Length: 0\r\n\r\n";
    worker.send(&server, &sa, data, sizeof(data), 0);
    worker.join();
}
