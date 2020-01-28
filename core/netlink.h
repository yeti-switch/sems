#ifndef NETLINK_H
#define NETLINK_H

#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <string>

class NetlinkHelper
{
    int fd;
    struct sockaddr_nl	sa;
    struct msghdr msg;
	struct iovec iov;
    struct {
        struct nlmsghdr nl;
        struct rtmsg    rt;
        char            buf[8192];
    } req;
    NetlinkHelper();
public:
    ~NetlinkHelper();

    static NetlinkHelper& instance();

    struct route_data{
        sockaddr_storage dst_sa; //in/out
        sockaddr_storage src_sa; //out
        int table_id;            //out
        int if_index;            //out
    };

    bool get_local_addr(const sockaddr_storage &dst, sockaddr_storage &local_addr);
    bool get_route_data(route_data& data);

private:
    bool send_request(const route_data& data);
    bool recv_request(route_data& data);
};

#endif/*NETLINK_H*/
