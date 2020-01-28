#include "netlink.h"
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "log.h"

NetlinkHelper::NetlinkHelper()
{
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        ERROR("error creation netlink socket: %s\n", strerror(errno));
        return;
    }

    int val = 1;
    setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &val, sizeof(int));

    memset(&sa, 0, sizeof(sa));
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = &req;
    sa.nl_family = AF_NETLINK;
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = 0;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        ERROR("error binding with socket: %s\n", (char*)strerror(errno));
        close(fd);
        fd = 0;
        return;
    }
}

NetlinkHelper::~NetlinkHelper()
{
    if (fd > 0) close(fd);
}

NetlinkHelper& NetlinkHelper::instance()
{
    thread_local static NetlinkHelper helper;
    return helper;
}

bool NetlinkHelper::get_local_addr(const sockaddr_storage& dst, sockaddr_storage& local_addr)
{
    route_data data;
    data.dst_sa = dst;
    if(!get_route_data(data)) return false;
    local_addr = data.src_sa;
    return true;
}

bool NetlinkHelper::get_route_data(NetlinkHelper::route_data& data)
{
    if (fd <= 0) return false;

    if (data.dst_sa.ss_family != AF_INET &&
        data.dst_sa.ss_family != AF_INET6)
        return false;

    if (!send_request(data) ||
        !recv_request(data)) {
            close(fd);
            fd = 0;
            return false;
    }
    return true;
}

bool NetlinkHelper::send_request(const route_data& data)
{
    memset(&req, 0, sizeof(req));
    req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nl.nlmsg_flags = NLM_F_REQUEST;
    req.nl.nlmsg_type = RTM_GETROUTE;
    req.nl.nlmsg_seq = time(NULL);

    // set the routing message header
    req.rt.rtm_family = data.dst_sa.ss_family;
    req.rt.rtm_flags = RTM_F_LOOKUP_TABLE;

    struct rtattr*  rta = (struct rtattr*)&req.buf;
    rta->rta_type = RTA_DST;
    if(data.dst_sa.ss_family == AF_INET) {
        rta->rta_len = sizeof(struct rtattr) + sizeof(struct in_addr);
        memcpy(rta + 1, &((sockaddr_in*)&data.dst_sa)->sin_addr, sizeof(struct in_addr));
    } else if(data.dst_sa.ss_family == AF_INET6) {
        rta->rta_len = sizeof(struct rtattr) + sizeof(struct in6_addr);
        memcpy(rta + 1, &((sockaddr_in6*)&data.dst_sa)->sin6_addr, sizeof(struct in6_addr));
    }
    req.nl.nlmsg_len += rta->rta_len;

    iov.iov_len = req.nl.nlmsg_len;
    if(sendmsg(fd, &msg, 0) < 0) {
        ERROR("error sending data to socket: %s\n", (char*)strerror(errno));
        return false;
    }

    return true;
}

bool NetlinkHelper::recv_request(NetlinkHelper::route_data& data)
{
    ssize_t status = recvmsg(fd, &msg, MSG_PEEK | MSG_TRUNC);
    if (status <= 0) {
        ERROR("error recv message by netlink: %s\n", (char*)strerror(errno));
        return false;
    }

    memset(&req, 0, sizeof(req));
    iov.iov_len = req.nl.nlmsg_len = status;

    status = recvmsg(fd, &msg, 0);
    if(status != req.nl.nlmsg_len) {
        return false;
    }

    struct rtattr*  rta = (struct rtattr*)&req.buf;
    rta = (struct rtattr*)&req.buf;
    while (RTA_OK(rta, req.nl.nlmsg_len)) {
        int data_len = rta->rta_len - sizeof(struct rtattr);
        char* pdata = (char *)(rta + 1);
        switch(rta->rta_type) {
            case RTA_DST:
            {
                if(data_len == sizeof(struct in_addr)) {
                    data.dst_sa.ss_family = AF_INET;
                    memcpy(&((struct sockaddr_in*)&data.dst_sa)->sin_addr, pdata, data_len);
                } else if(data_len == sizeof(struct in6_addr)) {
                    data.dst_sa.ss_family = AF_INET6;
                    memcpy(&((struct sockaddr_in6*)&data.dst_sa)->sin6_addr, pdata, data_len);
                }
                break;
            }
            case RTA_TABLE:
            {
                data.table_id = *(int*)pdata;
                break;
            }
            case RTA_PREFSRC:
            {
                if(data_len == sizeof(struct in_addr)) {
                    data.src_sa.ss_family = AF_INET;
                    memcpy(&((struct sockaddr_in*)&data.src_sa)->sin_addr, pdata, data_len);
                } else if(data_len == sizeof(struct in6_addr)) {
                    data.src_sa.ss_family = AF_INET6;
                    memcpy(&((struct sockaddr_in6*)&data.src_sa)->sin6_addr, pdata, data_len);
                }
                break;
            }
            case RTA_OIF:
            {
                data.if_index = *(int*)pdata;
                break;
            }
        }
        rta = RTA_NEXT(rta,req.nl.nlmsg_len);
    }

    return true;
}
