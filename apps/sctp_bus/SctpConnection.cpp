#include "SctpConnection.h"
#include "AmSessionContainer.h"

#include <sys/epoll.h>

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/sctp.h>

SctpConnection::SctpConnection()
  : fd(-1),
    epoll_fd(-1),
    _id(0),
    state(Closed),
    last_cseq(0)
{
    bzero(&addr, sizeof(sockaddr_storage));
}

SctpConnection::~SctpConnection()
{
    DBG("%s()",FUNC_NAME);
    close();
}

int SctpConnection::sctp_recvmsg(int s, void *msg, size_t len, struct sockaddr *from,
    socklen_t *fromlen, struct sctp_sndrcvinfo *sinfo,
    int *msg_flags)
{
    int error;
    struct iovec iov;
    struct msghdr inmsg;
    char incmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
    struct cmsghdr *cmsg = NULL;

    memset(&inmsg, 0, sizeof (inmsg));

    iov.iov_base = msg;
    iov.iov_len = len;

    inmsg.msg_name = from;
    inmsg.msg_namelen = fromlen ? *fromlen : 0;
    inmsg.msg_iov = &iov;
    inmsg.msg_iovlen = 1;
    inmsg.msg_control = incmsg;
    inmsg.msg_controllen = sizeof(incmsg);

    error = recvmsg(s, &inmsg, msg_flags ? *msg_flags : 0);
    if (error < 0)
        return error;

    if (fromlen)
        *fromlen = inmsg.msg_namelen;
    if (msg_flags)
        *msg_flags = inmsg.msg_flags;

    if (!sinfo)
        return error;

    for (cmsg = CMSG_FIRSTHDR(&inmsg); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&inmsg, cmsg))
    {
        if ((IPPROTO_SCTP == cmsg->cmsg_level) &&
            (SCTP_SNDRCV == cmsg->cmsg_type))
            break;
    }

    /* Copy sinfo. */
    if (cmsg)
        memcpy(sinfo, CMSG_DATA(cmsg), sizeof(struct sctp_sndrcvinfo));

    return (error);
}


int SctpConnection::close()
{
    if(-1==fd) return fd;

    DBG("close connection with id %d, socket: %d",_id,fd);

    /*if(-1!=epoll_fd) {
        if(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL) == -1)
            WARN("epoll_ctl(EPOLL_CTL_DEL,%d): %m",fd);
    }*/

    //::shutdown(fd, SHUT_RDWR);
    int old_fd = fd;

    ::close(fd);
    fd = -1;

    state = Closed;

    if(!event_sink.empty()) {
        AmSessionContainer::instance()->postEvent(
            event_sink,
            new SctpBusConnectionStatus(_id, SctpBusConnectionStatus::Closed));
    }

    return old_fd;
}

