#include "SctpServerConnection.h"
#include "SctpBusEventRequest.pb.h"

#include "sip/ip_util.h"

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

#include "AmUtils.h"
#include "jsonArg.h"
#include "AmSessionContainer.h"

int SctpServerConnection::init(int efd, const sockaddr_storage &a)
{
    int opt = 1;
    struct sctp_event_subscribe event = {};

    clients.clear();

    set_addr(a);
    set_epoll_fd(efd);

    DBG("bind sctp socket to: %s:%d",am_inet_ntop(&addr).c_str(),am_get_port(&addr));

    if((fd = socket( AF_INET, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_SCTP)) < 0 )
        sctp_sys_err("socket()");

    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        sctp_sys_err("setsockopt(SO_REUSEADDR)");

#ifdef SO_REUSEPORT // (since Linux 3.9)
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        sctp_sys_err("setsockopt(SO_REUSEPORT)");
#endif

    if(sctp_bindx(fd,(struct sockaddr *)&addr, 1, SCTP_BINDX_ADD_ADDR) < 0)
        sctp_sys_err("sctp_bindx()");

    /** enable all SCTP event notifications */
    event.sctp_data_io_event        = 1;
    event.sctp_association_event    = 1;
    //event.sctp_address_event        = 1;
    event.sctp_send_failure_event   = 1;
    event.sctp_peer_error_event     = 1;
    event.sctp_shutdown_event       = 1;
    event.sctp_partial_delivery_event = 1;
    event.sctp_adaptation_layer_event = 1;

    if(setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event)) < 0)
        sctp_sys_err("setsockopt(IPPROTO_SCTP)");

    if(listen(fd, 20) != 0)
        sctp_sys_err("listen()");

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data = {
            .fd = fd
        }
    };

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1)
        sctp_sys_err("epoll_ctl(EPOLL_CTL_ADD)");

    return 0;
}

void SctpServerConnection::handle_notification(const sockaddr_storage &from)
{
    const char *str;
    const auto sn = (sctp_notification *)payload;

    switch(sn->sn_header.sn_type) {
    case SCTP_ASSOC_CHANGE: {
        const auto &sac = sn->sn_assoc_change;
        switch(sac.sac_state) {
        case SCTP_COMM_UP:
            str = "COMMUNICATION UP";
            INFO("associated with %s:%u/%d (%d)",
                 am_inet_ntop(&from).c_str(),am_get_port(&from),
                 sac.sac_assoc_id,fd);
            clients_mutex.lock();
            clients.emplace(sac.sac_assoc_id,
                            client_info(
                               am_inet_ntop(&from),
                                am_get_port(&from)));
            clients_mutex.unlock();
            break;
        case SCTP_COMM_LOST:
            str = "COMMUNICATION LOST";
            clients_mutex.lock();
            clients.erase(sac.sac_assoc_id);
            clients_mutex.unlock();
            break;
        case SCTP_RESTART:
            str = "RESTART";
            break;
        case SCTP_SHUTDOWN_COMP:
            str = "SHUTDOWN COMPLETE";
            clients_mutex.lock();
            clients.erase(sac.sac_assoc_id);
            clients_mutex.unlock();
            break;
        case SCTP_CANT_STR_ASSOC:
            str = "CANT START ASSOC";
            ERROR("SCTP_CANT_STR_ASSOC, assoc=%u",sac.sac_assoc_id);
        default:
            str = "UNKNOWN";
        } //switch(sac.sac_state)
        DBG("SCTP_ASSOC_CHANGE: %s, assoc=%u",str,sac.sac_assoc_id);
    } break; //case SCTP_ASSOC_CHANGE
    case SCTP_PEER_ADDR_CHANGE: {
        const auto &spc = sn->sn_paddr_change;
        switch(spc.spc_state) {
        case SCTP_ADDR_AVAILABLE:
            str = "ADDRESS AVAILABLE";
            break;
        case SCTP_ADDR_UNREACHABLE:
            str = "ADDRESS UNAVAILABLE";
            break;
        case SCTP_ADDR_REMOVED:
            str = "ADDRESS REMOVED";
            break;
        case SCTP_ADDR_ADDED:
            str = "ADDRESS ADDED";
            break;
        case SCTP_ADDR_MADE_PRIM:
            str = "ADDRESS MADE PRIMARY";
            break;
        default:
            str = "UNKNOWN";
        } //switch(spc.spc_state)
        DBG("SCTP_PEER_ADDR_CHANGE: %s, assoc=%u",str,spc.spc_assoc_id);
    } break; //case SCTP_PEER_ADDR_CHANGE
    case SCTP_REMOTE_ERROR: {
        const auto &sre = sn->sn_remote_error;
        ERROR("SCTP_REMOTE_ERROR: assoc=%u", sre.sre_assoc_id);
    } break;
    case SCTP_SEND_FAILED: {
        const auto &ssf = sn->sn_send_failed;
        ERROR("SCTP_SEND_FAILED: assoc=%u", ssf.ssf_assoc_id);
    } break;
    case SCTP_ADAPTATION_INDICATION: {
        const auto &ae = sn->sn_adaptation_event;
        DBG("SCTP_ADAPTATION_INDICATION bits:0x%x", ae.sai_adaptation_ind);
    } break;
    case SCTP_PARTIAL_DELIVERY_EVENT: {
        const auto &pdapi = sn->sn_pdapi_event;
        DBG("SCTP_PD-API event:%u", pdapi.pdapi_indication);
        if(pdapi.pdapi_indication == 0)
            DBG("PDI- Aborted");
    } break;
    case SCTP_SHUTDOWN_EVENT: {
        const auto &sse = sn->sn_shutdown_event;
        DBG("SCTP_SHUTDOWN_EVENT: assoc=%u", sse.sse_assoc_id);
        clients_mutex.lock();
        clients.erase(sse.sse_assoc_id);
        clients_mutex.unlock();
    } break;
    default:
        ERROR("Unknown notification event type=%xh",sn->sn_header.sn_type);
    } //switch(snp->sn_header.sn_type)
}

void SctpServerConnection::process(uint32_t events)
{
    int flags = 0, length;
    struct sctp_sndrcvinfo  sinfo;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(struct sockaddr);

    length = sctp_recvmsg(fd, payload, sizeof(payload)-1,
                          (struct sockaddr *)&from,
                          &fromlen,
                          &sinfo,
                          &flags);

    if( length < 0 ) {
        ERROR("sctp_recvmsg(): %m");
        return;
    }

    if(0/*reject condition*/) {
        ERROR("not allowed from %s",am_inet_ntop(&from).c_str());
        sinfo.sinfo_flags = SCTP_EOF;
        sctp_send(fd, NULL, 0, &sinfo, MSG_NOSIGNAL);
    }

    if(flags & MSG_NOTIFICATION) {
        handle_notification(from);
        return;
    }

    // catch only FULL SIZE message
    //!TODO: implement fragments reassembling
    if(!(flags & MSG_EOR) ) {
        ERROR("Truncated message received");
        return;
    }

    SctpBusEventRequest r;
    if(!r.ParseFromArray(payload,length)){
        ERROR("failed deserialize request");
        return;
    }

    DBG("RECV sctp_bus event %d:%s -> %d:%s/%d",
        r.src_node_id(),
        r.src_session_id().c_str(),
        r.dst_node_id(),
        r.dst_session_id().c_str(),
        sinfo.sinfo_assoc_id);

    clients_mutex.lock();
    ClientsMap::iterator it = clients.find(sinfo.sinfo_assoc_id);
    if(it!=clients.end()) {
        it->second.last_node_id =  r.src_node_id();
        it->second.events_received++;
    }
    clients_mutex.unlock();

    if(!AmConfig::node_id) {
        WARN("node_id is 0 (default value). this may cause not intended behavior");
    }

    SctpBusEvent *ev = new SctpBusEvent(r.src_node_id(), r.src_session_id());
    if(!json2arg(r.json_data(),ev->data)){
        ERROR("failed deserialize json payload");
        delete ev;
        return;
    }

    //DBG("received event data: %s",r.json_data().c_str());
    if(!AmSessionContainer::instance()->postEvent(r.dst_session_id(),ev)) {
        DBG("failed to post SctpBusEvent for session: %s",
            r.dst_session_id().c_str());
    }
}

void SctpServerConnection::getInfo(AmArg &ret)
{
    clients_mutex.lock();
    for(const auto &client : clients) {
        ret.push(AmArg());
        AmArg &c = ret.back();
        const client_info &info = client.second;
        c["assoc_id"] = client.first;
        c["remote_host"] = info.host;
        c["remote_port"] = info.port;
        c["last_node_id"] = info.last_node_id;
        c["events_received"] = info.events_received;
    }
    clients_mutex.unlock();
}
