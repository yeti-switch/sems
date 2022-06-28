#include <sys/epoll.h>
#include <netdb.h>
#include <netinet/sctp.h>
#include <algorithm>
#include <cJSON.h>
#include "BusClient.h"
#include "connection.h"
#include "sems.h"
#include "jsonArg.h"

#include <cstring>
#include <string>
#include <lzo/lzo1x.h>

//set upper limit of the uncompressed data to the 20MB
#define MAX_DECOMPRESSED_SIZE (20 << 20)

// added to libsctp/sendmsg.c
// int     sctp_sendv(int s, struct iovec *iov, int iov_len, struct sctp_sndrcvinfo *sinfo, int flags);

uint32_t BusConnection::seq = 0;

static  int
sctp_sendv(int s, struct iovec *iov, int iov_len,
          struct sctp_sndrcvinfo *sinfo, int flags)
{
    struct msghdr outmsg = {0};
    char outcmsg[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))] = {0};

    outmsg.msg_name = NULL;
    outmsg.msg_namelen = 0;
    outmsg.msg_iov = iov;
    outmsg.msg_iovlen = iov_len;
    outmsg.msg_controllen = 0;

    if (sinfo) {
        struct cmsghdr *cmsg;

        outmsg.msg_control = outcmsg;
        outmsg.msg_controllen = sizeof(outcmsg);
        outmsg.msg_flags = 0;

        cmsg = CMSG_FIRSTHDR(&outmsg);
        cmsg->cmsg_level = IPPROTO_SCTP;
        cmsg->cmsg_type = SCTP_SNDRCV;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));

        outmsg.msg_controllen = cmsg->cmsg_len;
        memcpy(CMSG_DATA(cmsg), sinfo, sizeof(struct sctp_sndrcvinfo));
    }

    return sendmsg(s, &outmsg, flags);
}

BusConnection::BusConnection(BusClient *_bus, const sockaddr_storage &_saddr,
                             int _slot, int _reconnect_interval, int _node_id,
                             int _so_rcvbuf, int _so_sndbuf)
:   bus(_bus), saddr(_saddr), slot(_slot), state(Closed),
    reconnect_interval(_reconnect_interval), last_activity(0), node_id(_node_id),
    so_rcvbuf (_so_rcvbuf), so_sndbuf(_so_sndbuf),
    e_send(0), e_recv(0), reconn(0), last_err(0)
{
    INFO("%s(): %s:%d", __func__, am_inet_ntop(&saddr).c_str(), am_get_port(&saddr));

    memset(&connected_time, 0, sizeof(connected_time));
    struct timeval	tv;
    gettimeofday(&tv, NULL);

    node_sign = tv.tv_sec * 1000000ULL + tv.tv_usec;
    node_ver = 0;

    payload.reserve(BUS_SCTP_BUFFER_SIZE);

    connect();
}

BusConnection::~BusConnection()
{
    DBG("~%s()", __func__);
    ::close(fd);
}

bool BusConnection::epoll_link(int op, uint32_t events)
{
    struct epoll_event ev = {0};

    ev.events   = events;
    ev.data.fd  = slot;

    return bus->link(fd, op, ev);
}

void BusConnection::on_timer(uint64_t timer_val)
{
    if( state != Connected
        && timer_val - last_activity > (uint64_t)reconnect_interval ) {
        close();
        connect();
        ++reconn;
    }
}

void BusConnection::send_hello()
{
    char payload[1024] = {0};

    snprintf(payload, sizeof(payload), "Sems-%s", get_sems_version());

    size_t  info_length = strlen(payload),
            pdu_length = sizeof(bus_pdu_hdr_t) + sizeof(bus_pdu_hello_t);

    bus_pdu_t pdu;
    memset(&pdu, 0, sizeof(bus_pdu_t));
    pdu.hdr.magic  = htonl(BUS_MAGIC);
    pdu.hdr.type   = htons(PDU_TYPE_HELLO);
    pdu.hdr.seq = htonl(++seq);
    pdu.hdr.length = htonl(sizeof(bus_pdu_hello) + info_length);

    bus_pdu_hello_t &hello = pdu.hello;
    hello.node_type = BUS_PEER_TYPE_SEMS_NODE;
    hello.node_id   = node_id;
    hello.node_ver  = node_ver;
    hello.node_sign = node_sign;

    int iov_len = 2;
    struct iovec iov[2] = {
        {.iov_base = (void *)&pdu,     .iov_len = pdu_length },
        {.iov_base = (void *)payload,  .iov_len = info_length }
    };

    struct sctp_sndrcvinfo sinfo = {0};

    sinfo.sinfo_assoc_id = assoc_id;

    if (sctp_sendv(fd, iov, iov_len, &sinfo, MSG_NOSIGNAL) < 0)
        ERROR("sctp_send(): %m");
}


void BusConnection::connect()
{
    last_activity = bus->get_timer_val();

    fd = ::socket(saddr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_SCTP);

    if (fd == -1) {
        ERROR("socket(): %m");
        return;
    }

    if (so_rcvbuf && ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf, sizeof(int))  < 0)
        ERROR("setsockopt(SO_RCVBUF): %m");

    if (so_sndbuf && ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &so_sndbuf, sizeof(int)) < 0)
        ERROR("setsockopt(SO_SNDBUF): %m");

    int opt = 1;

    if (::setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &opt, sizeof(int)) < 0) {
        ERROR("setsockopt(SCTP_NODELAY): %m");
        close();
        return;
    }

#if 0
    struct sctp_initmsg initmsg = {};

    initmsg.sinit_num_ostreams = node_id + 1;

    if( ::setsockopt( fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) < 0)
    {
        ERROR("setsockopt(SCTP_INITMSG): %m");
        close();
        return;
    }


    struct sctp_sndrcvinfo info = {};

    info.sinfo_ppid = htonl(PAYLOAD_TYPE_APP_JSON);

    /** SCTP_DEFAULT_SEND_PARAM is DEPRECATED */
    /** for kernel >= 3.17 prefer to use SCTP_DEFAULT_SNDINFO with struct sctp_sndinfo */

    if( ::setsockopt( fd, IPPROTO_SCTP, SCTP_DEFAULT_SEND_PARAM, &info, sizeof(info)) < 0)
    {
        ERROR("setsockopt(SCTP_DEFAULT_SEND_PARAM): %m");
        close();
        return;
    }
#endif

    struct sctp_event_subscribe event = {};
    /** enable all SCTP event notifications */
    // event.sctp_data_io_event            = 1;
    event.sctp_association_event        = 1;
    //event.sctp_address_event          = 1;
    // event.sctp_send_failure_event       = 1;
    // event.sctp_peer_error_event         = 1;
    event.sctp_shutdown_event           = 1;
    // event.sctp_partial_delivery_event   = 1;
    // event.sctp_adaptation_layer_event   = 1;

    if (::setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event)) < 0) {
        ERROR("setsockopt(SCTP_EVENTS): %m");
        close();
        return;
    }

    INFO("%s() fd=%d", __func__, fd);

    state = Connected;

    if (::connect( fd, reinterpret_cast<sockaddr *>(&saddr), SA_len(&saddr)) == -1) {
        if (errno == EINPROGRESS)
            state = Connecting;
        else {
            close();
            return;
        }
    }
    
    
    if(state == Connecting) {
        gettimeofday(&connected_time, 0);
    }
    
    uint32_t events = EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR;

    if (state != Connected)
        events |= EPOLLOUT;

    if (!epoll_link(EPOLL_CTL_ADD, events))
        close();
}


void BusConnection::close()
{
    if (fd != -1)
        ::close(fd);

    fd = -1;
    state = Closed;
    payload.clear();
    last_err = errno;
    memset(&connected_time, 0, sizeof(connected_time));
}


void BusConnection::postError(const string &sess_id, const string &err_str)
{
    map<string, string> params;
    params["error"] = err_str;

    AmArg data;
    data["error"] = err_str;

    DBG("post error reply to: '%s'",sess_id.c_str());
    BusReplyEvent* ev = new BusReplyEvent(BusReplyEvent::Error, params, data);

    if(!AmSessionContainer::instance()->postEvent(sess_id, ev)) {
        DBG("couldn't post to event queue: '%s'",sess_id.c_str());
    }
}

void BusConnection::getInfo(AmArg& ret)
{
    ret["address"] = am_inet_ntop(&saddr);
    ret["port"] = am_get_port(&saddr);
    ret["events_sent"] = (int32_t)e_send;
    ret["events_received"] = (int32_t)e_recv;
    ret["reconnects"] = (int32_t)reconn;
    ret["connected_at"] = timeval2str(connected_time);
    ret["last_err"] = strerror(last_err);
    ret["status"] = state_to_str(state);
}

void BusConnection::postEvent(const string &sess_id, map<string, string> &params, const AmArg &data)
{
    BusReplyEvent* ev = new BusReplyEvent(BusReplyEvent::Success, params, data);
    if(!AmSessionContainer::instance()->postEvent(sess_id, ev)) {
        DBG("couldn't post to event queue: '%s'",sess_id.c_str());
    }
}


void BusConnection::handle_notification(const char *payload, int length)
{
    union sctp_notification     *snp;
    struct sctp_assoc_change    *sac;
    // struct sctp_shutdown_event  *sse;
    // struct sctp_paddr_change    *spc;
    // struct sctp_remote_error    *sre;
    // struct sctp_send_failed     *ssf;

    snp = (union sctp_notification *)payload;

    switch (snp->sn_header.sn_type) {
    case SCTP_ASSOC_CHANGE:
            sac = &snp->sn_assoc_change;
            assoc_id = (uint32_t)sac->sac_assoc_id;

            INFO("SCTP_ASSOC_CHANGE: %d",assoc_id);

            switch (sac->sac_state) {
            case SCTP_COMM_UP:
            case SCTP_RESTART:  send_hello();
                            break;
            case SCTP_COMM_LOST:
            case SCTP_SHUTDOWN_COMP:
            case SCTP_CANT_STR_ASSOC:
            default:;
            }
            break;

    case SCTP_SHUTDOWN_EVENT:
            // sse = &snp->sn_shutdown_event;
            break;

    case SCTP_PEER_ADDR_CHANGE:
    case SCTP_REMOTE_ERROR:
    case SCTP_SEND_FAILED:
    case SCTP_ADAPTATION_INDICATION:
    case SCTP_PARTIAL_DELIVERY_EVENT:
    default:;
    }
}


void BusConnection::hello_handler(bus_pdu_t *pdu, int info_length)
{
    bus_pdu_hello_t *hello = &pdu->hello;

    INFO("HELLO: type=%d id=%u ver=0x%08x sign=0x%016lx info='%.*s'",
        hello->node_type, hello->node_id,
        hello->node_ver, hello->node_sign, info_length, hello + sizeof(struct bus_pdu_hello));
}

string BusConnection::inflatePacked(const char* data, uint32_t data_size)
{
    std::string ret;

    int out_len_int = *(int *)data;
    if(out_len_int <= 0 || out_len_int > MAX_DECOMPRESSED_SIZE) {
        ERROR("inflatePacked(%p, %u): got decompressed size: %d. return empty result",
              data, data_size, out_len_int);
        return ret;
    }

    unsigned long out_len = out_len_int;
    ret.resize(out_len);
    int res = lzo1x_decompress((unsigned char*)data + 4, data_size - 4, (unsigned char*)ret.c_str(), &out_len, 0);
    if(res != LZO_E_OK)
        ret.clear();
    return ret;
}

void BusConnection::pdu_handler(int status, const string &src, const string &dst,
                                const char* body, uint32_t b_size,
                                const char* packed, uint32_t p_size)
{
    map<string, string> params;
    AmArg               event_data;

    if(b_size)
        if (!json2arg(body, event_data))
            ERROR("failed deserialize json payload. body: '%s'",
                  body);

    if(p_size) {
        string conf = inflatePacked(packed, p_size);
        AmArg args;
        if (!json2arg(conf, args))
            ERROR("failed deserialize json payload. packed: '%s'",
                  conf.c_str());
        for(auto& arg : args) {
            event_data[arg.first] = arg.second;
        }
    }
    params["src"] = src;
    params["dst"] = dst;
    params["status"] = std::to_string(status);

    DBG("post reply event. src: '%s', dst: '%s', status: %d",
        src.c_str(),dst.c_str(),status);
    postEvent(dst, params, event_data);
}

static void dump_payload(string &s, const char *payload, int length)
{
    char *c;

    s.reserve(((length/0x10)+1)*((3*0x10)+0x10));
    c = (char *)s.data();

    for(int i = 0; i < length;) {
        c+=sprintf(c,"  0x%02x | ",i);
        int j = 0;
        for(; i < length && j < 0x10; j++,i++) {
            c+=sprintf(c,"%02x ",payload[i]&0xff);
        }

        if(j < length) {
            int n = (0x10-j)*3;
            memset(c,' ',n);
            c+=n;
        }

        *c++ = '|';

        *c++ = '\n';
    }
    *(c++) = 0;
}

void BusConnection::recv()
{
    int                     flags = 0,
                            length;
    struct sockaddr_in6     from;
    socklen_t               fromlen = sizeof (struct sockaddr_in6);
    struct sctp_sndrcvinfo  sinfo;
    char                    buffer[512*1024]; // 512KB

    length = sctp_recvmsg(fd, buffer, sizeof(buffer),
                          (struct sockaddr *)&from, &fromlen, &sinfo, &flags);


    DBG("sctp_recvmsg: got %d bytes from %d", length, fd);

    if (length < 0) {
        ERROR("sctp_recvmsg(): %m");
        payload.clear();

    }

    if (flags & MSG_NOTIFICATION) {
        handle_notification(buffer, length);
        return;
    }

    payload.append(buffer, length);

    if (!(flags & MSG_EOR)) { /// Truncated message received ?
        DBG("Truncated message received(length %ld)", payload.length());
        return;
    }

    /// have got complete message from SCTP layer
    size_t bus_pdu_hdr_t_size = sizeof(bus_pdu_hdr_t);

    if (payload.length() < bus_pdu_hdr_t_size) {
        ERROR("Too short packet %d", length);
        payload.clear();
        return;
    }

    bus_pdu_hdr_t           *hdr = (bus_pdu_hdr_t*)&payload[0];
    if (hdr->magic != htonl(BUS_MAGIC)) {
        ERROR( "Bad magic value 0x%08x (0x%08x expected)", hdr->magic, BUS_MAGIC);
        payload.clear();
        return;
    }

    hdr->type   = htons(hdr->type);
    hdr->status = htons(hdr->status);
    hdr->seq    = htonl(hdr->seq);

    bus_pdu_type_t  type = get_pdu_type(hdr->type);
    bus_pdu_t       *pdu = (bus_pdu_t*)hdr;

    DBG("got PDU with type: %s (0x%04x). PDU length: %d, payload length: %d",
        pdu_type_to_str(type),hdr->type,length,ntohl(hdr->length));
#if 0
    string s;
    dump_payload(s,payload,length);
    DBG("binary dump:\n"
        "         00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n"
        "       +-------------------------------------------------+\n"
        "%s"
        "       +-------------------------------------------------+\n",
        s.data());
#endif

    bool packed = false; 
    switch (type) {
    // case BUS_PDU_HELLO:
    case BUS_PDU_HELLO_RESP: {
            ssize_t length = payload.length();
            length -= (sizeof(bus_pdu_hdr_t) + sizeof(bus_pdu_hello_t));

            if (length >= 0)
                hello_handler(pdu, length);
            else
                ERROR("Bad formated HELLO packet: length=%ld", length);

            break;
    }
    case BUS_PDU_QUERY_PACKED_RESP:
            packed = true;
    case BUS_PDU_QUERY_RESP:
            bus->on_query_response(hdr->seq);
    case BUS_PDU_QUERY:
    case BUS_PDU_QUERY_PACKED:
    case BUS_PDU_EVENT: {
            ssize_t         length = payload.length();
            bus_pdu_query_t &query = pdu->query;
            uint8_t src_length = query.src_length,
                    dst_length = query.dst_length;

            length -= (sizeof(bus_pdu_hdr_t)
                        + (packed ? sizeof(bus_pdu_query_packet_t) : sizeof(bus_pdu_query_t))
                        + src_length + dst_length);

            uint32_t body_length = packed ? htonl(pdu->query_packed.body_length) : length,
                    packed_len = packed ? length - body_length : 0;
            length -= (packed ? body_length : 0);
            DBG("body size: %d packed size: %d", body_length, packed_len);

            if (length < 0) {
                ERROR("Bad formated packet: length=%ld, src_len=%d, dst_len=%d, body_len=%d",
                        length, src_length, dst_length, body_length);
                break;
            }

            string src, dst;
            const char *body = 0, *pack = 0;

            const char* addrs = reinterpret_cast<char *>(&query)
                                + (packed ? sizeof(bus_pdu_query_packet_t) : sizeof(bus_pdu_query_t));
            if(src_length) {
                src.assign(addrs,src_length);
                if(src.back()=='\0') src.resize(src.size()-1);
            }

            addrs += src_length;
            if(dst_length) {
                dst.assign(addrs, dst_length);
                if(dst.back()=='\0') dst.resize(dst.size()-1);
            }

            addrs += dst_length;
            if (body_length) {
                body = addrs;
            }

            addrs += body_length;
            if(packed_len) {
                pack = addrs;
            }

            pdu_handler(hdr->status, src, dst, body, body_length, pack, packed_len);
            ++e_recv;
            break;
    }
    case BUS_PDU_EVENT_RESP:
        DBG("error reply for sent event. "
            "status: %i, seq: %i, length: %i",
            pdu->hdr.status,pdu->hdr.seq,ntohl(pdu->hdr.length));
        break;
    default: {
        string s;
        dump_payload(s,payload.c_str(), payload.length());
        DBG("Received unsupported payload type 0x%04x. "
            "binary dump:\n"
            "         00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n"
            "       +-------------------------------------------------+\n"
            "%s"
            "       +-------------------------------------------------+\n",
            hdr->type,s.data());
    }}

    payload.clear();
}


void print_events(const char *func, uint32_t events)
{

    char buf[128];
    int len = 0;
    buf[0] = 0;

    if(events & EPOLLIN)    len += sprintf(&buf[len],"EPOLLIN ");
    if(events & EPOLLOUT)   len += sprintf(&buf[len],"EPOLLOUT ");
    if(events & EPOLLPRI)   len += sprintf(&buf[len],"EPOLLPRI ");
    if(events & EPOLLERR)   len += sprintf(&buf[len],"EPOLLERR ");
    if(events & EPOLLHUP)   len += sprintf(&buf[len],"EPOLLHUP ");
    if(events & EPOLLRDHUP) len += sprintf(&buf[len],"EPOLLRDHUP ");

    INFO("%s(): 0x%08x %s",  __func__, events, buf);

}


bool BusConnection::sendMsg(BusMsg *msg, uint32_t& msg_seq)
{
    bsaddr_t    src, dst;
    const void  *data;
    size_t      data_size;

    uint16_t status = msg->status;
    struct sctp_sndrcvinfo sinfo = {};

    sinfo.sinfo_assoc_id = assoc_id;

    src.addr = msg->local_tag.c_str();
    src.addr_length = msg->local_tag.length();

    dst.addr = msg->application_method.c_str();
    dst.addr_length = msg->application_method.length();

    data = msg->body.c_str();
    data_size = msg->body.length();

    uint8_t     src_length = src.addr_length;
    uint8_t     dst_length = dst.addr_length;

    src_length += !!src_length; // append 0
    dst_length += !!dst_length; // append 0

    int type, pdu_len;
    if(msg->is_query) {
        type = PDU_TYPE_QUERY_PACKED;
        pdu_len = sizeof(bus_pdu_query_packet_t);
    } else {
        type = PDU_TYPE_EVENT;
        pdu_len = sizeof(bus_pdu_event_t);
    }
    bus_pdu_t pdu = {
                .hdr = {
                    .magic  = htonl(BUS_MAGIC),
                    .type   = htons(type),
                },
            };

    pdu.hdr.status = htons(status);
    pdu.hdr.seq    = htonl(++seq);
    pdu.hdr.length = htonl(src_length + dst_length + data_size + pdu_len);
    msg_seq = seq;

    pdu.query.src_length = src_length;
    pdu.query.dst_length = dst_length;
    pdu.query_packed.body_length = htonl(data_size);

    uint32_t    length = sizeof(bus_pdu_hdr_t) + pdu_len;

    int iov_len = 4;
    struct iovec iov[4] = {
                { .iov_base = (void *)&pdu,         .iov_len = length },
                { .iov_base = (void *)src.addr,     .iov_len = src_length },
                { .iov_base = (void *)dst.addr,     .iov_len = dst_length },
                { .iov_base = (void *)data,         .iov_len = data_size },
    };

    iov_len -= !data_size;

    DBG("BUS_%s: %.*s: %.*s",
        msg->is_query ? "QUERY" : "EVENT",
        (int)dst.addr_length, (char *)dst.addr,
        (int)data_size, (char *)data);

    if (sctp_sendv(fd, iov, iov_len, &sinfo, SCTP_UNORDERED | MSG_NOSIGNAL) < 0) {
        ERROR("sctp_send(): %m");
        return false;
//        postError(msg->local_tag, "Bus send error");
    }
    
    ++e_send;
    return true;
}


void BusConnection::handler(uint32_t ev)
{
    if (ev & ~(EPOLLIN | EPOLLOUT)) {
        int err = 0;
        socklen_t len = sizeof(err);

        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);

        ERROR("NETWORK: fd=%d %s [%s]:%u",
            fd,
            err ? strerror(err) : "Peer shutdown",
            am_inet_ntop(&saddr).c_str(), am_get_port(&saddr));

        close();
        return;
    }

    if (ev & EPOLLIN)
        recv();

    if (ev & EPOLLOUT) {
        state = Connected;

        gettimeofday(&connected_time, 0);
        
        INFO("%s() fd=%d connected [%s]:%u", __func__, fd, am_inet_ntop(&saddr).c_str(), am_get_port(&saddr) );

        if (!epoll_link(EPOLL_CTL_MOD, EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR))
            close();
    }
}
