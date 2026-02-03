#include "AmRtpAudio.h"
#include "AmUtils.h"
#include "sip/ip_util.h"

#include <getopt.h>
#include <string.h>
#include <filesystem>
#include <confuse.h>
#include <vector>
#include <tuple>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

using namespace std;

/* options */

static const struct option options[] = {
    {          "help",       no_argument, NULL, 'h' },
    { "streams_count", required_argument, NULL, 'c' },
    {      "interval", required_argument, NULL, 'i' },
    {               0,                 0, NULL,   0 }
};

static void print_usage(char *argv[])
{
    int                   i;
    std::filesystem::path path(argv[0]);

    printf("Usage:\n");
    printf("%s [OPTIONS] <cfg_file>\n", path.filename().c_str());
    printf("Options:\n");
    for (i = 0; options[i].name != 0; i++) {
        printf(" --%-18s", options[i].name);
        printf(" short-option: -%c", options[i].val);
        printf("\n");
    }

    printf("\nConfiguration file example:");
    printf(R"(
    streams {
        # src_hosts = { 127.0.0.1 }
        # dst_hosts = { 127.0.0.1 }
        src_ports = { 20000, 30000-30008 }
        dst_ports = { 50000-50050 }
        iface = eth0
    }
    streams {
        ...
    }
    ...)");
    printf("\n");
}

/* configuration */

#define CFG_SECTION_STREAMS "streams"
#define CFG_SRC_HOSTS       "src_hosts"
#define CFG_DST_HOSTS       "dst_hosts"
#define CFG_SRC_PORTS       "src_ports"
#define CFG_DST_PORTS       "dst_ports"
#define CFG_IFACE           "iface"

char      defaul_hosts[]  = "{ 127.0.0.1 }";
const int defaul_interval = 20; // microsecond

static bool stop{};
static void sig_int(int n)
{
    stop = true;
}

struct streams {
    string         iface;
    vector<string> src_hosts;
    vector<string> dst_hosts;
    vector<int>    src_ports;
    vector<int>    dst_ports;
    vector<int>    sock_fds;
};

vector<struct streams> streams_vec{};

void dump_streams()
{
    for (auto i = 0; i < streams_vec.size(); ++i) {
        auto &s = streams_vec[i];
        printf("%d streams:", i);
        printf("\n  iface: %s", s.iface.c_str());

        printf("\n  src_hosts: ");
        for (auto j = 0; j < s.src_hosts.size(); ++j)
            printf("%s, ", s.src_hosts[j].c_str());

        printf("\n  dst_hosts: ");
        for (auto j = 0; j < s.dst_hosts.size(); ++j)
            printf("%s, ", s.dst_hosts[j].c_str());

        printf("\n  src_ports: ");
        for (auto j = 0; j < s.src_ports.size(); ++j)
            printf("%d, ", s.src_ports[j]);

        printf("\n  dst_ports: ");
        for (auto j = 0; j < s.dst_ports.size(); ++j)
            printf("%d, ", s.dst_ports[j]);

        printf("\n");
    }
}

std::tuple<int, int> parse_port_range(const string &range)
{
    auto pos = range.find('-');
    if (pos == string::npos)
        return { atoi(range.c_str()), 0 };

    return { atoi(range.substr(0, pos).c_str()), atoi(range.substr(pos + 1, std::string::npos).c_str()) };
}

int parse(const char *config)
{
    cfg_opt_t streams_opts[]{ CFG_STR_LIST(CFG_SRC_HOSTS, defaul_hosts, CFGF_NONE),
                              CFG_STR_LIST(CFG_DST_HOSTS, defaul_hosts, CFGF_NONE),
                              CFG_STR_LIST(CFG_SRC_PORTS, 0, CFGF_NONE),
                              CFG_STR_LIST(CFG_DST_PORTS, 0, CFGF_NONE),
                              CFG_STR(CFG_IFACE, "", CFGF_NONE),
                              CFG_END() };

    cfg_opt_t opts[]{ CFG_SEC(CFG_SECTION_STREAMS, streams_opts, CFGF_MULTI), CFG_END() };

    cfg_t *cfg = cfg_init(opts, CFGF_NONE);
    if (!cfg)
        return -1;

    switch (cfg_parse(cfg, config)) {
    case CFG_SUCCESS: break;
    case CFG_PARSE_ERROR:
        fprintf(stderr, "Configuration parse error\n");
        cfg_free(cfg);
        return -1;
    default:
        fprintf(stderr, "Unexpected error on configuration\n");
        cfg_free(cfg);
        return -1;
    }

    // parse streams
    for (auto i = 0; i < cfg_size(cfg, CFG_SECTION_STREAMS); ++i) {
        cfg_t *s_cfg = cfg_getnsec(cfg, CFG_SECTION_STREAMS, i);
        auto  &s     = streams_vec.emplace_back();
        s.iface      = cfg_getstr(s_cfg, CFG_IFACE);

        for (auto j = 0; j < cfg_size(s_cfg, CFG_SRC_HOSTS); ++j)
            s.src_hosts.emplace_back(cfg_getnstr(s_cfg, CFG_SRC_HOSTS, j));

        for (auto j = 0; j < cfg_size(s_cfg, CFG_DST_HOSTS); ++j)
            s.dst_hosts.emplace_back(cfg_getnstr(s_cfg, CFG_DST_HOSTS, j));

        for (auto j = 0; j < cfg_size(s_cfg, CFG_SRC_PORTS); ++j) {
            string p      = cfg_getnstr(s_cfg, CFG_SRC_PORTS, j);
            auto [p1, p2] = parse_port_range(p);
            do {
                s.src_ports.emplace_back(p1++);
            } while (p2 >= p1);
        }

        for (auto j = 0; j < cfg_size(s_cfg, CFG_DST_PORTS); ++j) {
            string p      = cfg_getnstr(s_cfg, CFG_DST_PORTS, j);
            auto [p1, p2] = parse_port_range(p);
            do {
                s.dst_ports.emplace_back(p1++);
            } while (p2 >= p1);
        }
    }

    cfg_free(cfg);
    dump_streams();

    return 0;
}

int fill_sockaddr(const string &host, const int &port, struct sockaddr_storage &sa)
{
    memset(&sa, 0, sizeof(struct sockaddr_storage));

    if (validate_ipv4_addr(host)) {
        struct sockaddr_in *s_addr = (struct sockaddr_in *)&sa;
        s_addr->sin_family         = AF_INET;
        s_addr->sin_port           = htons(port);

        if (inet_pton(AF_INET, host.c_str(), &s_addr->sin_addr) <= 0) {
            fprintf(stderr, "Invalid address %s\n", host.c_str());
            return -1;
        }

        return 0;
    }

    if (validate_ipv6_addr(host)) {
        struct sockaddr_in6 *s_addr = (struct sockaddr_in6 *)&sa;
        s_addr->sin6_family         = AF_INET6;
        s_addr->sin6_port           = htons(port);

        if (inet_pton(AF_INET6, host.c_str(), &s_addr->sin6_addr) <= 0) {
            fprintf(stderr, "Invalid address %s\n", host.c_str());
            return -1;
        }

        return 0;
    }

    return -1;
}

int create_and_bind_dgram_sock(const string &host, const int &port)
{
    struct sockaddr_storage sa;
    if (fill_sockaddr(host, port, sa) < 0)
        return -1;

    int sock_fd = socket(sa.ss_family, SOCK_DGRAM, 0);

    if (sock_fd < 0) {
        fprintf(stderr, "Socket creation failed for [%s:%d]. Error: %s\n", host.c_str(), port, strerror(errno));
        return -1;
    }

    if (bind(sock_fd, (const struct sockaddr *)&sa, SA_len(&sa)) > 0) {
        fprintf(stderr, "Binding failed for [%s:%d]. Error: %s\n", host.c_str(), port, strerror(errno));
        close(sock_fd);
        return -1;
    }

    // printf("Socket %d ready for [%s:%d]\n", sock_fd, host.c_str(), port);

    return sock_fd;
}

int sendto(const int sock_fd, const unsigned char *data, int size, const string &host, const int &port)
{
    struct sockaddr_storage sa;

    if (fill_sockaddr(host, port, sa) < 0)
        return -1;

    if (sendto(sock_fd, data, size, 0, (const struct sockaddr *)&sa, SA_len(&sa)) < 0) {
        fprintf(stderr, "Sending from socket %d to [%s:%d] failed. Error: %s\n", sock_fd, host.c_str(), port,
                strerror(errno));
        return -1;
    }

    // printf("Sending from socket %d to [%s:%d]\n", sock_fd, host.c_str(), port);

    return 0;
}

unsigned int get_timestamp()
{
    return chrono::duration_cast<chrono::seconds>(chrono::system_clock::now().time_since_epoch()).count();
}

int main(int argc, char *argv[])
{
    int                opt{};
    int                streams_count{};
    int                interval = defaul_interval;
    bool               endless_loop{};
    AmRtpPacket        rp;
    char               data[160];
    unsigned long long packets_count{};

    // sig_int
    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    // parse opts
    while ((opt = getopt_long(argc, argv, "hc:i:", options, NULL)) != -1) {
        switch (opt) {
        case 'h': print_usage(argv); exit(0);
        case 'c': streams_count = atoi(optarg); break;
        case 'i': interval = atoi(optarg); break;
        default:  fprintf(stderr, "Unknown option %s\n", argv[optind]); return -EINVAL;
        }
    }

    printf("streams_count: \t %d\n", streams_count);
    endless_loop = (streams_count == 0);

    if (optind < argc) {
        const char *config = argv[argc - 1];
        printf("config \t\t %s\n", config);

        if (access(config, F_OK)) {
            fprintf(stderr, "Couldn't found file: %s \n", config);
            return -ENOENT;
        }

        if (parse(config)) {
            fprintf(stderr, "Parsing config failed: %s \n", config);
            return -ENOENT;
        }

    } else {
        fprintf(stderr, "<cfg_file> arg is absent\n");
        return -EINVAL;
    }

    // create sockets
    for (auto &s : streams_vec)
        for (auto &src_host : s.src_hosts)
            for (auto &src_port : s.src_ports) {
                int sock_fd = create_and_bind_dgram_sock(src_host, src_port);
                if (sock_fd < 0)
                    goto finish;

                s.sock_fds.push_back(sock_fd);
            }

    // flll rtp packet with initial data
    rp.payload   = 0; // PCMU
    rp.marker    = false;
    rp.timestamp = get_timestamp();
    rp.sequence  = 999;
    rp.ssrc      = 1111111111;
    memset(data, '0', sizeof(data));

    // send data
    while (endless_loop || streams_count > 0) {
        for (auto &s : streams_vec)
            for (auto &dst_host : s.dst_hosts)
                for (auto &dst_port : s.dst_ports)
                    for (auto sock_fd : s.sock_fds) {

                        // flll rtp packet and compile
                        rp.timestamp += 160;
                        rp.sequence += 1;
                        rp.compile((unsigned char *)data, strlen((char *)data));

                        if (sendto(sock_fd, rp.getBuffer(), rp.getBufferSize(), dst_host, dst_port) < 0)
                            goto finish;

                        printf("\rPackets count: %llu", ++packets_count);
                        fflush(stdout);
                        usleep(interval);
                        if (stop) {
                            printf("\n");
                            goto finish;
                        }
                    }

        if (!endless_loop)
            --streams_count;
    }

    printf("\n");

finish:
    // close sockets
    for (auto &s : streams_vec)
        for (auto sock_fd : s.sock_fds) {
            // printf("Close %d\n", sock_fd);
            close(sock_fd);
        }

    return 0;
}
