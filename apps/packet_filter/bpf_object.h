#ifndef BPF_OBJECT_H
#define BPF_OBJECT_H

#include <bpf/bpf.h>
#include "shared_struct.h"
#include "AmLCContainers.h"

struct BpfObject {
    virtual ~BpfObject() {}

    virtual int  bpf_prog_load()   = 0;
    virtual int  bpf_get_fds()     = 0;
    virtual void bpf_prog_unload() = 0;

    virtual void reuse_shared_memory()                              = 0;
    virtual int  run_prog_allocator(int pages_num)                  = 0;
    virtual int  tc_ingress_cleanup(int ifindex, bool hook_created) = 0;
    virtual int  tc_ingress_attach(int ifindex, bool &hook_created) = 0;
    virtual int  configure_L3_map()                                 = 0;
};

class PacketFilterBpf : private BpfObject {
  protected:
    int   config_v4_map;
    int   config_v6_map;
    int   L3_dev_map;
    int   ipport2ipport_ipv4_cnt_map;
    int   ipport2ipport_ipv6_cnt_map;
    char *shared_mem;

    struct arena_allocator *bpf_prog_allocator;
    struct ipport2ipport   *bpf_prog_filter;
    int                     bpf_prog_filter_fd;
    uint32_t                bpf_prog_filter_id;

    typedef enum {
        RANGE_OP_PORT_UNBIND = 0,
        RANGE_OP_PORT_BIND   = 1,
    } range_op_t;

    std::vector<port_range> ranges;
    std::map<int, bool>     tc_ifs; /** interfaces the filter attached to */

  private:
    int  bpf_prog_load() override;
    int  bpf_get_fds() override;
    void bpf_prog_unload() override;

    int  run_prog_allocator(int pages_num) override;
    void reuse_shared_memory() override;
    int  tc_ingress_cleanup(int ifindex, bool hook_created) override;
    int  tc_ingress_attach(int ifindex, bool &hook_created) override;
    int  configure_L3_map() override;

  protected:
    bool   config_update_ranges(off_t &config_offs, MEDIA_info *proto, PortMap &portmap);
    size_t config_parser();

    void range_op(range_op_t op, port_range &range, uint16_t port);
    void onPortBind(unsigned range_n, uint16_t port);
    void onPortUnbind(unsigned range_n, uint16_t port);

  public:
    PacketFilterBpf();
    ~PacketFilterBpf();
};

extern BpfObject *currentBpf;

#endif /*BPF_OBJECT_H*/
