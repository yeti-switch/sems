#ifndef PACKET_FILTER_TESTER_H
#define PACKET_FILTER_TESTER_H

#include <stdint.h>
#include "../bpf_object.h"

class TestBpf : public BpfObject {
    int  bpf_prog_load() override { return 0; }
    int  bpf_get_fds() override { return 0; }
    void bpf_prog_unload() override {}

    void reuse_shared_memory() override {}
    int  run_prog_allocator(int) override { return 0; }
    int  tc_ingress_cleanup(int, bool) override { return 0; }
    int  tc_ingress_attach(int, bool &) override { return 0; }
    int  configure_L3_map() override { return 0; }
};

class PacketFilterTest : public PacketFilterBpf {
  public:
    TestBpf test_bpf;
    bool    bpf_enable;

    PacketFilterTest();
    ~PacketFilterTest();

    int bpf_test_run(char *buf, unsigned int len, unsigned int &retval, unsigned int &duration);
};

extern PacketFilterTest pf_test;

#endif /*PACKET_FILTER_TESTER_H*/
