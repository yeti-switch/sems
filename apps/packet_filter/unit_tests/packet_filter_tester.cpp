#include "packet_filter_tester.h"
#include "../PacketFilter.h"
#include "ipport2ipport.skel.h"
#include <linux/pkt_cls.h>

PacketFilterTest::PacketFilterTest()
{
    auto pf_bpf = currentBpf;
    PacketFilter::instance();
    currentBpf = &test_bpf;
    if (pf_bpf->bpf_prog_load()) {
        bpf_enable = false;
        return;
    }
    pf_bpf->bpf_get_fds();
    pf_bpf->configure_L3_map();
    size_t   config_size = config_parser();
    unsigned PAGE_SIZE   = getpagesize();
    unsigned pages       = (config_size + PAGE_SIZE - 1) / PAGE_SIZE;

    if (pf_bpf->run_prog_allocator(pages) == -1) {
        bpf_enable = false;
        return;
    }
    pf_bpf->reuse_shared_memory();
    bpf_enable                             = true;
    bpf_prog_filter->data->tc_action_block = TC_ACT_SHOT;
}

PacketFilterTest::~PacketFilterTest() {}

int PacketFilterTest::bpf_test_run(char *buf, unsigned int len, unsigned int &retval, unsigned int &duration)
{
    if (!bpf_prog_filter)
        return -1;

    struct __sk_buff ctx = { 0 };

    struct bpf_test_run_opts opts = {
        .sz            = sizeof(opts),
        .data_in       = buf,
        .data_out      = nullptr,
        .data_size_in  = len,
        .data_size_out = 0,
        .ctx_in        = &ctx,
        .ctx_out       = &ctx,
        .ctx_size_in   = sizeof(ctx),
        .ctx_size_out  = sizeof(ctx),
        .repeat        = 1,
    };

    int bpf_prog_fd = bpf_program__fd(bpf_prog_filter->progs.tc_prog);
    int err         = bpf_prog_test_run_opts(bpf_prog_fd, &opts);
    retval          = opts.retval;
    duration        = opts.duration;
    return err;
}

PacketFilterTest pf_test;
