#include <gtest/gtest.h>
#include <AmLCContainers.h>
#include <sip/ip_util.h>
#include "../WorkersManager.h"

#include <thread>
#include <mutex>
#include <chrono>
#include <unordered_set>

void freePortBordersTest(unsigned short low, unsigned short high)
{
    std::set<unsigned short> rtp_ports, rtcp_ports;

    RTP_info info(low, high);
    GTEST_ASSERT_EQ(info.prepare("test"), 0);

    sockaddr_storage ss;
    for (int i = low; i < high; i += 2) {
        fflush(stdout);
        ASSERT_TRUE(info.getNextRtpAddress(ss));
        int port = am_get_port(&ss);

        GTEST_ASSERT_EQ(rtp_ports.count(port), 0);      // check RTP port for uniqueness
        GTEST_ASSERT_EQ(rtcp_ports.count(port + 1), 0); // check RTCP port for uniqueness

        rtp_ports.emplace(port);
        rtcp_ports.emplace(port + 1);
    }

    // check all ports are considered used
    info.iterateUsedPorts([&rtp_ports, &rtcp_ports](const std::string &addr, unsigned short rtp, unsigned short rtcp) {
        GTEST_ASSERT_EQ(rtp_ports.count(rtp), 1);
        GTEST_ASSERT_EQ(rtcp_ports.count(rtcp), 1);
    });

    // free ports
    for (auto p : rtp_ports) {
        am_set_port(&ss, p);
        info.freeRtpAddress(ss);
    }

    // check all ports are free
    bool has_used_ports = false;
    info.iterateUsedPorts(
        [&has_used_ports](const std::string &addr, unsigned short rtp, unsigned short rtcp) { has_used_ports = true; });

    ASSERT_FALSE(has_used_ports);
}

TEST(Config, MediaFreePortBorders)
{
    freePortBordersTest(2, -1);
    freePortBordersTest(27514, 32767);
    freePortBordersTest(27520, 32767);
    freePortBordersTest(27520, 32749);
    freePortBordersTest(27520, 27539);
}

void freePortAvoidFreshlyFreedTest(unsigned short low, unsigned short high)
{
    int port;

    RTP_info info(low, high);
    GTEST_ASSERT_EQ(info.prepare("test"), 0);

    sockaddr_storage ss;

    EXPECT_TRUE(info.getNextRtpAddress(ss));
    port = am_get_port(&ss);
    GTEST_ASSERT_EQ(port, low);

    info.freeRtpAddress(ss);

    EXPECT_TRUE(info.getNextRtpAddress(ss));
    port = am_get_port(&ss);
    GTEST_ASSERT_NE(port, low);
}

TEST(Config, MediaFreePortAvoidFreshlyFreed)
{
    freePortAvoidFreshlyFreedTest(64, 255);
}

TEST(Config, MediaFreePortAquireOrdering)
{
    int port;
    int low  = 64;
    int high = 255;

    RTP_info info(low, high);
    info.prepare("test");

    int start = low >> 6;
    int end   = (high >> 6) + !!(high % 64);

    int free_ports_left = high - low;

    int adresses = end - start;

    int expected_ports[adresses];
    for (int i = 0; i < adresses; i++) {
        expected_ports[i] = start * 64 + i * 64;
    }

    sockaddr_storage ss;
    do {
        for (int j = 0; j < adresses; j++) {
            EXPECT_TRUE(info.getNextRtpAddress(ss));
            port = am_get_port(&ss);

            if (free_ports_left > 0) {
                GTEST_ASSERT_NE(port, 0);
            }

            GTEST_ASSERT_EQ(expected_ports[j], port);
            expected_ports[j] += 2;

            free_ports_left -= 2;
        }
    } while (free_ports_left > 0);

    EXPECT_FALSE(info.getNextRtpAddress(ss));
}

bool rand_bool()
{
    int g = std::rand();
    return (g % 2); // 1 is converted to true and 0 as false
}

TEST(Config, AccuireReleaseMediaPorts)
{
    std::srand(time(0));

    int low  = 64;
    int high = 65535;

    RTP_info port_map(low, high);
    port_map.prepare("test");

    int start = low >> 6;
    int end   = (high >> 6) + !!(high % 64);

    DBG("start %d end %d", start, end);

    int aq_threads_count = 100;
    int rm_threads_count = 100;
    int aq_count         = (end - start) * 8;
    int rm_count         = (end - start);

    std::mutex               m;
    std::unordered_set<int>  aquired_ports, port_map_used_ports;
    std::vector<std::thread> threads;

    DBG("start %d threads with %d aquires for range %d-%d", aq_threads_count, aq_count, low, high);

    for (int i = 0; i < aq_threads_count; ++i) {
        threads.emplace_back([&]() {
            int              port;
            sockaddr_storage ss;
            for (int i = aq_count; i; --i) {
                if (port_map.getNextRtpAddress(ss)) {
                    port = am_get_port(&ss);

                    m.lock();
                    aquired_ports.emplace(port);
                    m.unlock();
                    // DBG(" >> aquire %d", port);
                }
            }
        });
    }

    DBG("start %d threads with %d release for range %d-%d", rm_threads_count, rm_count, low, high);

    for (int i = 0; i < rm_threads_count; ++i) {
        threads.emplace_back([&]() {
            int              port;
            sockaddr_storage ss;
            for (int i = rm_count; i; --i) {

                m.lock();
                auto it = aquired_ports.begin();
                if (it != aquired_ports.end()) {
                    port = *it;
                    aquired_ports.erase(it);
                    m.unlock();
                } else {
                    WARN("aquired_ports is empty");
                    m.unlock();
                    break;
                }


                // DBG("remove %d << ", port);
                am_set_port(&ss, port);
                port_map.freeRtpAddress(ss);
            }
        });
    }

    for (auto &t : threads)
        t.join();

    port_map.iterateUsedPorts([&](const std::string &address, unsigned short port1, unsigned short port2) {
        port_map_used_ports.emplace(port1);
    });

    INFO("compare resulst");
    INFO("  aquired_ports.size() == %d", aquired_ports.size());
    INFO("  port_map_used_ports.size() == %d", port_map_used_ports.size());
    GTEST_ASSERT_EQ(aquired_ports, port_map_used_ports);
}

TEST(Config, FillPoolMediaPorts)
{
    std::srand(time(0));

    int low  = 64;
    int high = 65535;

    RTP_info port_map(low, high);
    port_map.prepare("test");

    int start = low >> 6;
    int end   = (high >> 6) + !!(high % 64);

    DBG("start %d end %d", start, end);

    int aq_count = (end - start) * 32 + 1; // fill pool
    int rm_count = (end - start) * 32;

    std::mutex              m;
    std::unordered_set<int> aquired_ports, port_map_used_ports;

    for (int i = 3; i; --i) {
        int              port;
        sockaddr_storage ss;
        DBG("start aquiring of %d items in %d-%d range", aq_count, low, high);
        for (int i = aq_count; i; --i) {
            if (port_map.getNextRtpAddress(ss)) {
                port = am_get_port(&ss);

                m.lock();
                aquired_ports.emplace(port);
                m.unlock();
                // DBG("aquire %d", port);
            } else {
                DBG("pool is full");
            }
        }

        DBG("start releasing of %d items in %d-%d range", rm_count, low, high);
        for (int i = rm_count; i; --i) {

            m.lock();
            auto it = aquired_ports.begin();
            if (it != aquired_ports.end()) {
                port = *it;
                aquired_ports.erase(it);
                m.unlock();
            } else {
                WARN("aquired_ports is empty");
                m.unlock();
                break;
            }


            // DBG("remove %d", port);
            am_set_port(&ss, port);
            port_map.freeRtpAddress(ss);
        }
    }

    port_map.iterateUsedPorts([&](const std::string &address, unsigned short port1, unsigned short port2) {
        port_map_used_ports.emplace(port1);
    });

    INFO("compare resulst");
    INFO("  aquired_ports.size() == %d", aquired_ports.size());
    INFO("  port_map_used_ports.size() == %d", port_map_used_ports.size());
    GTEST_ASSERT_EQ(aquired_ports, port_map_used_ports);
}

TEST(Config, DISABLED_MediaAquireOrderingMultithreaded)
{
    int low  = 1024;
    int high = 10001;

    int threads_count = 10;
    // int aquires_count = 50;
    int aquires_count = 500;

    RTP_info port_map(low, high);
    port_map.prepare("test");

    std::mutex                                   m;
    std::vector<std::pair<std::thread::id, int>> aquired_ports;
    std::map<int, int>                           ports_distribution;

    DBG("start %d threads with %d aquires for range %d-%d", threads_count, aquires_count, low, high);

    std::vector<std::thread> threads;
    for (int i = 0; i < threads_count; i++) {
        threads.emplace_back([&]() {
            int              port;
            sockaddr_storage ss;
            std::list<int>   delayed_ports_free;

            // std::this_thread::sleep_for(std::chrono::milliseconds(100));

            for (int i = aquires_count; i; i--) {
                if (port_map.getNextRtpAddress(ss)) {
                    // std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    port = am_get_port(&ss);
                    delayed_ports_free.emplace_back(port);
                    if (delayed_ports_free.size() > 2) {
                        am_set_port(&ss, *delayed_ports_free.begin());
                        port_map.freeRtpAddress(ss);
                    }
                } else {
                    port = -1;
                }
                std::lock_guard<std::mutex> l(m);
                aquired_ports.emplace_back(std::this_thread::get_id(), port);
                ports_distribution[port]++;
                // std::this_thread::yield();
            }
        });
    }

    for (auto &t : threads)
        t.join();

    DBG("ports allocations: %zd", aquired_ports.size());
    for (auto &ap : aquired_ports) {
        std::cout << "0x" << std::hex << ap.first << ": " << std::dec << ap.second << std::endl;
    }
    DBG("distribution size: %zd (pool size: %d)", ports_distribution.size(), (high - low + 1) / 2);
    for (auto &it : ports_distribution) {
        std::cout << it.first << ": " << it.second << std::endl;
    }
}
