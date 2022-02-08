#include <gtest/gtest.h>
#include <IPTree.h>
#include <sip/ip_util.h>

TEST(Common, IPTree)
{
    IPTree tree;
    AmSubnet subnet;
    sockaddr_storage addr;
    IPTree::MatchResult match_result;

    subnet.parse("10.255.0.2");
    tree.addSubnet(subnet, 0x3);
    tree.addSubnet(subnet, 0x3); //test double add
    tree.addSubnet(subnet, 0x4); //test collision

    subnet.parse("10.255.0.0/26");
    tree.addSubnet(subnet, 0x2);

    subnet.parse("10.255.0.0/16");
    tree.addSubnet(subnet, 0x1);

    subnet.parse("0.0.0.0/0");
    tree.addSubnet(subnet, 0x0);

    //any addr
    memset(&addr,0,sizeof(sockaddr_storage));
    am_inet_pton("10.255.0.2", &addr);

    //match ip against IP binary tree
    tree.match(addr, match_result);

    EXPECT_EQ(match_result.size(),5);
    //check result indexes ordering
    for(int i = 0; i < 5; i++) {
        EXPECT_EQ(match_result[i],i);
    }

    //IPv6
    subnet.parse("dead:beef::1");
    tree.addSubnet(subnet, 0x2);

    subnet.parse("::0/0");
    tree.addSubnet(subnet, 0x0);

    subnet.parse("dead:beef::/64");
    tree.addSubnet(subnet, 0x1);

    memset(&addr,0,sizeof(sockaddr_storage));
    am_inet_pton("dead:beef::1", &addr);
    match_result.clear();
    tree.match(addr, match_result);

    EXPECT_EQ(match_result.size(),3);
    //check result indexes ordering
    for(int i = 0; i < 3; i++) {
        EXPECT_EQ(match_result[i],i);
    }
}
