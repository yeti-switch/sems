#ifndef AM_LC_CONFIG_H
#define AM_LC_CONFIG_H

#include <confuse.h>
#include <map>
#include "AmLCContainers.h"

class AmLcConfig
{
    AmLcConfig();
public:
    ~AmLcConfig();

    static AmLcConfig& GetInstance()
    {
        static AmLcConfig config;
        return config;
    }

    int readConfiguration();
    int finalizeIpConfig();
    void dump_Ifs();
    std::string fixIface2IP(const std::string& dev_name, bool v6_for_sip);

    std::vector<SIP_interface> sip_ifs;
    std::vector<MEDIA_interface> media_ifs;
    std::map<std::string, unsigned short> sip_if_names;
    std::map<std::string, unsigned short> media_if_names;
    std::map<std::string,unsigned short> local_sip_ip2if;
    std::vector<SysIntf> sys_ifs;
protected:
    IP_info* readInterface(cfg_t* cfg, const std::string& if_name, IP_info::IP_type ip_type);
    int readAcl(cfg_t* cfg, trsp_acl& acl, const std::string& if_name);
    bool fillSysIntfList();
    int insertSIPInterfaceMapping(const std::string& ifname, const SIP_info& intf, int idx);
    int setNetInterface(IP_info& ip_if);
    void fillMissingLocalSIPIPfromSysIntfs();
    int checkSipInterfaces();
private:
    cfg_t *m_cfg;
};

#endif/*AM_LC_CONFIG_H*/
