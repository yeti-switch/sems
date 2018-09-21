#include "raw_sender.h"
#include "raw_sock.h"
#include "AmLcConfig.h"
#include "AmConfig.h"

#include "log.h"

#include <errno.h>
#include <string.h>

int raw_sender::rsock = -1;
int raw_sender::rsock6 = -1;

int raw_sender::init()
{
  int rcv_buf_size = 0;

  if(rsock >= 0) {
    return 0;
  }
  
  rsock = raw_udp_socket(1);
  if(rsock < 0) {
    if(errno == EPERM) {
      ERROR("SEMS must be running as root to be able to use raw sockets.");
      goto err;
    }
    else {
      ERROR("raw_udp_socket(): %s",strerror(errno));
      goto err;
    }
  }

  if(setsockopt(rsock, SOL_SOCKET, SO_RCVBUF, &rcv_buf_size, sizeof(rcv_buf_size)) < 0) {
      ERROR("setsockopt(): %s",strerror(errno));
      goto err;
  }

  rsock6 = raw_udp_socket6(1);
  if(rsock6 < 0) {
    if(errno == EPERM) {
      ERROR("SEMS must be running as root to be able to use raw sockets.");
      goto err;
    }
    else {
      ERROR("raw_udp_socket(): %s",strerror(errno));
      goto err;
    }
  }

  if(setsockopt(rsock6, SOL_SOCKET, SO_RCVBUF, &rcv_buf_size, sizeof(rcv_buf_size)) < 0) {
      ERROR("setsockopt(): %s",strerror(errno));
      goto err;
  }

  return 0;
err:
  ERROR("-> raw socket usage will be deactivated.");
  return -1;
}

int raw_sender::send(const char* buf, unsigned int len, int sys_if_idx,
             const sockaddr_storage* from, const sockaddr_storage* to, int tos)
{
  //TODO: grab the MTU from the interface def
  int ret = -1;
  if(from->ss_family == PF_INET) {
    ret = raw_iphdr_udp4_send(rsock,buf,len,from,to,
                AmLcConfig::GetInstance().sys_ifs[sys_if_idx].mtu,
                tos);
  } else if(from->ss_family == PF_INET6) {
    ret = raw_iphdr_udp6_send(rsock6,buf,len,from,to,
                AmLcConfig::GetInstance().sys_ifs[sys_if_idx].mtu,
                tos);
  }
  if(ret < 0) {
    ERROR("send(): %s",strerror(errno));
    return ret;
  }

  if((unsigned int)ret < len) {
    DBG("incomplete udp send (%i instead of %i)",ret,len);
    return -1;
  }

  return 0;
}
