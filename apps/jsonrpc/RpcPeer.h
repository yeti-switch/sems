/*
 * $Id: ModMysql.cpp 1764 2010-04-01 14:33:30Z peter_lemenkov $
 *
 * Copyright (C) 2010 TelTech Systems Inc.
 *
 * This file is part of SEMS, a free SIP media server.
 *
 * SEMS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. This program is released under
 * the GPL with the additional exemption that compiling, linking,
 * and/or using OpenSSL is allowed.
 *
 * For a license to use the SEMS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * SEMS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _RpcPeer_h_
#define _RpcPeer_h_

#include <ev.h>
#include <stdlib.h>
#include "log.h"
#include "AmArg.h"

#define MAX_RPC_MSG_SIZE 20 * 1024 * 1024 // 20k
#define MAX_NS_LEN_SIZE  10
#define SEND_SLEEP       10000 // 10 ms send retry

#include <map>
#include <string>

struct JsonrpcPeerConnection {
    std::string id;

    // event queue keys that should receive the reply
    // to requests sent on that connection
    //        req_id              queue       udata
    std::map<std::string, std::pair<std::string, AmArg>> replyReceivers;

    // if present, notifications will be sent
    // to that event queue directly
    std::string notificationReceiver;

    // if present, requests will be sent
    // to that event queue directly
    std::string requestReceiver;

    int flags;

    enum {
        FL_CLOSE_ALWAYS          = 1,  // always close connection after request processed
        FL_CLOSE_WRONG_REPLY     = 2,  // close connection if reply with unknown ID received
        FL_CLOSE_NO_REPLYLINK    = 4,  // close connection if reply queue for a request missing
        FL_CLOSE_NO_REQUEST_RECV = 8,  // close connection if reques queue missing
        FL_CLOSE_NO_NOTIF_RECV   = 16, // close connection if notification queue missing
        FL_REJECTED              = 32, // connection if not whitelists
    };

    enum ConnectionType { PEER_UNKNOWN, PEER_TCP, PEER_TLS, PEER_WS, PEER_WSS } conn_type;

    JsonrpcPeerConnection()
        : flags(0)
        , conn_type(PEER_UNKNOWN)
    {
        req_id = rand() % 1024;
    }

    int req_id;

    JsonrpcPeerConnection(const std::string &id)
        : id(id)
        , flags(0)
        , conn_type(PEER_UNKNOWN)
    {
        DBG3("created connection '%s'", id.c_str());
    }

    virtual ~JsonrpcPeerConnection() { DBG3("destroying connection '%s'", id.c_str()); }

    void notifyDisconnect();

    virtual void addMessage(const char *data, size_t len) = 0;
    virtual void clearMessage()                           = 0;
};

class JsonrpcNetstringsConnection : public JsonrpcPeerConnection {
  public:
    int   fd;
    ev_io ev_write;
    ev_io ev_read;
    bool  msg_recv;

  protected:
    char         snd_size[MAX_NS_LEN_SIZE + 1];
    char         msgbuf[MAX_RPC_MSG_SIZE];
    unsigned int msg_size;
    unsigned int rcvd_size;
    bool         in_msg;

  public:
    JsonrpcNetstringsConnection(const std::string &id);
    virtual ~JsonrpcNetstringsConnection();

    virtual int connect(const std::string &host, int port, std::string &res_str);

    void close();
    enum { CONTINUE = 0, REMOVE, DISPATCH } ReadResult;

    /** @returns ReadResult */
    virtual int netstringsRead();
    virtual int read_data(char *data, int size);

    /**
        blocking write: blocks until message in msgbuf
        with size msg_size is written
    */
    virtual int netstringsBlockingWrite();
    virtual int send_data(char *data, int size);

    void  resetRead();
    char *getMessage(size_t *len);
    bool  messagePending();
    bool  messageIsRecv();

    void addMessage(const char *data, size_t len) override;
    void clearMessage() override;
};

#endif
