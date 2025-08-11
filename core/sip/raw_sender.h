#ifndef _raw_sender_h_
#define _raw_sender_h_

struct sockaddr_storage;

class raw_sender {
    static int rsock;
    static int rsock6;

    raw_sender() {}
    ~raw_sender() {}

  public:
    static int init();
    static int send(const char *buf, unsigned int len, int sys_if_idx, const sockaddr_storage *from,
                    const sockaddr_storage *to, int tos);
};

#endif
