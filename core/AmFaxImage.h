#ifndef AM_FAX_IMAGE_H
#define AM_FAX_IMAGE_H

#include "AmSdp.h"
#include "media/AmRtpConnection.h"
#include "AmAudio.h"
#include "AmMediaProcessor.h"
#include <spandsp.h>
#include "udptl.h"

#define T38_FMT        "t38"

class AmSession;
class msg_logger;

typedef struct t38_option{
    uint16_t    T38FaxVersion;
    uint32_t    T38MaxBitRate;
    bool        T38FaxFillBitRemoval;
    bool        T38FaxTranscodingMMR;
    bool        T38FaxTranscodingJBIG;
    std::string T38FaxRateManagement;
    int         T38FaxMaxBuffer;
    uint32_t    T38FaxMaxDatagram;
    uint32_t    T38FaxMaxIFP;
    std::string T38FaxUdpEC;

    void getT38DefaultOptions();
    void negotiateT38Options(const std::vector<SdpAttribute>& attr);
    void getAttributes(SdpMedia& m);
} t38_options_t;

class UDPTLConnection : public AmStreamConnection
{
public:
    UDPTLConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port);
    virtual ~UDPTLConnection();

    void handleConnection(uint8_t * data, unsigned int size, struct sockaddr_storage * recv_addr, struct timeval recv_time) override;
};

class DTLSUDPTLConnection : public AmStreamConnection
{
    AmStreamConnection* m_dtls_conn;
public:
    DTLSUDPTLConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port, AmStreamConnection* dtls);
    virtual ~DTLSUDPTLConnection();

    void handleConnection(uint8_t * data, unsigned int size, struct sockaddr_storage * recv_addr, struct timeval recv_time) override;
    void handleSymmetricRtp(struct sockaddr_storage*, struct timeval*) override {}
    ssize_t send(AmRtpPacket * packet) override;
};

struct FaxCompleteEvent
  : public AmEvent
{
    FaxCompleteEvent(bool isSuccess, const string& strResult, const map<string, string> &stat, const map<string, string> &t38params)
    :  AmEvent(0), m_isSuccess(isSuccess), m_strResult(strResult), m_statistics(stat), m_t38Params(t38params)
    { }
    bool m_isSuccess;
    string m_strResult;
    map<string, string> m_statistics;
    map<string, string> m_t38Params;
};

class AmFaxImage
{
  protected:
    t30_state_t *m_t30_state;
    std::string m_filePath;
    bool m_send;
    AmEventQueue* eq;
    ContextLoggingHook* logger;

  public:
    AmFaxImage(AmEventQueue* q, const std::string& filePath, bool send, ContextLoggingHook* logger_);
    virtual ~AmFaxImage();

    void init_t30();
    virtual void get_fax_params(std::map<std::string, std::string>& params){}
    t30_state_t *get_t30_state() { return m_t30_state; }

  protected:
    friend void spandsp_log_handler(void* user_data, int level, const char *text);
    friend int phase_b_handler(void *user_data, int result);
    friend int phase_d_handler(void *user_data, int result);
    friend void phase_e_handler(void *user_data, int result);
    void logHandler(int level, const char* text);
    void faxComplete(bool isSuccess, const std::string& strResult, const t30_stats_t& t);
};

class FaxAudioImage : public AmAudio, public AmFaxImage
{
    fax_state_t* m_fax_state;
public:
    FaxAudioImage(AmEventQueue* q, const std::string& filePath, bool send, ContextLoggingHook* logger_);
    ~FaxAudioImage();

    int write(unsigned int user_ts, unsigned int size) override;
    int read(unsigned int user_ts, unsigned int size) override;

    int init_tone_fax();
};

class FaxT38Image : public AmMediaSession, public AmFaxImage, public atomic_ref_cnt
{
    AmSession* m_sess;
    t38_terminal_state_t* m_t38_state;
    udptl_state_t *m_udptl_state;
    t38_options_t m_t38_options;
    struct timeval m_lastTime;
    unsigned long long m_last_ts;
public:
    FaxT38Image(AmSession* sess, const std::string& filePath, bool send, ContextLoggingHook* logger_);
    ~FaxT38Image();

    int send_udptl_packet(const uint8_t *buf, int len);
    int init_t38();
    void setOptions(const t38_options_t& t38_options);
protected:

    //AmMediaSession implementation
    int readStreams(unsigned long long ts, unsigned char * buffer) override;
    int writeStreams(unsigned long long ts, unsigned char * buffer) override;
    void onMediaProcessingStarted() override;
    void onMediaSessionExists() override;
    void onMediaProcessingTerminated() override;
    void clearAudio() override;
    void clearRTPTimeout() override;
    void processDtmfEvents() override;

    //AmFaxImage implementation
    void get_fax_params(std::map<std::string, std::string> & params) override;
};

#endif/*AM_FAX_IMAGE_H*/
