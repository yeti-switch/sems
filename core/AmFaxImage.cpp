#include "AmFaxImage.h"
#include "AmSession.h"
#include "udptl.h"

#define T38_FAX_RATE_DEFAULT "transferredTCF"
#define T38_FAX_UDPEC_DEFAULT "t38UDPRedundancy"
#define NAME_TO_STRING(name) #name

#define STAT_ECM            "ecm"
#define STAT_BIT_RATE       "bit_rate"
#define STAT_TX_PAGES       "tx_pages"
#define STAT_RX_PAGES       "rx_pages"
#define STAT_PIF            "total_pages"
#define STAT_ILENGTH        "image_length"
#define STAT_ISIZE          "image_size"
#define STAT_IRESOLUTION    "image_resolution"
#define STAT_BAD_ROWS       "bad_rows"
#define STAT_L_BAD_ROWS_RUN "longest_bad_row_run"
#define STAT_BAD_ECM_FRAMES "bad_ecm_frames"
#define STAT_COMP_TYPE      "compression_type"

#define FAX_RATE              8000

static std::map<std::string, std::string> t38_option_map(const t38_options_t& opt)
{
    std::map<std::string, std::string> options;
    char intValue[20];
    sprintf(intValue, "%d", opt.T38FaxVersion);
    options.insert(std::make_pair(NAME_TO_STRING(T38FaxVersion), intValue));
    sprintf(intValue, "%d", opt.T38MaxBitRate);
    options.insert(std::make_pair(NAME_TO_STRING(T38MaxBitRate), intValue));
    options.insert(std::make_pair(NAME_TO_STRING(T38FaxFillBitRemoval), opt.T38FaxFillBitRemoval ? "true" : "false"));
    options.insert(std::make_pair(NAME_TO_STRING(T38FaxTranscodingMMR), opt.T38FaxTranscodingMMR ? "true" : "false"));
    options.insert(std::make_pair(NAME_TO_STRING(T38FaxTranscodingJBIG), opt.T38FaxTranscodingJBIG ? "true" : "false"));
    options.insert(std::make_pair(NAME_TO_STRING(T38FaxRateManagement), opt.T38FaxRateManagement));
    sprintf(intValue, "%d", opt.T38FaxMaxBuffer);
    options.insert(std::make_pair(NAME_TO_STRING(T38FaxMaxBuffer), intValue));
    sprintf(intValue, "%d", opt.T38FaxMaxDatagram);
    options.insert(std::make_pair(NAME_TO_STRING(T38FaxMaxDatagram), intValue));
    sprintf(intValue, "%d", opt.T38FaxMaxIFP);
    options.insert(std::make_pair(NAME_TO_STRING(T38FaxMaxIFP), intValue));
    options.insert(std::make_pair(NAME_TO_STRING(T38FaxUdpEC), opt.T38FaxUdpEC));
    return options;
}

static std::map<std::string, std::string> transfer_statistics_map(const t30_stats_t& s)
{
    std::map<std::string, std::string> stat;
    char intValue[20];
    std::string data;
    stat.insert(std::make_pair(STAT_ECM, (s.error_correcting_mode)  ?  "yes"  :  "no"));
    sprintf(intValue, "%d", s.bit_rate);
    stat.insert(std::make_pair(STAT_BIT_RATE, intValue));
    sprintf(intValue, "%d", s.pages_tx);
    stat.insert(std::make_pair(STAT_TX_PAGES, intValue));
    sprintf(intValue, "%d", s.pages_rx);
    stat.insert(std::make_pair(STAT_RX_PAGES, intValue));
    sprintf(intValue, "%d", s.pages_in_file);
    stat.insert(std::make_pair(STAT_PIF, intValue));
    sprintf(intValue, "%d", s.width);
    data = intValue;
    data += " perl X ";
    sprintf(intValue, "%d", s.length);
    data += intValue;
    data += " perl";
    stat.insert(std::make_pair(STAT_ISIZE, data));
    sprintf(intValue, "%d", s.x_resolution);
    data = intValue;
    data += " perls X ";
    sprintf(intValue, "%d", s.y_resolution);
    data += intValue;
    data += " perls";
    stat.insert(std::make_pair(STAT_IRESOLUTION, data));
    sprintf(intValue, "%d", s.bad_rows);
    stat.insert(std::make_pair(STAT_BAD_ROWS, intValue));
    sprintf(intValue, "%d", s.longest_bad_row_run);
    stat.insert(std::make_pair(STAT_L_BAD_ROWS_RUN, intValue));
    sprintf(intValue, "%d", s.error_correcting_mode_retries);
    stat.insert(std::make_pair(STAT_BAD_ECM_FRAMES, intValue));
    sprintf(intValue, "%d", s.image_size);
    stat.insert(std::make_pair(STAT_ILENGTH, intValue));
    sprintf(intValue, "%d", s.encoding);
    stat.insert(std::make_pair(STAT_COMP_TYPE, intValue));
    return stat;
}

static std::string transfer_statistics(t30_state_t *s)
{
    std::string log;
    t30_stats_t t;
    t30_get_transfer_statistics(s, &t);
    std::map<std::string, std::string> stat_map = transfer_statistics_map(t);

    for(auto& stat_pair : stat_map) {
        log += stat_pair.first + " " + stat_pair.second + "\n";
    }
    return log;
}

void spandsp_log_handler(int level, const char *text, void* user_data)
{
    AmFaxImage* image = (AmFaxImage*)user_data;
    image->logHandler(level, text);
}

int phase_b_handler(t30_state_t *s, void *user_data, int result)
{
    char log[200];

    AmFaxImage* image = (AmFaxImage*)user_data;
    sprintf(log, "Phase B - (0x%X) %s", result, t30_frametype(result));
    image->logHandler(SPAN_LOG_FLOW, log);
    return T30_ERR_OK;
}

int phase_d_handler(t30_state_t *s, void *user_data, int result)
{
    char log[200];

    AmFaxImage* image = (AmFaxImage*)user_data;
    sprintf(log, "Phase D - (0x%X) %s\n", result, t30_frametype(result));
    std::string logStr(log);
    logStr += "--++--\n";
    logStr += transfer_statistics(s);
    logStr += "\n--++--";
    image->logHandler(SPAN_LOG_FLOW, logStr.c_str());
    return T30_ERR_OK;
}

void phase_e_handler(t30_state_t *s, void *user_data, int result)
{
    char log[200];

    AmFaxImage* image = (AmFaxImage*)user_data;
    sprintf(log, "Phase E - (%d) %s\n", result, t30_completion_code_to_str(result));
    t30_stats_t t;
    std::string logStr(log);
    logStr += "--++--\n";
    logStr += transfer_statistics(s);
    logStr += "\n--++--";
    image->logHandler(SPAN_LOG_FLOW, logStr.c_str());
    t30_get_transfer_statistics(s, &t);
    image->faxComplete(result == T30_ERR_OK, t30_completion_code_to_str(result), t);
}

int t38_tx_packet_handler(t38_core_state_t *s, void *user_data, const uint8_t *buf, int len, int count)
{
    FaxT38Image* image = (FaxT38Image*)user_data;
    image->send_udptl_packet(buf,len);
    //FIXME: should we ignore send errors here ?
    return 0;
}

/*- End of functions --------------------------------------------------------*/

/***************************************************************************************************/
/*                                     t38_option functions                                        */
/***************************************************************************************************/
void t38_option::getT38DefaultOptions()
{
    T38FaxVersion = 0;
    T38MaxBitRate = 14400;
    T38FaxFillBitRemoval = 1;
    T38FaxTranscodingMMR = 0;
    T38FaxTranscodingJBIG = 0;
    T38FaxRateManagement = T38_FAX_RATE_DEFAULT;
    T38FaxMaxBuffer = 2000;
    T38FaxMaxDatagram = LOCAL_FAX_MAX_DATAGRAM;
    T38FaxMaxIFP = 40;
    T38FaxUdpEC = T38_FAX_UDPEC_DEFAULT;
}

void t38_option::negotiateT38Options(const std::vector<SdpAttribute>& attr)
{
    getT38DefaultOptions();
    for(auto &attribute : attr) {
        if(attribute.attribute == NAME_TO_STRING(T38FaxVersion)) {
            T38FaxVersion = (uint16_t)atoi(attribute.value.c_str());
        } else if(attribute.attribute == NAME_TO_STRING(T38MaxBitRate)){
            T38MaxBitRate = (uint32_t)atoi(attribute.value.c_str());
        } else if(attribute.attribute == NAME_TO_STRING(T38FaxFillBitRemoval)){
            T38FaxFillBitRemoval = (bool)atoi(attribute.value.c_str());
        } else if(attribute.attribute == NAME_TO_STRING(T38FaxTranscodingMMR)){
            T38FaxTranscodingMMR = (bool)atoi(attribute.value.c_str());
        } else if(attribute.attribute == NAME_TO_STRING(T38FaxTranscodingJBIG)){
            T38FaxTranscodingJBIG = (bool)atoi(attribute.value.c_str());
        } else if(attribute.attribute == NAME_TO_STRING(T38FaxRateManagement)){
            T38FaxRateManagement = attribute.value;
        } else if(attribute.attribute == NAME_TO_STRING(T38FaxMaxBuffer)){
            T38FaxMaxBuffer = (uint32_t)atoi(attribute.value.c_str());
        } else if(attribute.attribute == NAME_TO_STRING(T38FaxMaxDatagram)){
            T38FaxMaxDatagram = (uint32_t)atoi(attribute.value.c_str());
        } else if(attribute.attribute == NAME_TO_STRING(T38FaxMaxIFP)){
            T38FaxMaxIFP = (uint32_t)atoi(attribute.value.c_str());
        } else if(attribute.attribute == NAME_TO_STRING(T38FaxUdpEC)){
            T38FaxUdpEC = attribute.value;
        }
    }
}

void t38_option::getAttributes(SdpMedia& m)
{
    char data[100];
    sprintf(data, "%d", T38FaxVersion);
    m.attributes.push_back(SdpAttribute(NAME_TO_STRING(T38FaxVersion), data));
    sprintf(data, "%d", T38MaxBitRate);
    m.attributes.push_back(SdpAttribute(NAME_TO_STRING(T38MaxBitRate), data));
    sprintf(data, "%d", T38FaxFillBitRemoval);
    m.attributes.push_back(SdpAttribute(NAME_TO_STRING(T38FaxFillBitRemoval), data));
    sprintf(data, "%d", T38FaxTranscodingMMR);
    m.attributes.push_back(SdpAttribute(NAME_TO_STRING(T38FaxTranscodingMMR), data));
    sprintf(data, "%d", T38FaxTranscodingJBIG);
    m.attributes.push_back(SdpAttribute(NAME_TO_STRING(T38FaxTranscodingJBIG), data));
    m.attributes.push_back(SdpAttribute(NAME_TO_STRING(T38FaxRateManagement), T38FaxRateManagement));
    sprintf(data, "%d", T38FaxMaxBuffer);
    m.attributes.push_back(SdpAttribute(NAME_TO_STRING(T38FaxMaxBuffer), data));
    sprintf(data, "%d", T38FaxMaxDatagram);
    m.attributes.push_back(SdpAttribute(NAME_TO_STRING(T38FaxMaxDatagram), data));
    sprintf(data, "%d", T38FaxMaxIFP);
    m.attributes.push_back(SdpAttribute(NAME_TO_STRING(T38FaxMaxIFP), data));
    m.attributes.push_back(SdpAttribute(NAME_TO_STRING(T38FaxUdpEC), T38FaxUdpEC));
}

/***************************************************************************************************/
/*                                         UDPTLConnection                                         */
/***************************************************************************************************/
UDPTLConnection::UDPTLConnection(AmMediaTransport* _transport, const string& remote_addr, int remote_port)
: AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::UDPTL_CONN)
{
}

UDPTLConnection::~UDPTLConnection()
{
}

void UDPTLConnection::handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval rv_time)
{
    sockaddr_storage laddr;
    transport->getLocalAddr(&laddr);

    AmRtpPacket* p = transport->getRtpStream()->createRtpPacket();
    if(!p) return;

    p->recv_time = rv_time;
    p->relayed = false;
    p->setAddr(recv_addr);
    p->setLocalAddr(&laddr);
    p->setBuffer(data, size);
    transport->onRawPacket(p, this);
}

/***************************************************************************************************/
/*                                         UDPTLConnection                                         */
/***************************************************************************************************/
DTLSUDPTLConnection::DTLSUDPTLConnection(AmMediaTransport* _transport, const std::string& remote_addr, int remote_port, AmStreamConnection* dtls)
: AmStreamConnection(_transport, remote_addr, remote_port, AmStreamConnection::UDPTL_CONN), m_dtls_conn(dtls)
{
}

DTLSUDPTLConnection::~DTLSUDPTLConnection()
{
}

void DTLSUDPTLConnection::handleConnection(uint8_t* data, unsigned int size, struct sockaddr_storage* recv_addr, struct timeval recv_time)
{
    ERROR("NOT IMPLEMENTED. that's wrong - this function doesn't to called");
}

ssize_t DTLSUDPTLConnection::send(AmRtpPacket* packet)
{
    return m_dtls_conn->send(packet);
}

/***************************************************************************************************/
/*                                           AmFaxImage                                            */
/***************************************************************************************************/
AmFaxImage::AmFaxImage(AmEventQueue* q, const std::string& filePath, bool send)
  : m_t30_state(0),
    m_filePath(filePath),
    m_send(send),
    eq(q)
{}

AmFaxImage::~AmFaxImage()
{
}

void AmFaxImage::init_t30()
{
    logging_state_t *logging = 0;
    logging = t30_get_logging_state(m_t30_state);
    span_log_set_level(logging, SPAN_LOG_SHOW_SEVERITY | SPAN_LOG_SHOW_TAG | SPAN_LOG_SHOW_PROTOCOL | SPAN_LOG_DEBUG);
    span_log_set_protocol(logging, "T30");
    span_log_set_message_handler(logging, spandsp_log_handler, this);
    t30_set_ecm_capability(m_t30_state, TRUE);
    t30_set_supported_image_sizes(m_t30_state, T30_SUPPORT_US_LETTER_LENGTH | T30_SUPPORT_US_LEGAL_LENGTH | T30_SUPPORT_UNLIMITED_LENGTH |
                                               T30_SUPPORT_215MM_WIDTH | T30_SUPPORT_303MM_WIDTH);
    t30_set_supported_resolutions(m_t30_state, T30_SUPPORT_STANDARD_RESOLUTION | T30_SUPPORT_FINE_RESOLUTION | T30_SUPPORT_SUPERFINE_RESOLUTION |
                                               T30_SUPPORT_R8_RESOLUTION | T30_SUPPORT_R16_RESOLUTION |
                                               T30_SUPPORT_300_300_RESOLUTION | T30_SUPPORT_400_400_RESOLUTION |
                                               T30_SUPPORT_600_600_RESOLUTION | T30_SUPPORT_1200_1200_RESOLUTION | T30_SUPPORT_300_600_RESOLUTION |
                                               T30_SUPPORT_400_800_RESOLUTION | T30_SUPPORT_600_1200_RESOLUTION);
    t30_set_supported_compressions(m_t30_state, T30_SUPPORT_T4_1D_COMPRESSION | T30_SUPPORT_T4_2D_COMPRESSION | T30_SUPPORT_T6_COMPRESSION);
    t30_set_supported_t30_features(m_t30_state, T30_SUPPORT_IDENTIFICATION | T30_SUPPORT_SELECTIVE_POLLING | T30_SUPPORT_SUB_ADDRESSING);
    if(m_send)
        t30_set_tx_file(m_t30_state, m_filePath.c_str(), 0, -1);
    else
        t30_set_rx_file(m_t30_state, m_filePath.c_str(), -1);
    t30_set_phase_b_handler(m_t30_state, phase_b_handler, (void *) this);
    t30_set_phase_d_handler(m_t30_state, phase_d_handler, (void *) this);
    t30_set_phase_e_handler(m_t30_state, phase_e_handler, (void *) this);
}

void AmFaxImage::logHandler(int level, const char* text)
{
    switch(level){
        case SPAN_LOG_ERROR:
        case SPAN_LOG_PROTOCOL_ERROR:
            CLASS_ERROR("%s", text);
            break;
        case SPAN_LOG_WARNING:
        case SPAN_LOG_PROTOCOL_WARNING:
            CLASS_WARN("%s", text);
            break;
        case SPAN_LOG_FLOW:
        case SPAN_LOG_FLOW_2:
        case SPAN_LOG_FLOW_3:
        case SPAN_LOG_DEBUG:
        case SPAN_LOG_DEBUG_2:
        case SPAN_LOG_DEBUG_3:
            CLASS_DBG("%s", text);
            break;
        default:
            break;
    }
}

void AmFaxImage::faxComplete(bool isSuccess, const std::string& strResult, const t30_stats_t& t)
{
    std::map<std::string, std::string> stat = transfer_statistics_map(t);
    std::map<std::string, std::string> params;
    get_fax_params(params);
    eq->postEvent(new FaxCompleteEvent(isSuccess, strResult, stat, params));
}

/***************************************************************************************************/
/*                                        FaxAudioImage                                            */
/***************************************************************************************************/
FaxAudioImage::FaxAudioImage(AmEventQueue* q, const std::string& filePath, bool send)
: AmFaxImage(q, filePath, send)
, m_fax_state{0}
{
}

FaxAudioImage::~FaxAudioImage()
{
    if(m_fax_state) {
        fax_release(m_fax_state);
    }
}

int FaxAudioImage::init_tone_fax()
{
    CLASS_DBG("initialize tone fax");
    fmt->setRate(FAX_RATE);

    if(m_fax_state) {
        CLASS_ERROR("fax tone stack was inited");
        return -1;
    }
    m_fax_state = ::fax_init(m_fax_state, m_send ? TRUE : FALSE);
    if(!m_fax_state) {
        CLASS_ERROR("fax tone stack initialisation failed");
        return -1;
    }

    logging_state_t *logging = 0;
    logging = fax_get_logging_state(m_fax_state);
    span_log_set_level(logging, SPAN_LOG_SHOW_SEVERITY | SPAN_LOG_SHOW_TAG | SPAN_LOG_SHOW_PROTOCOL | SPAN_LOG_DEBUG);
    span_log_set_protocol(logging, "INBOUND FAX");
    span_log_set_message_handler(logging, spandsp_log_handler, this);

    fax_set_transmit_on_idle(m_fax_state, TRUE);

    m_t30_state = fax_get_t30_state(m_fax_state);
    init_t30();

    CLASS_DBG("initialize tone fax complete");

    return 0;
}

int FaxAudioImage::read(unsigned int user_ts, unsigned int size)
{
    if(m_fax_state) {
        unsigned char* amp = AmAudio::samples;
        memset(amp, 0, size);
        int ret = fax_tx(m_fax_state, (int16_t*)amp, fmt->bytes2samples(size));
        return fmt->calcBytesToRead(ret);
    }
    return -1;
}

int FaxAudioImage::write(unsigned int user_ts, unsigned int size)
{
    if(m_fax_state) {
        unsigned char* amp = AmAudio::samples;
        /*int ret = */fax_rx(m_fax_state, (int16_t*)amp, fmt->bytes2samples(size));
        return size;
    }
    return -1;
}

/***************************************************************************************************/
/*                                        FaxAudioImage                                            */
/***************************************************************************************************/
FaxT38Image::FaxT38Image(AmSession* sess, const std::string& filePath, bool send)
: AmFaxImage(sess, filePath, send)
, m_sess(sess)
, m_t38_state(0)
, m_udptl_state(0)
{
}

FaxT38Image::~FaxT38Image()
{
    if(m_udptl_state) {
        udptl_release(m_udptl_state);
    }
    if(m_t38_state) {
        t38_terminal_release(m_t38_state);
    }
}

int FaxT38Image::init_t38()
{
    CLASS_DBG("initialize t38");
    if(m_t38_state) {
        CLASS_ERROR("t38 terminal was inited");
        return FALSE;
    }
    m_t38_state = t38_terminal_init(m_t38_state, m_send ? TRUE : FALSE, t38_tx_packet_handler, this);
    if(!m_t38_state) {
        CLASS_ERROR("t38 terminal initialisation failed");
        return FALSE;
    }

    m_t38_options.getT38DefaultOptions();

    if(m_t38_options.T38FaxMaxBuffer > T38_TX_BUF_LEN) {
        CLASS_WARN("T38FaxMaxBuffer %d more then maximum packet len " NAME_TO_STRING(T38_TX_BUF_LEN), m_t38_options.T38FaxMaxBuffer);
    }

    logging_state_t *logging = 0;
    logging = t38_terminal_get_logging_state(m_t38_state);
    span_log_set_level(logging, SPAN_LOG_SHOW_SEVERITY | SPAN_LOG_SHOW_TAG | SPAN_LOG_SHOW_PROTOCOL | SPAN_LOG_DEBUG);
    span_log_set_protocol(logging, "T38 TERMINAL");
    span_log_set_message_handler(logging, spandsp_log_handler, this);

    int method;
    if (m_t38_options.T38FaxRateManagement == T38_FAX_RATE_DEFAULT) {
        method = 2;
    } else {
        method = 1;
    }
    t38_core_state_t* t38_core = t38_terminal_get_t38_core_state(m_t38_state);
    logging = t38_core_get_logging_state(t38_core);
    span_log_set_level(logging, SPAN_LOG_SHOW_SEVERITY | SPAN_LOG_SHOW_TAG | SPAN_LOG_SHOW_PROTOCOL | SPAN_LOG_DEBUG);
    span_log_set_protocol(logging, "T38 CORE");
    span_log_set_message_handler(logging, spandsp_log_handler, this);

    t38_set_t38_version(t38_core, m_t38_options.T38FaxVersion);
    t38_set_max_buffer_size(t38_core, m_t38_options.T38FaxMaxBuffer);
    t38_set_fastest_image_data_rate(t38_core, m_t38_options.T38MaxBitRate);
    t38_set_fill_bit_removal(t38_core, m_t38_options.T38FaxFillBitRemoval);
    t38_set_mmr_transcoding(t38_core, m_t38_options.T38FaxTranscodingMMR);
    t38_set_jbig_transcoding(t38_core, m_t38_options.T38FaxTranscodingJBIG);
    t38_set_max_datagram_size(t38_core, m_t38_options.T38FaxMaxDatagram);
    t38_set_data_rate_management_method(t38_core, method);


    m_t30_state = t38_terminal_get_t30_state(m_t38_state);
    init_t30();

    CLASS_DBG("initialize t38 complete, initialize udptl");
    if(m_udptl_state) {
        CLASS_ERROR("udptl stack was inited");
        return FALSE;
    }
    m_udptl_state = udptl_init(m_udptl_state, UDPTL_ERROR_CORRECTION_REDUNDANCY, 3, 3, (udptl_rx_packet_handler_t *) t38_core_rx_ifp_packet, (void *) t38_core);
    if(!m_udptl_state) {
        CLASS_ERROR("udptl stack initialisation failed");
        return FALSE;
    }

    gettimeofday(&m_lastTime, NULL);
    CLASS_DBG("initialize udptl complete");
    return TRUE;
}

void FaxT38Image::setOptions(const t38_options_t& t38_options)
{
    m_t38_options = t38_options;
}

int FaxT38Image::send_udptl_packet(const uint8_t* buf, int len)
{
    static const cstring empty;

    if(len > m_t38_options.T38FaxMaxBuffer) {
        CLASS_WARN("send buffer %u more permission t38 packet len %u",
                      len, m_t38_options.T38FaxMaxBuffer);
    }

    unsigned char data[RTP_PACKET_BUF_SIZE];
    int packet_len = udptl_build_packet(m_udptl_state, data , buf, len);
    if(packet_len <= 0) {
        CLASS_ERROR("udptl_build_packet failed return %u", packet_len);
        return -1;
    }

    CLASS_DBG("udptl fax packet (len = %d) send to %s:%d", packet_len, m_sess->RTPStream()->getRHost(FAX_TRANSPORT).c_str(), m_sess->RTPStream()->getRPort(FAX_TRANSPORT));
    unsigned int tx_user_ts = m_last_ts * (FAX_RATE / 100) / (WALLCLOCK_RATE/100);
    int ret = m_sess->RTPStream()->send_udptl(tx_user_ts, data, packet_len);
    if(-1==ret) {
        CLASS_ERROR("sendto: %d, errno = %d",ret,errno);
        return ret;
    }

    return ret;
}

int FaxT38Image::readStreams(unsigned long long ts, unsigned char * buffer)
{
    AmRtpPacket* rp = NULL;
    int err = m_sess->RTPStream()->nextPacket(rp);

    if(err <= 0)
        return err;

    if (!rp)
        return 0;

    if(udptl_rx_packet(m_udptl_state, rp->getBuffer(), rp->getBufferSize()) < 0) {
        CLASS_ERROR("incorrect udptl packet [pkt-size=%u]", rp->getBufferSize());
        m_sess->RTPStream()->freeRtpPacket(rp);
        return 0;
    }

    m_sess->RTPStream()->freeRtpPacket(rp);
    return 0;
}

int FaxT38Image::writeStreams(unsigned long long ts, unsigned char * buffer)
{
    timeval now;
    gettimeofday(&now, NULL);
    m_last_ts = ts;
    uint64_t last_ = m_lastTime.tv_sec*1000 + m_lastTime.tv_usec/1000;
    uint64_t now_ = now.tv_sec*1000 + now.tv_usec/1000;
    m_lastTime = now;
    if(m_t38_state && last_) {
        int samples = ms_to_samples((now_ - last_));
        t38_terminal_send_timeout(m_t38_state, samples);
    }
    return 0;
}

void FaxT38Image::onMediaProcessingStarted()
{
    CLASS_DBG("onMediaProcessingStarted()");
    AmMediaSession::onMediaProcessingStarted();
    inc_ref(this);
    init_t38();
}

void FaxT38Image::onMediaSessionExists()
{
    CLASS_DBG("onMediaSessionExists()");
    //cleanup ref aquired by onMediaProcessingStarted()
    dec_ref(this);
}

void FaxT38Image::onMediaProcessingTerminated()
{
    CLASS_DBG("onMediaProcessingTerminated()");

    AmMediaSession::onMediaProcessingTerminated();

    if(m_udptl_state) {
        udptl_release(m_udptl_state);
        m_udptl_state = 0;
    }
    if(m_t38_state) {
        t38_terminal_release(m_t38_state);
        m_t38_state = 0;
    }

    dec_ref(this);
}

void FaxT38Image::clearAudio()
{
}

void FaxT38Image::processDtmfEvents()
{
}

void FaxT38Image::clearRTPTimeout()
{
    m_sess->RTPStream()->clearRTPTimeout();
}

void FaxT38Image::get_fax_params(std::map<std::string, std::string>& params)
{
    params = t38_option_map(m_t38_options);
}
