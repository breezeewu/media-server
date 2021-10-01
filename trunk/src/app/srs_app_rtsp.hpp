/*
The MIT License (MIT)

Copyright (c) 2013-2015 SRS(ossrs)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef SRS_APP_RTSP_HPP
#define SRS_APP_RTSP_HPP

/*
#include <srs_app_rtsp.hpp>
*/

#include <srs_core.hpp>

#include <string>
#include <vector>
#include <map>

#include <srs_app_st.hpp>
#include <srs_app_thread.hpp>
#include <srs_app_listener.hpp>
#include <srs_app_source.hpp>
//#include <srs_rtsp_stack.hpp>
#ifdef SRS_AUTO_STREAM_CASTER
#define SRS_RTSP_ENABLE_TLS_SOCKET
#define SRS_FIX_RTSP_PARAM
#define SRS_RTSP_TLS_PORT 443
#define SRS_RTSP_RECORD_FILE "hs004_1280x720_2.rec"//"hevc_dec.rec"
//#define SRS_READ_RTP_PACKET_FROM_FILE
//#define SRS_READ_PACKET_FROM_RECORD_FILE
class SrsStSocket;
class SrsRtspConn;
class SrsRtspStack;
class SrsRtspCaster;
class SrsConfDirective;
class SrsRtpPacket;
class SrsRequest;
class SrsStSocket;
class SrsRtmpClient;
class SrsRawH264Stream;
class SrsRawAacStream;
struct SrsRawAacStreamCodec;
class SrsSharedPtrMessage;
class SrsCodecSample;
class SrsSimpleBuffer;
class SrsPithyPrint;
class RTP_INFO;
class IRecodrDemux;
using namespace std;
/**
* a rtp connection which transport a stream.
*/
class SrsRtpConn: public ISrsUdpHandler
{
private:
    SrsPithyPrint* pprint;
    SrsUdpListener* listener;
    SrsRtspConn* rtsp;
    SrsRtpPacket* cache;
    int stream_id;
    int _port;
public:
    SrsRtpConn(SrsRtspConn* r, int p, int sid);
    virtual ~SrsRtpConn();
public:
    virtual int port();
    virtual int listen();
// interface ISrsUdpHandler
public:
    virtual int on_udp_packet(sockaddr_in* from, char* buf, int nb_buf);
};

/**
* audio is group by frames.
*/
struct SrsRtspAudioCache
{
    int64_t dts;
    SrsCodecSample* audio_samples;
    SrsSimpleBuffer* payload;

    SrsRtspAudioCache();
    virtual ~SrsRtspAudioCache();
};

/**
* the time jitter correct for rtsp.
*/
class SrsRtspJitter
{
private:
    int64_t previous_timestamp;
    int64_t pts;
    int delta;
public:
    SrsRtspJitter();
    virtual ~SrsRtspJitter();
public:
    virtual int64_t timestamp();
    virtual int correct(int64_t& ts);
};

class SrsRtspPlayDispatcher:public ISrsReusableThreadHandler
{
protected:
    uint32_t            ussrc;
    SrsReusableThread*  prtsp_fwd_thread;
    SrsRtspStack*       rtsp_stack;
    std::string         device_sn;
    class ForwardRtspQueue*   pfwd_rtsp_que;
    bool                bruning;
    SrsSource*          psource;
    int64_t             lstart_pts;
    int64_t             llast_pts;
    int64_t             lpts_offset;
    
    std::map<int, RTP_INFO*>    m_vrtp_info_list;
#ifdef SRS_READ_RTP_PACKET_FROM_FILE
    FILE*                       m_pfile;
#endif
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
    class IRecodrDemux*             m_prec_demux;
    uint8_t*                        m_ppkt_buf;
    int                             m_npkt_buf_len;
    string                          vps;
    string                          sps;
    string                          pps;

    string                          adts_hdr;
    struct ipc_record_info*         m_prec_info;
protected:
    int open_record_file(const char* prec_path);
    void close_record_file();
    int read_packet_from_record();
#endif
public:
    SrsRtspPlayDispatcher();

    ~SrsRtspPlayDispatcher();

    int add_rtp_info(int pt, RTP_INFO* prtpinfo);
    //int add_rtp_info(int pt, std::string url, std::string track_name, uint32_t timestamp, uint16_t seq_num);

    const RTP_INFO* get_rtp_info(int pt);

    int init_rtsp_dispatch(SrsRtspStack* rtsp,  std::string devicesn);

    int start();

    void on_thread_start();

    int cycle();

    void on_thread_stop();

    void stop();

    int wait_for_live_stream(int timeout_ms = 20000);

    int get_sps_and_pps(int& codec_id, string& vps, string& sps, string& pps);

    int get_audio_config(string& acfg);

protected:
    uint32_t gen_ssrc();
    /*
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
    int get_packet_from_record_demux();
#endif
*/
#ifdef SRS_READ_RTP_PACKET_FROM_FILE
    int read_rtsp_over_tcp_packet(char* pbuf, int len, uint8_t* pchannel_id = NULL);
#endif
};
/**
* the rtsp connection serve the fd.
*/
class SrsRtspConn : public ISrsOneCycleThreadHandler
{
private:
    std::string output_template;
    std::string rtsp_tcUrl;
    std::string rtsp_stream;
    std::string rtsp_session_name;
    std::string rtsp_media_title;
    int         m_nrtsp_tcp_port;
private:
    std::string session;
    // video stream.
    int video_id;
    std::string video_codec;
    SrsRtpConn* video_rtp;
    // audio stream.
    int audio_id;
    std::string audio_codec;
    int audio_sample_rate;
    int audio_channel;
    SrsRtpConn* audio_rtp;
private:
    st_netfd_t stfd;
    SrsStSocket* skt;
    SrsRtspStack* rtsp;
    SrsRtspCaster* caster;
    SrsOneCycleThread* trd;
private:
    SrsRequest* req;
    SrsStSocket* io;
    SrsRtmpClient* client;
    SrsRtspJitter* vjitter;
    SrsRtspJitter* ajitter;
    int stream_id;

private:
    SrsRawH264Stream* avc;
    std::string h264_sps;
    std::string h264_pps;
private:
    SrsRawAacStream* aac;
    SrsRawAacStreamCodec* acodec;
    std::string aac_specific_config;
    SrsRtspAudioCache* acache;
    std::map<std::string, std::string>  m_mauth_list;
    SrsRtspPlayDispatcher* prtsp_play_dispatcher;

    RTP_INFO*       m_pvideo_rtp_info;
    RTP_INFO*       m_paudio_rtp_info;
    //std::map<int, RTP_INFO*>    vrtp_info_list;

    double      start_time;
    double      stop_time;
    unsigned short  rtp_seq_num;
    unsigned int    rtp_timestamp;
public:
    SrsRtspConn(SrsRtspCaster* c, st_netfd_t fd, std::string o);
    virtual ~SrsRtspConn();
public:
    virtual int serve();
private:
    virtual int do_cycle();
// internal methods
public:
    virtual int on_rtp_packet(SrsRtpPacket* pkt, int stream_id);
// interface ISrsOneCycleThreadHandler
public:
    virtual int cycle();
    virtual void on_thread_stop();
private:
    virtual int on_rtp_video(SrsRtpPacket* pkt, int64_t dts, int64_t pts);
    virtual int on_rtp_audio(SrsRtpPacket* pkt, int64_t dts);
    virtual int kickoff_audio_cache(SrsRtpPacket* pkt, int64_t dts);
private:
    virtual int write_sequence_header();
    virtual int write_h264_sps_pps(u_int32_t dts, u_int32_t pts);
    virtual int write_h264_ipb_frame(char* frame, int frame_size, u_int32_t dts, u_int32_t pts);
    virtual int write_audio_raw_frame(char* frame, int frame_size, SrsRawAacStreamCodec* codec, u_int32_t dts);
    virtual int rtmp_write_packet(char type, u_int32_t timestamp, char* data, int size);
private:
    // connect to rtmp output url. 
    // @remark ignore when not connected, reconnect when disconnected.
    virtual int connect();
    virtual int connect_app(std::string ep_server, std::string ep_port);

    virtual int gen_h264_rtp_map_info(int pt, std::string url, std::string track_name);

    virtual int gen_aac_rtp_map_info(int pt, std::string url, std::string track_name);

    virtual int on_connect(SrsRequest* preq);

    virtual int on_close(SrsRequest* preq);

    virtual int http_hooks_on_connect(SrsRequest* preq);

    virtual int http_hooks_on_close(SrsRequest* preq);

    //virtual int parser_rtsp_request(SrsRtspRequest* rtspreq);
    //bool digest_auth_enable();

    //bool on_digest_auth(std::string method, class SrsRtspAuthorization* pauthorize);

};

/**
* the caster for rtsp.
*/
class SrsRtspCaster : public ISrsTcpHandler
{
private:
    std::string output;
    int local_port_min;
    int local_port_max;
    // key: port, value: whether used.
    std::map<int, bool> used_ports;
private:
    std::vector<SrsRtspConn*> clients;
public:
    SrsRtspCaster(SrsConfDirective* c);
    virtual ~SrsRtspCaster();
public:
    /**
    * alloc a rtp port from local ports pool.
    * @param pport output the rtp port.
    */
    virtual int alloc_port(int* pport);
    /**
    * free the alloced rtp port.
    */
    virtual void free_port(int lpmin, int lpmax);
// interface ISrsTcpHandler
public:
    virtual int on_tcp_client(st_netfd_t stfd);
// internal methods.
public:
    virtual void remove(SrsRtspConn* conn);
};

#endif

#endif
