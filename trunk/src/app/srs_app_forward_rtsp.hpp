/****************************************************************************************************************
 * filename     srs_app_forward_rtsp.hpp
 * describe     Sunvalley forward rtsp classs define
 * author       Created by dawson on 2019/04/25
 * Copyright    ©2007 - 2029 Sunvally. All Rights Reserved.
 ***************************************************************************************************************/

#ifndef SRS_APP_FORWARD_RTSP_HPP
#define SRS_APP_FORWARD_RTSP_HPP

/*
#include <srs_app_rtsp.hpp>
*/

#include <srs_core.hpp>
#include <srs_app_st.hpp>
#include <srs_app_thread.hpp>
#include <srs_kernel_stream.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_app_thread.hpp>
#include <srs_kernel_codec.hpp>
extern "C"
{
    #include <SVRtspPush.h>
}
#include <stdint.h>
#include <string>
#include <queue>
#include <map>
#define SRS_RTSP_FORWARD_SLEEP_US       (int64_t)(150*1000LL)

#define SRS_RTSP_AVC_PAYLOAD_TYPE       96
#define SRS_RTSP_AAC_PAYLOAD_TYPE       97
#define SRS_RTSP_HEVC_PAYLOAD_TYPE      98
class SrsSource;
class SrsRequest;
class SrsSharedPtrMessage;
using namespace internal;

class ForwardRtspSample
{
public:
    ForwardRtspSample()
    {
        keyflag = 0;
        dts = -1;
        pts = -1;

        mediatype = -1;
        payloadtype -1;
        payload = new SrsSimpleBuffer();
        LB_ADD_MEM(payload, sizeof(SrsSimpleBuffer));
    }

    ~ForwardRtspSample()
    {
        if(payload)
        {
            srs_freep(payload);
        }
    }

public:
    // the timestamp in 90khz
    int64_t dts;
    int64_t pts;

    //media type: 0:video, 1:audio
    int mediatype;
    int payloadtype;
    int keyflag;
    // the payload bytes.
    SrsSimpleBuffer* payload;
};

#define DISABLE_FORWARD_RTSP_API
class ForwardRtspQueue
{
public:
    std::queue<ForwardRtspSample*>    m_vFwdMsgList;
    size_t     m_nmax_queue_size;
    SrsAvcAacCodec*                     m_pavccodec;
    SrsCodecSample*                     m_pavcsample;
    SrsAvcAacCodec*                     m_paaccodec;
    SrsCodecSample*                     m_paacsample;

    bool                                m_bwait_keyframe;
    bool                                m_bsend_avc_seq_hdr;
    bool                                m_bsend_aac_seq_hdr;

    
public:
    ForwardRtspQueue();

    ~ForwardRtspQueue();

    int enqueue(SrsSharedPtrMessage* pmsg);

    int enqueue_avc(SrsAvcAacCodec* codec, SrsCodecSample* sample, int64_t pts);

    int enqueue_aac(SrsAvcAacCodec* codec, SrsCodecSample* sample, int64_t pts);

    int get_queue_size();

    int push_back(ForwardRtspSample* psample);

    ForwardRtspSample* dump_packet();

    int get_sps_pps(std::string& sps, std::string& pps);

    int get_aac_sequence_hdr(std::string& audio_cfg);

    bool is_codec_ok();
};

class SrsForwardRtsp:public ForwardRtspQueue, public ISrsReusableThreadHandler
{
public:
    SrsForwardRtsp(SrsRequest* req);
    ~SrsForwardRtsp();

    int initialize(const char* prtsp_url, const char* prtsp_log_url);

    int set_raw_data_path(const char* prawpath);

    int publish();

    int unpublish();

    int start();

    void on_thread_start();

    int cycle();

    void on_thread_stop();

    void stop();

    bool is_forward_rtsp_enable();

    static int RtspCallback(int nUserID, E_Event_Code eHeaderEventCode);

protected:
    SrsReusableThread rtsp_forward_thread;
    std::string     m_sForwardRtspUrl;
    std::string     m_sFwdRtspLogUrl;
    std::string     m_sRtspUrl;
    std::string     m_sFwdRtspRawDataDir;
    SrsRequest*     m_pReq;
    bool            m_bRuning;
    long            m_lConnectID;
    static bool     m_bInit;
    FILE*           m_pvideofile;
    FILE*           m_paudiofile;
};

#endif
