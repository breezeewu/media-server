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

#include <srs_app_rtsp.hpp>

#include <algorithm>

#include <srs_app_config.hpp>
#include <srs_kernel_error.hpp>
#include <srs_rtsp_stack.hpp>
#include <srs_app_st.hpp>
#include <srs_kernel_log.hpp>
#include <srs_app_utility.hpp>
#include <srs_core_autofree.hpp>
#include <srs_kernel_stream.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_rtmp_amf0.hpp>
#include <srs_rtmp_utility.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_raw_avc.hpp>
#include <srs_kernel_codec.hpp>
#include <srs_app_pithy_print.hpp>
#include <lbsp_openssl_utility.hpp>
//#include <lbsp_media_aac_cfg.hxx>
#include <srs_app_forward_rtsp.hpp>
//#include <lbsp_media_aac_cfg.hxx>
#include <lbsp_utility_common.hpp>
#include <srs_app_tls_socket.hpp>
#include <lbsp_utility_string.hpp>
#include <srs_app_http_hooks.hpp>
#include <srs_protocol_json.hpp>
#include <lbsp_media_rtcp.hpp>
#include <lbsp_media_parser.hpp>
#include <lbsp_io_http_client.hpp>
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
//#include "lbsp_ipc_record.hpp"
//#include <lbsp_media_avcc.hxx>
#endif
using namespace std;
using namespace lbsp_util;
#ifdef SRS_AUTO_STREAM_CASTER
SrsRtpConn::SrsRtpConn(SrsRtspConn* r, int p, int sid)
{
    rtsp = r;
    _port = p;
    stream_id = sid;
    // TODO: support listen at <[ip:]port>
    listener = new SrsUdpListener(this, "0.0.0.0", p);
    
    LB_ADD_MEM(listener, sizeof(SrsUdpListener));
    cache = new SrsRtpPacket();
    LB_ADD_MEM(cache, sizeof(SrsRtpPacket));
    pprint = SrsPithyPrint::create_caster();
}

SrsRtpConn::~SrsRtpConn()
{
    srs_freep(listener);
    srs_freep(cache);
    srs_freep(pprint);
}

int SrsRtpConn::port()
{
    return _port;
}

int SrsRtpConn::listen()
{
    return listener->listen();
}

int SrsRtpConn::on_udp_packet(sockaddr_in* from, char* buf, int nb_buf)
{
    int ret = ERROR_SUCCESS;

    pprint->elapse();

    if (true) {
        lazy_bitstream stream;

        if ((ret = stream.initialize(buf, nb_buf)) != ERROR_SUCCESS) {
            return ret;
        }
    
        SrsRtpPacket pkt;
        if ((ret = pkt.decode(&stream)) != ERROR_SUCCESS) {
            srs_error("rtsp: decode rtp packet failed. ret=%d", ret);
            return ret;
        }

        if (pkt.chunked) {
            if (!cache) {
                cache = new SrsRtpPacket();
                LB_ADD_MEM(cache, sizeof(SrsRtpPacket));
            }
            cache->copy(&pkt);
            cache->get_payload()->append(pkt.get_payload()->bytes(), pkt.get_payload()->length());
            if (!cache->completed && pprint->can_print()) {
                srs_trace("<- "SRS_CONSTS_LOG_STREAM_CASTER" rtsp: rtp chunked %dB, age=%d, vt=%d/%u, sts=%u/%#x/%#x, paylod=%dB", 
                    nb_buf, pprint->age(), cache->version, cache->payload_type, cache->sequence_number, cache->timestamp, cache->ssrc, 
                    cache->get_payload()->length()
                );
                return ret;
            }
        } else {
            srs_freep(cache);
            cache = new SrsRtpPacket();
            LB_ADD_MEM(cache, sizeof(SrsRtpPacket));
            cache->reap(&pkt);
        }
    }

    if (pprint->can_print()) {
        srs_trace("<- "SRS_CONSTS_LOG_STREAM_CASTER" rtsp: rtp #%d %dB, age=%d, vt=%d/%u, sts=%u/%u/%#x, paylod=%dB, chunked=%d", 
            stream_id, nb_buf, pprint->age(), cache->version, cache->payload_type, cache->sequence_number, cache->timestamp, cache->ssrc, 
            cache->get_payload()->length(), cache->chunked
        );
    }

    // always free it.
    SrsAutoFree(SrsRtpPacket, cache);
    
    if ((ret = rtsp->on_rtp_packet(cache, stream_id)) != ERROR_SUCCESS) {
        srs_error("rtsp: process rtp packet failed. ret=%d", ret);
        return ret;
    }

    return ret;
}

SrsRtspAudioCache::SrsRtspAudioCache()
{
    dts = 0;
    audio_samples = NULL;
    payload = NULL;
}

SrsRtspAudioCache::~SrsRtspAudioCache()
{
    srs_freep(audio_samples);
    srs_freep(payload);
}

SrsRtspJitter::SrsRtspJitter()
{
    delta = 0;
    previous_timestamp = 0;
    pts = 0;
}

SrsRtspJitter::~SrsRtspJitter()
{
}

int64_t SrsRtspJitter::timestamp()
{
    return pts;
}

int SrsRtspJitter::correct(int64_t& ts)
{
    int ret = ERROR_SUCCESS;

    if (previous_timestamp == 0) {
        previous_timestamp = ts;
    }

    delta = srs_max(0, ts - previous_timestamp);
    if (delta > 90000) {
        delta = 0;
    }

    previous_timestamp = ts;

    ts = pts + delta;
    pts = ts;    

    return ret;
}

#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
int SrsRtspPlayDispatcher::open_record_file(const char* prec_path)
{
    int ret = -1;
    close_record_file();
    m_prec_info = new ipc_record_info;
    LB_ADD_MEM(m_prec_info, sizeof(ipc_record_info));
    memset(m_prec_info, 0, sizeof(ipc_record_info));
    lstart_pts = INT64_MIN;
    if(NULL == m_prec_demux)
    {
        m_prec_demux = new RecordDemux();
        LB_ADD_MEM(m_prec_demux, sizeof(RecordDemux));
        ret = m_prec_demux->open(prec_path, m_prec_info) ? 0 : -1;//("154632_1_0_d");
        srs_rtsp_debug("ret:%d = m_prec_demux->open(prec_path:%s, m_prec_info)\n", ret, prec_path);
        if(ret < 0)
        {
            srs_error("ret:%d = m_prec_demux->open(\"154632_1_0_d\") failed\n", ret);
            srs_freep(m_prec_demux);
            //delete m_prec_demux;
            //m_prec_demux = NULL;
            return ret;
        }
    }

    m_ppkt_buf = new uint8_t[1024*1024];
    m_npkt_buf_len = 1024*1024;
    LB_ADD_MEM(m_ppkt_buf, m_npkt_buf_len);

    return ret;
}

void SrsRtspPlayDispatcher::close_record_file()
{
    srs_rtsp_debug("close_record_file begin\n");
    if(m_prec_demux)
    {
        srs_freep(m_prec_demux);
        //delete m_prec_demux;
        //m_prec_demux = NULL;
    }

    if(m_prec_info)
    {
        srs_freep(m_prec_info);
        //delete m_prec_info;
        //m_prec_info = NULL;
    }
    if(m_ppkt_buf)
    {
        srs_freepa(m_ppkt_buf);
        //delete[] m_ppkt_buf;
        //m_ppkt_buf = NULL;
    }
    m_npkt_buf_len = 0;
}

int SrsRtspPlayDispatcher::read_packet_from_record()
{
    if(m_prec_demux && m_ppkt_buf)
    {
        int64_t pts = 0;
        ipc_packet_header pkt;

        int ret = m_prec_demux->read_packet(&pkt, (char*)m_ppkt_buf, m_npkt_buf_len, true);
        srs_rtsp_debug("ret:%d = m_prec_demux->read_packet, pkt.pts:%" PRId64 ", pkt.size:%d\n", ret, pkt.pts, pkt.size);
        if(ret < 0)
        {
            srs_error("ret:%d = m_prec_demux->read_packet failed\n", ret);
            m_prec_demux->close();
            ret = m_prec_demux->open(SRS_RTSP_RECORD_FILE);
            lpts_offset += llast_pts + 30;
            return -1;
        }
        else
        {
            pts = pkt.pts;
            srs_trace("read record frame success ret:%d, pkt.keyflag:%d, pkt.size:%d, pts:%"PRId64"\n", ret, pkt.keyflag, pkt.size, pts);
            srs_trace_memory((char*)m_ppkt_buf, 32);
        }
        if(INT64_MIN == lstart_pts)
        {
            lstart_pts = pts;
        }
        srs_rtsp_debug("pts:%"PRId64" = pts:%"PRId64" - lstart_pts:%"PRId64"\n", pts - lstart_pts, pts, lstart_pts);
        pts = pts - lstart_pts;
        ForwardRtspSample* prrs = new ForwardRtspSample();
        LB_ADD_MEM(prrs, sizeof(ForwardRtspSample));
        llast_pts = pts;
        prrs->pts = prrs->dts = pts + lpts_offset;
        if(0 == pkt.codec_id || 1 == pkt.codec_id)
        {
            prrs->mediatype = 0;
            prrs->payloadtype = 0 == pkt.codec_id ? SRS_RTSP_AVC_PAYLOAD_TYPE : SRS_RTSP_HEVC_PAYLOAD_TYPE;
            prrs->keyflag = pkt.keyflag;
            prrs->payload->append((char*)m_ppkt_buf, pkt.size);
        }
        else
        {
            prrs->mediatype = 1;
            prrs->payloadtype = 97;
            int adts_hdr_len = 0;
            if(m_ppkt_buf[0] &0xff)
            {
                adts_hdr_len = 7;
            }
            prrs->payload->append((char*)m_ppkt_buf + adts_hdr_len, pkt.size - adts_hdr_len);
        }
        pfwd_rtsp_que->push_back(prrs);
        srs_rtsp_debug("read_frame from record pt:%d, pts:%"PRId64", size:%d\n", prrs->payloadtype, pts, pkt.size);
        return 0;
    }

    return -1;
}
#endif

SrsRtspPlayDispatcher::SrsRtspPlayDispatcher()//:rtsp_fwd_thread("rtsp play dispatcher", this, SRS_RTSP_FORWARD_SLEEP_US)
{
    prtsp_fwd_thread = NULL;
    ussrc           = 0;
    rtsp_stack      = NULL;
    pfwd_rtsp_que   = NULL;
    psource         = NULL;
    lstart_pts      = INT64_MIN;
    lpts_offset     = 0;
    llast_pts       = 0;
#ifdef SRS_READ_RTP_PACKET_FROM_FILE
    m_pfile = NULL;
#endif
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
    m_prec_demux = NULL;
    m_ppkt_buf = NULL;//new uint8_t[1024*1024];
    m_npkt_buf_len = 0;
    m_prec_info = NULL;
#endif
}

SrsRtspPlayDispatcher::~SrsRtspPlayDispatcher()
{
    srs_freep(pfwd_rtsp_que);

    for(std::map<int, RTP_INFO*>::iterator it = m_vrtp_info_list.begin(); it != m_vrtp_info_list.end(); it++)
    {
        srs_freep(it->second);
        it->second = NULL;
    }

    m_vrtp_info_list.clear();
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
    close_record_file();
#endif
}

int SrsRtspPlayDispatcher::add_rtp_info(int pt, RTP_INFO* prtpinfo)
{
    if(NULL == prtpinfo)
    {
        assert(0);
        return -1;
    }

    std::map<int, RTP_INFO*>::iterator it = m_vrtp_info_list.find(pt);
    if(it != m_vrtp_info_list.end())
    {
        srs_freep(it->second);
        m_vrtp_info_list.erase(it);
    }

    RTP_INFO* prtp_info = new RTP_INFO;
    LB_ADD_MEM(prtp_info, sizeof(RTP_INFO));
    srs_rtsp_debug("new RTP_INFO, prtp_info->seq_number:%d, prtp_info->rtp_timestamp:%u\n", prtp_info->seq_number, prtp_info->rtp_timestamp);
    *prtp_info = *prtpinfo;
    m_vrtp_info_list[pt] = prtp_info;
    return 0;
}

const RTP_INFO* SrsRtspPlayDispatcher::get_rtp_info(int pt)
{
    std::map<int, RTP_INFO*>::iterator it = m_vrtp_info_list.find(pt);
    if(it != m_vrtp_info_list.end())
    {
        return it->second;
    }

    return NULL;
}


int SrsRtspPlayDispatcher::init_rtsp_dispatch(SrsRtspStack* rtsp, std::string devicesn)
{
    srs_trace("(rtsp:%p, devicesn:%s)\n", rtsp, devicesn.c_str());
    rtsp_stack = rtsp;
    device_sn = devicesn;

    return 0;
}

int SrsRtspPlayDispatcher::start()
{
    srs_rtsp_debug("SrsRtspPlayDispatcher::start() begin\n");
    if(NULL == rtsp_stack || device_sn.empty())
    {
        srs_error("rtsp_stack:%p or device_sn:%s not init\n", rtsp_stack, device_sn.c_str());
        return -1;
    }
    if(NULL == prtsp_fwd_thread)
    {
        prtsp_fwd_thread = new SrsReusableThread("rtsp play dispatcher", this, 20000);
        LB_ADD_MEM(prtsp_fwd_thread, sizeof(SrsReusableThread));
        srs_rtsp_debug("prtsp_fwd_thread:%p = new SrsReusableThread(rtsp play dispatcher, this, 20000)\n", prtsp_fwd_thread);
    }
    if(device_sn.empty())
    {
        srs_error("device_sn:%s is empty\n", device_sn.c_str());
        return -1;
    }
    int ret = 0;

    if(NULL == pfwd_rtsp_que)
    {
        pfwd_rtsp_que = new ForwardRtspQueue();
        LB_ADD_MEM(pfwd_rtsp_que, sizeof(ForwardRtspQueue));
    }

    ret = prtsp_fwd_thread->start();
    //srs_rtsp_debug("ret:%d = prtsp_fwd_thread->start()\n", ret);
#ifdef SRS_READ_RTP_PACKET_FROM_FILE
    if(NULL == m_pfile)
    {
        m_pfile = fopen("rtsp.data", "rb");
        srs_rtsp_debug("m_pfile:%p = fopen(rtsp.data, rb)\n", m_pfile);
    }
#endif

    return ret;
}

void SrsRtspPlayDispatcher::on_thread_start()
{
    int ret = 0;
    bruning = 1;
    llast_pts = 0;
    srs_rtsp_debug("on_thread_start(), rtsp_stack:%p, pfwd_rtsp_que:%p\n", rtsp_stack, pfwd_rtsp_que);

#if !defined(SRS_READ_RTP_PACKET_FROM_FILE) && !defined(SRS_READ_PACKET_FROM_RECORD_FILE)
    unsigned long begin_time = get_sys_time();
    unsigned long timeout_ms = 20000;
    ret = 0;
    
    do{
        psource = SrsSource::find_srssource_by_deviceid(device_sn);
        if(psource)
        {
            ret = psource->add_forward_queue(pfwd_rtsp_que);
        }
        else
        {
            st_usleep(20000);
        }
    }while (NULL == psource && get_sys_time() - begin_time < timeout_ms);
#endif
/*
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
    ret = open_record_file("154632_1_0_d");
    //ret = m_prec_demux->seek(16000);
    srs_trace("ret:%d =  open_record_file(154632_1_0_d)\n", ret);
#endif*/
}

int SrsRtspPlayDispatcher::cycle()
{
    //srs_rtsp_debug("SrsRtspPlayDispatcher::cycle begin\n");
    int ret = 0;
#if !defined(SRS_READ_RTP_PACKET_FROM_FILE) && !defined(SRS_READ_PACKET_FROM_RECORD_FILE)
    if(NULL == psource)
    {
        lberror("device %s not foud, dispatch failed\n", device_sn.c_str());
        return -1;
    }
#endif
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
    ret = read_packet_from_record();
    if(ret < 0)
    {
        return -1;
    }
#endif
#if !defined(SRS_READ_RTP_PACKET_FROM_FILE) || defined(SRS_READ_PACKET_FROM_RECORD_FILE)
    while(bruning && pfwd_rtsp_que->get_queue_size() > 0)
    {
        if(pfwd_rtsp_que->get_queue_size() > 50)
        {
            srs_debug("pfwd_rtsp_que->get_queue_size():%d\n", pfwd_rtsp_que->get_queue_size());
        }
        ForwardRtspSample* sample = pfwd_rtsp_que->dump_packet();
        //srs_rtsp_debug("send packet:sample->payloadtype:%d, sample->payload->bytes():%p, sample->payload->length():%d, sample->pts:%"PRId64"\n", sample->payloadtype, sample->payload->bytes(), sample->payload->length(), sample->pts);
        ret = rtsp_stack->send_packet(ussrc, sample->payloadtype, sample->payload->bytes(), sample->payload->length(), sample->pts);
        //srs_rtsp_debug("ret:%d = rtsp_stack->send_packet(ussrc:%u, sample->payloadtype:%d, sample->payload->bytes():%p, sample->payload->length():%d, sample->pts:%"PRId64")\n",  ret, ussrc, sample->payloadtype, sample->payload->bytes(), sample->payload->length(), sample->pts);
        if(ret < 0)
        {
            srs_error("ret:%d = rtsp_stack->send_packet(ussrc:%u, pt:%d, pdata:%p, len:%d, sample->pts:%"PRId64") failed\n", ret, ussrc, sample->payloadtype, sample->payload->bytes(), sample->payload->length(), sample->pts);
            srs_freep(sample);
            break;
        }
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
        ret = read_packet_from_record();
        if(ret < 0)
        {
            //return -1;
        }
#endif
        srs_freep(sample);
        st_usleep(35000);
    }
    
#else
    char rtp_buf[1500];
    srs_rtsp_debug("m_pfile:%p, sizeof(int):%d\n", m_pfile, sizeof(int));
    uint8_t channel_id = 0;
    while(bruning && m_pfile)
    {
        int pkt_len = read_rtsp_over_tcp_packet(rtp_buf, 1500, &channel_id);
        int len = rtsp_stack->send_data(rtp_buf, pkt_len);
        if(len < 0)
        {
            srs_error("len:%d = rtsp_stack->send_data(rtp_buf:%p, offset:%d) failed\n", len, rtp_buf);
            return len;
        }
        st_usleep(10000);
    }
    srs_rtsp_debug("bruning:%d && m_pfile:%p\n", (int)bruning, m_pfile);
#endif
    return ret;
}

void SrsRtspPlayDispatcher::on_thread_stop()
{
    srs_rtsp_debug("on_thread_stop()\n");
    bruning = 0;
    if(psource)
    {
        psource->remove_forward_queue(pfwd_rtsp_que);
        //psource->notify_live_show(device_sn, e_ipc_tigger_type_echoshow, 0);
        srs_debug("on_thread_stop->release_ref");
        psource->release_ref();
        psource = NULL;
    }
#ifdef SRS_READ_RTP_PACKET_FROM_FILE
    if(m_pfile)
    {
        fclose(m_pfile);
        m_pfile = NULL;
    }
#endif
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
    close_record_file();
#endif
}

void SrsRtspPlayDispatcher::stop()
{
    srs_rtsp_debug("stop() begin, prtsp_fwd_thread:%p\n", prtsp_fwd_thread);
    bruning = false;
    if(prtsp_fwd_thread)
    {
        prtsp_fwd_thread->stop();
        //delete prtsp_fwd_thread;
        srs_freep(prtsp_fwd_thread);
        prtsp_fwd_thread = NULL;
        srs_rtsp_debug("delete prtsp_fwd_thread:%p\n", prtsp_fwd_thread);
    }
    //rtsp_fwd_thread.stop();
    if(pfwd_rtsp_que)
    {
        //delete pfwd_rtsp_que;
        srs_freep(pfwd_rtsp_que);
        pfwd_rtsp_que = NULL;
    }
    srs_rtsp_debug("stop() end\n");
}

int SrsRtspPlayDispatcher::wait_for_live_stream(int timeout_ms)
{
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
    int ret = 0;
    if(NULL == m_prec_demux)
    {
        ret = open_record_file(SRS_RTSP_RECORD_FILE);
        SRS_CHECK_RESULT(ret);
    }

    if(m_prec_demux)
    {
        ret = m_prec_demux->seek(0);
        SRS_CHECK_RESULT(ret);
        ret = m_prec_demux->parser_sequence_header(vps, sps, pps, adts_hdr);
        srs_rtsp_debug("ret:%d = m_prec_demux->parser_sequence_header(vps, sps, pps, adts_hdr)\n", ret);
        SRS_CHECK_RESULT(ret);
        ret = m_prec_demux->seek(4000);
        srs_rtsp_debug("ret:%d = m_prec_demux->seek(6000)", ret);
    }
    return ret;
#else
    unsigned long begin_time = get_sys_time();
    //srs_trace("wait_for_live_stream(timeout_ms:%d) begin_time:%lu\n", timeout_ms, begin_time);
    psource = SrsSource::wait_for_connectioned(device_sn, timeout_ms);
    /*do
    {
        if(NULL == psource)
        {
            psource = SrsSource::find_srssource_by_deviceid(device_sn);
            //srs_trace("psource:%p = SrsSource::find_srssource_by_deviceid(device_sn:%s)\n", psource, device_sn.c_str());
        }
        if(psource && psource->is_metadata_ready())
        {
            srs_rtsp_debug("codec ok, prepare  to play!");
           return 0; 
        }
        else
        {
            st_usleep(20000);
            //srs_rtsp_debug("st_usleep(20000)");
        }
    } while (get_sys_time() - begin_time < timeout_ms);*/
    if(NULL == psource)
    {
        srs_error("wait for live stream timeout!, get_sys_time():%lu, timeout:%ld, timeout_ms:%d, psource:%p\n", get_sys_time(), get_sys_time() - begin_time, timeout_ms, psource);
        return -1;
    }
    //
    return 0;
#endif
}

int SrsRtspPlayDispatcher::get_sps_and_pps(int& codec_id, string& vps, string& sps, string& pps)
{
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
    if(m_prec_info)
    {
        codec_id = m_prec_info->vcodec_id == 0 ? SrsCodecVideoAVC : SrsCodecVideoHEVC;
        vps = this->vps;
        sps = this->sps;
        pps = this->pps;
        //pps.append("\0");
        return 0;
    }
    else
    {
        return -1;
    }
#else
    if(psource)
    {
        return psource->get_sps_pps(codec_id, vps, sps, pps);
    }
    else
    {
        srs_error("no stream source availabe, psource:%p\n", psource);
    }
    
#endif
}

int SrsRtspPlayDispatcher::get_audio_config(string& acfg)
{
#ifdef SRS_READ_PACKET_FROM_RECORD_FILE
    acfg = adts_hdr;
#else
    return psource->get_aac_config(acfg);
#endif
}

uint32_t SrsRtspPlayDispatcher::gen_ssrc()
{
    //return srand((unsigned)time(NULL));
    return (uint32_t)get_sys_time();
}

#ifdef SRS_READ_RTP_PACKET_FROM_FILE
int SrsRtspPlayDispatcher::read_rtsp_over_tcp_packet(char* pbuf, int len, uint8_t* pchannel_id)
{
    SRS_CHECK_PARAM_PTR(pbuf, -1);
    SRS_CHECK_PARAM_PTR(m_pfile, -1);
    char rtp_buf[1500];
#if 0
    //int len = 0;
    int readlen = fread(&len, 1, sizeof(int), m_pfile);
    if(readlen <= 0)
    {
        srs_trace("rtp file reach end of stream\n");
        return -1;
    }
    readlen = fread(pbuf, 1, len, m_pfile);

    return readlen;
#else
    
    //srs_rtsp_debug("m_pfile:%p, sizeof(int):%d\n", m_pfile, sizeof(int));
    int pkt_len = 0;
    int offset = 0;
    int readlen = fread(pbuf, 1, sizeof(int), m_pfile);
    if(readlen <= 0)
    {
        srs_trace("rtp file reach end of stream\n");
        return -1;
    }
    
    //srs_trace_memory(pbuf, 16);
    offset += readlen;
    if(pchannel_id)
    {
        *pchannel_id = pbuf[1];
    }
    pkt_len = (pbuf[2]&0xff) << 8;
    srs_trace("rtsp over tcp header: pbuf[2]:%0x, pbuf[3]:%0x, pkt_len:%d\n", (int)pbuf[2], (int)pbuf[3], pkt_len);
    pkt_len |= pbuf[3]&0xff;
    srs_rtsp_debug("before fread(pbuf:%p + offset:%d, 1, pkt_len:%d, m_pfile:%p)\n", pbuf, offset, pkt_len, m_pfile);
    readlen = fread(pbuf + offset, 1, pkt_len, m_pfile);
    srs_rtsp_debug("readlen:%d = fread(&pkt_len:%d, 1, sizeof(pkt_len), m_pfile:%p)\n", readlen, pkt_len, 1, m_pfile);
    if(readlen <= 0)
    {
        srs_trace("rtp file reach end of stream\n");
        return -1;
    }
    offset += readlen;
    return offset;
#endif
}
#endif
SrsRtspConn::SrsRtspConn(SrsRtspCaster* c, st_netfd_t fd, std::string o)
{
    output_template = o;

    session = "";
    video_rtp = NULL;
    audio_rtp = NULL;

    caster = c;
    stfd = fd;
    /*int no_blk_flags = fcntl(st_netfd_fileno(fd), F_GETFL, 0);
    int block_flags = no_blk_flags &(~O_NONBLOCK);
    int ret = fcntl(st_netfd_fileno(fd), F_SETFL, block_flags);*/
    std::string ip = srs_get_local_ip(st_netfd_fileno(fd), &m_nrtsp_tcp_port);
    //m_nrtsp_tcp_port = srs_get_local_port(st_netfd_fileno(fd));
    //srs_rtsp_debug("ip:%s, port:%d\n", ip.c_str(), m_nrtsp_tcp_port);
    if(SRS_RTSP_TLS_PORT == m_nrtsp_tcp_port)
    {
        skt = new SrsSSLSocket(fd);
        //srs_rtsp_debug("skt:%p = new SrsSSLSocket(fd:%d)\n", skt, fd);
        LB_ADD_MEM(skt, sizeof(SrsSSLSocket));
    }
    else
    {
        skt = new SrsStSocket(fd);
        //srs_rtsp_debug("skt:%p = new SrsStSocket(fd:%d)\n", skt, fd);
        LB_ADD_MEM(skt, sizeof(SrsStSocket)); 
    }
    rtsp = new SrsRtspStack(skt);
    LB_ADD_MEM(rtsp, sizeof(SrsRtspStack));
    trd = new SrsOneCycleThread("rtsp", this);
    LB_ADD_MEM(trd, sizeof(SrsOneCycleThread));

    req = NULL;
    io = NULL;
    client = NULL;
    stream_id = 0;
    vjitter = new SrsRtspJitter();
    LB_ADD_MEM(vjitter, sizeof(SrsRtspJitter));
    ajitter = new SrsRtspJitter();
    LB_ADD_MEM(ajitter, sizeof(SrsRtspJitter));

    avc = new SrsRawH264Stream();
    LB_ADD_MEM(avc, sizeof(SrsRawH264Stream));
    aac = new SrsRawAacStream();
    LB_ADD_MEM(aac, sizeof(SrsRawAacStream));
    acodec = new SrsRawAacStreamCodec();
    LB_ADD_MEM(acodec, sizeof(SrsRawAacStreamCodec));
    acache = new SrsRtspAudioCache();
    LB_ADD_MEM(acache, sizeof(SrsRtspAudioCache));

    rtsp_session_name = "Matroska video+audio+(optional)subtitles, streamed by the LIVE555 Media Server";//"SRS h264 stream, streamed by srs rtsp server";

    start_time = -1.0;
    stop_time  = -1.0;
    m_mauth_list["dawson"] = "zwu123456";
    m_pvideo_rtp_info = NULL;
    m_paudio_rtp_info = NULL;
    prtsp_play_dispatcher = NULL;
}

SrsRtspConn::~SrsRtspConn()
{
    //srs_rtsp_debug("~SrsRtspConn begin, stfd:%p, this:%p\n", stfd, this);
    srs_close_stfd(stfd);
    //srs_rtsp_debug("~SrsRtspConn after srs_close_stfd(stfd:%p)\n", stfd);
    srs_freep(video_rtp);
    srs_freep(audio_rtp);
    //srs_rtsp_debug("~SrsRtspConn after srs_freep(audio_rtp:%p)\n", audio_rtp);
    srs_freep(trd);
    srs_freep(skt);
    srs_freep(rtsp);
    //srs_rtsp_debug("~SrsRtspConn after srs_freep(rtsp:%p)\n", rtsp);
    srs_freep(client);
    srs_freep(io);
    srs_freep(req);
    //srs_rtsp_debug("~SrsRtspConn after srs_freep(req:%p)\n", req);
    srs_freep(vjitter);
    srs_freep(ajitter);
    srs_freep(acodec);
    srs_freep(acache);
    //srs_rtsp_debug("~SrsRtspConn end\n");
}

int SrsRtspConn::serve()
{
    return trd->start();
}

int SrsRtspConn::do_cycle()
{
    int ret = ERROR_SUCCESS;

    // retrieve ip of client.
    std::string ip = srs_get_peer_ip(st_netfd_fileno(stfd));
    //srs_trace("rtsp: serve %s", ip.c_str());

    // consume all rtsp messages.
    for (;;) {
        SrsRtspRequest* rtspreq = NULL;
        if ((ret = rtsp->recv_message(&rtspreq)) != ERROR_SUCCESS) {
            if (!srs_is_client_gracefully_close(ret)) {
                srs_error("rtsp: recv request failed. ret=%d", ret);
            }
            return ret;
        }
        SrsAutoFree(SrsRtspRequest, rtspreq);
        //srs_rtsp_debug("rtsp: got rtsp request, ret:%d, method:%s\n", ret, rtspreq->method.c_str());

        if (rtspreq->is_options()) {
            SrsRtspOptionsResponse* res = new SrsRtspOptionsResponse(rtspreq->seq);
            LB_ADD_MEM(res, sizeof(SrsRtspOptionsResponse));
            SrsAutoFree(SrsRtspOptionsResponse, res);
            res->session = session;
            if ((ret = rtsp->send_message(res)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: send OPTIONS response failed. ret=%d", ret);
                }
                return ret;
            }
        } else if (rtspreq->is_announce()) {
            if (rtsp_tcUrl.empty()) {
                rtsp_tcUrl = rtspreq->uri;
            }
            size_t pos = string::npos;
            if ((pos = rtsp_tcUrl.rfind(".sdp")) != string::npos) {
                rtsp_tcUrl = rtsp_tcUrl.substr(0, pos);
            }

            if ((pos = rtsp_tcUrl.rfind("/")) != string::npos) {
                rtsp_stream = rtsp_tcUrl.substr(pos + 1);
                req->devicesn = rtsp_stream;
                rtsp_tcUrl = rtsp_tcUrl.substr(0, pos);
            }

            srs_assert(rtspreq->sdp);
            video_id = ::atoi(rtspreq->sdp->video_stream_id.c_str());
            audio_id = ::atoi(rtspreq->sdp->audio_stream_id.c_str());
            video_codec = rtspreq->sdp->video_codec;
            audio_codec = rtspreq->sdp->audio_codec;
            audio_sample_rate = ::atoi(rtspreq->sdp->audio_sample_rate.c_str());
            audio_channel = ::atoi(rtspreq->sdp->audio_channel.c_str());
            h264_sps = rtspreq->sdp->video_sps;
            h264_pps = rtspreq->sdp->video_pps;
            aac_specific_config = rtspreq->sdp->audio_sh;
            srs_trace("rtsp: video(#%d, %s, %s/%s), audio(#%d, %s, %s/%s, %dHZ %dchannels), %s/%s", 
                video_id, video_codec.c_str(), rtspreq->sdp->video_protocol.c_str(), rtspreq->sdp->video_transport_format.c_str(), 
                audio_id, audio_codec.c_str(), rtspreq->sdp->audio_protocol.c_str(), rtspreq->sdp->audio_transport_format.c_str(),
                audio_sample_rate, audio_channel, rtsp_tcUrl.c_str(), rtsp_stream.c_str()
            );

            SrsRtspResponse* res = new SrsRtspResponse(rtspreq->seq);
            LB_ADD_MEM(res, sizeof(SrsRtspResponse));
            SrsAutoFree(SrsRtspResponse, res);

            res->session = session;
            if ((ret = rtsp->send_message(res)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: send ANNOUNCE response failed. ret=%d", ret);
                }
                return ret;
            }
        }
        else if(rtspreq->is_describe())
        {
            bool brtsp_auth = true;
#if 1
            if(NULL == req)
            {
                req = new SrsRequest();
                LB_ADD_MEM(req, sizeof(SrsRequest));
                srs_debug("req:%p = new SrsRequest()\n", req);
            }
           
            string path = rtspreq->uri;
            size_t param_pos = path.find_last_of("?");
            if(std::string::npos != param_pos)
            {
                req->param = path.substr(param_pos+1);
                path = path.substr(0, param_pos);
                srs_rtsp_debug("have req->param:%s, path:%s, param_pos:%ld\n", req->param.c_str(), path.c_str(), param_pos);
            }
            size_t pos = path.find_first_of("/", 7);
            if(std::string::npos == pos)
            {
                srs_error("pos:%ld = path:%s.find_first_of(/, 7) failed\n", pos, path.c_str());
                return -1;
            }
            std::vector<string> pathlist = string_splits(path.substr(pos+1), "/");
            if(pathlist.size() >= 3)
            {
                req->token = pathlist[0];
                req->appkey = pathlist[1];
                req->devicesn = pathlist[2];
            }
            else if(pathlist.size() >= 2)
            {
                req->appkey = pathlist[0];
                req->devicesn = pathlist[1];
            }
            else
            {
                srs_error("Invalid rtsp path\n", path.c_str());
                return -1;
            }
            
            srs_rtsp_debug("req->token:%s, req->appkey:%s, req->devicesn:%s\n", req->token.c_str(), req->appkey.c_str(), req->devicesn.c_str());
            if(req->token.empty() && !req->param.empty())
            {
                ret = parser_value_from_http_param(req->param, "token", req->token);
            }
            ret = on_connect(req);
            //ret = 0;
            /*if (ret < 0)
            {
                char wauth[256] = {0};
                srs_rtsp_debug("rtsp descripe auth failed!\n");
                SrsRtspResponse* res = new SrsRtspResponse(rtspreq->seq);
                LB_ADD_MEM(res, sizeof(SrsRtspResponse));
                SrsAutoFree(SrsRtspResponse, res);
                res->session = session;
                res->status = SRS_CONSTS_RTSP_Forbidden;
                //sprintf(wauth, "WWW-Authenticate: Digest realm=\"SRS Streaming Media\", nonce=\"%s\"", lbsp_utility::CMD5Maker::gen_md5_by_time().c_str());
                //res->ext_hdr = wauth;//string_format("WWW-Authenticate: Digest realm=\"SRS Streaming Media\", nonce=\"%s\"", CMD5Maker::gen_md5_by_time().c_str());
                if ((ret = rtsp->send_message(res)) != ERROR_SUCCESS) {
                    if (!srs_is_client_gracefully_close(ret)) {
                        srs_error("rtsp: send ANNOUNCE response failed. ret=%d", ret);
                    }
                    return ret;
                }
            }*/
            
            //SRS_CHECK_RESULT(ret);
            /*if(digest_auth_enable() && !on_digest_auth(rtspreq->method, rtspreq->pauthorize))
            {
                char wauth[256] = {0};
                srs_rtsp_debug("rtsp descripe auth failed!\n");
                SrsRtspResponse* res = new SrsRtspResponse(rtspreq->seq);
                LB_ADD_MEM(res, sizeof(SrsRtspResponse));
                SrsAutoFree(SrsRtspResponse, res);
                res->session = session;
                res->status = SRS_CONSTS_RTSP_Unauthorized;
                sprintf(wauth, "WWW-Authenticate: Digest realm=\"SRS Streaming Media\", nonce=\"%s\"", lbsp_utility::CMD5Maker::gen_md5_by_time().c_str());
                res->ext_hdr = wauth;//string_format("WWW-Authenticate: Digest realm=\"SRS Streaming Media\", nonce=\"%s\"", CMD5Maker::gen_md5_by_time().c_str());
                if ((ret = rtsp->send_message(res)) != ERROR_SUCCESS) {
                    if (!srs_is_client_gracefully_close(ret)) {
                        srs_error("rtsp: send ANNOUNCE response failed. ret=%d", ret);
                    }
                    return ret;
                }
            }*/
#else
            if(m_mauth_list.size() > 0)
            {
                brtsp_auth = false;
                if(rtspreq->pauthorize)
                {
                    srs_rtsp_debug("user name:%s, response:%s\n", rtspreq->pauthorize->get_attribute(SRS_RTSP_AUTH_USER_NAME).c_str(), rtspreq->pauthorize->get_attribute(SRS_RTSP_AUTH_RESPONSE).c_str());
                    for(std::map<std::string, std::string>::iterator it = m_mauth_list.begin(); it != m_mauth_list.end(); it++)
                    {
                        std::string pwdmd5 = rtspreq->pauthorize->gen_response_by_pwd(rtspreq->method, rtspreq->uri, it->first, it->second);
                        //std::string pwdmd5 = lbsp_utility::CMD5Maker::gen_md5_by_string(it->second.c_str());
                        srs_rtsp_debug("method:%s, uri:%s, user name:%s, pwd:%s, pwdmd5:%s\n", rtspreq->method.c_str(), rtspreq->uri.c_str(),  it->first.c_str(), it->second.c_str(), pwdmd5.c_str());
                        if(it->first == rtspreq->pauthorize->get_attribute(SRS_RTSP_AUTH_USER_NAME) && pwdmd5 == rtspreq->pauthorize->get_attribute(SRS_RTSP_AUTH_RESPONSE))
                        {
                            brtsp_auth = true;
                            break;
                        }
                    }
                }

                if(!brtsp_auth)
                {
                    char wauth[256] = {0};
                    srs_rtsp_debug("rtsp descripe auth failed!\n");
                    SrsRtspResponse* res = new SrsRtspResponse(rtspreq->seq);
                    LB_ADD_MEM(res, sizeof(SrsRtspResponse));
                    SrsAutoFree(SrsRtspResponse, res);
                    res->session = session;
                    res->status = SRS_CONSTS_RTSP_Unauthorized;
                    sprintf(wauth, "WWW-Authenticate: Digest realm=\"LIVE555 Streaming Media\", nonce=\"%s\"", lbsp_utility::CMD5Maker::gen_md5_by_time().c_str());
                    res->ext_hdr = wauth;//string_format("WWW-Authenticate: Digest realm=\"SRS Streaming Media\", nonce=\"%s\"", CMD5Maker::gen_md5_by_time().c_str());
                    if ((ret = rtsp->send_message(res)) != ERROR_SUCCESS) {
                        if (!srs_is_client_gracefully_close(ret)) {
                            srs_error("rtsp: send ANNOUNCE response failed. ret=%d", ret);
                        }
                        return ret;
                    }
                }

                /*else
                {
                    SrsRtspDescribeResponse* res = new SrsRtspDescribeResponse(req->seq);
                    std::string ip;
                    int ret = get_local_ip(ip);
                    if(ERROR_SUCCESS != ret)
                    {
                        srs_error("ret:%d = get_local_ip(ip:%s) failed\n", ret, ip.c_str());
                        return ret;
                    }
                    size_t pos = rtsp_tcUrl.find_last_of("\\");
                    if(std::npos != pos)
                    {
                        rtsp_media_title = rtsp_tcUrl.substr(pos+1);
                    }
                    res->init_sdp(ip, rtsp_session_name, rtsp_media_title);
                    if ((ret = rtsp->send_message(res)) != ERROR_SUCCESS) {
                        if (!srs_is_client_gracefully_close(ret)) {
                            srs_error("rtsp: send ANNOUNCE response failed. ret=%d", ret);
                        }
                        return ret;
                    }
                }*/
            }
#endif
            if(brtsp_auth)
            {
                size_t pos = string::npos;
                if(rtsp_tcUrl.empty())
                {
                    rtsp_tcUrl = rtspreq->uri;
                }
                if(NULL == req)
                {
                    req = new SrsRequest();
                    LB_ADD_MEM(req, sizeof(SrsRequest));
                }
                pos = rtsp_tcUrl.rfind("?");
                if(pos != string::npos)
                {
                    string param = rtsp_tcUrl.substr(pos + 1);
                    rtspreq->uri = rtsp_tcUrl = rtsp_tcUrl.substr(0, pos);
                    vector<string> strlist = string_splits(param, "&");
                    for(size_t i = 0; i < strlist.size(); i++)
                    {
                        string value = strlist[i];
                        string key;
                        string_split(value, key, "=");
                        srs_rtsp_debug("req:%p, key:%s, value:%s", req, key.c_str(), value.c_str());
                        if(req && "token" == key)
                        {
                            req->token = value;
                        }
                    }
                }
                
                //srs_rtsp_debug("pos:%d = rtsp_tcUrl.rfind(?), rtsp_tcUrl:%s", pos, rtsp_tcUrl.c_str());
                /*if(pos != string::npos)
                {
                    string param = rtsp_tcUrl.substr(pos + 1);
                    rtspreq->uri = rtsp_tcUrl = rtsp_tcUrl.substr(0, pos);
                    map<string, string> pair_list = read_key_value_pair(param, "&", "=");
                    for(map<string, string>::iterator it = pair_list.begin(); it != pair_list.end(); it++)
                    {
                        string key = it->first;//to_lower(it->first);
                        srs_rtsp_debug("key:%s, value:%s\n", key.c_str(), it->second.c_str());
                        if("token" == key && req)
                        {
                            //string token = srs_string_trim(it->second, "\"");
                            //srs_rtsp_debug("token:%s\n", token.c_str());
                            req->token = it->second;
                            srs_rtsp_debug("req->token:%s\n", req->token.c_str());
                        }
                    }
                    //srs_rtsp_debug("rtspreq->uri:%s, req->token:%s\n", rtspreq->uri.c_str(), req->token.c_str());
                }*/
                if ((pos = rtsp_tcUrl.rfind(".sdp")) != string::npos) {
                    rtsp_tcUrl = rtsp_tcUrl.substr(0, pos);
                }
                if ((pos = rtsp_tcUrl.rfind("/")) != string::npos) {
                    rtsp_stream = rtsp_tcUrl.substr(pos + 1);
                    if(req)
                    {
                        req->devicesn = rtsp_stream;
                    }
                    srs_rtsp_debug("req:%p\n", req);
                    rtsp_tcUrl = rtsp_tcUrl.substr(0, pos);
                }
                //srs_rtsp_debug("rtsp descripe auth success, rtsp_stream:%s\n", rtsp_stream.c_str());
                SrsRtspDescribeResponse* res = new SrsRtspDescribeResponse(rtspreq->seq);
                LB_ADD_MEM(res, sizeof(SrsRtspDescribeResponse));
                SrsAutoFree(SrsRtspDescribeResponse, res);
                std::string ip = srs_get_localhost_ip();
                //int ret = srs_get_localhost_ip();
                if(ip.empty())
                {
                    srs_error("ip:%s = srs_get_local_ip() failed\n", ip.c_str());
                    return -1;
                }
                pos = rtspreq->uri.find("/", strlen("rtsp://"));
                if(std::string::npos != pos)
                {
                    rtsp_media_title = rtspreq->uri.substr(pos+1);
                }
                res->init_sdp(ip, rtsp_session_name, rtsp_media_title);
                string vps, sps, pps, aac_cfg;
                int vpt = 0;
                int codec_id = 0;
#if 1
                if(NULL == prtsp_play_dispatcher)
                {
                    prtsp_play_dispatcher = new SrsRtspPlayDispatcher();
                    //srs_trace("prtsp_play_dispatcher:%p = new SrsRtspPlayDispatcher()\n", prtsp_play_dispatcher);
                    LB_ADD_MEM(prtsp_play_dispatcher, sizeof(SrsRtspPlayDispatcher));
                    prtsp_play_dispatcher->init_rtsp_dispatch(rtsp, rtsp_stream);
                }

                //srs_trace("prtsp_play_dispatcher:%p->wait_for_live_stream() begin\n", prtsp_play_dispatcher);
                ret = prtsp_play_dispatcher->wait_for_live_stream();
                //srs_trace("ret:%d = prtsp_play_dispatcher->wait_for_live_stream()\n", ret, prtsp_play_dispatcher);
                SRS_CHECK_RESULT(ret);
                
                ret = prtsp_play_dispatcher->get_sps_and_pps(codec_id, vps, sps, pps);
                SRS_CHECK_RESULT(ret);
                //srs_trace("ret:%d = prtsp_play_dispatcher:%p->get_sps_and_pps(codec_id, vps, sps, pps)\n", ret, prtsp_play_dispatcher);
                if(!vps.empty())
                {
                    srs_trace("vps len:%d", vps.length());
                    srs_trace_memory(vps.data(), vps.length());
                }

                if(!sps.empty())
                {
                    srs_trace("sps len:%d", sps.length());
                    srs_trace_memory(sps.data(), sps.length());
                }
                if(!pps.empty())
                {
                    srs_trace("pps len:%d", pps.length());
                    srs_trace_memory(pps.data(), pps.length());
                }
                
                ret = prtsp_play_dispatcher->get_audio_config(aac_cfg);
                //srs_trace("prtsp_play_dispatcher:%p\n", prtsp_play_dispatcher);
                //CHECK_RESULT(ret);
                if(aac_cfg.empty())
                {
                    char acfg[] = {(char)0x15, (char)0x88};
                    aac_cfg.append(acfg, sizeof(acfg));
                }
#else
                // 1920 x 1080
                //uint8_t sps[] = {0x67, 0x42, 0x00, 0x2a, 0x96, 0x35, 0xc0, 0xf0, 0x04, 0x4f, 0xcb, 0x37, 0x01, 0x01, 0x01, 0x02};
                //uint8_t pps[] = {0x68, 0xce, 0x3c, 0x80};
                // 1280 x 720
                uint8_t sps[] = {0x67, 0x42, 0x00, 0x1f, 0x96, 0x35, 0x40, 0xa0, 0x0b, 0x74, 0xdc, 0x04, 0x04, 0x04, 0x08};
                uint8_t pps[] = {0x68, 0xce, 0x31, 0xb2};
                uint8_t adts[7] = {0xff, 0xf1, 0x6c, 0x40, 0x1a, 0xff, 0xfc};
                uint8_t asc[20] = {0};
                lbsp_media::CAacConfig aaccfg;
                ret = aaccfg.parser_adts_header(adts, 7);
                if(ret < 0)
                {
                    lberror("ret:%d = aaccfg.parser_adts_header failed\n", ret);
                    return ret;
                }
                int asc_len = aaccfg.mux_audio_specific_config(asc, 20);
                if(asc_len < 0)
                {
                    lberror("ret:%d = aaccfg.mux_audio_specific_config failed\n", asc_len);
                    return asc_len;
                }
                avc_sps.append((char*)sps, sizeof(sps));
                avc_pps.append((char*)pps, sizeof(pps));
                aac_cfg.append((char*)asc, asc_len);
#endif
                int fd = rtsp->get_fd();
                if(fd == -1)
                {
                    srs_error("Invalid socket fd:%d\n", fd);
                    return -1;
                }
                int port = 0;
                std::string src_ip = srs_get_local_ip(fd, &port);
                //int port = srs_get_local_port(fd, &port);
                char url[256] = {0};
                sprintf(url, "rtsp://%s:%d/%s/", src_ip.c_str(), port, rtsp_media_title.c_str());
                srs_rtsp_debug(url);
                std::string video_track = "track1";
                std::string aac_track = "track2";
                std::string video_url = std::string(url) +  video_track;
                std::string aac_url = std::string(url) + aac_track;
                if(SrsCodecVideoAVC == codec_id)
                {
                    vpt = SRS_RTSP_AVC_PAYLOAD_TYPE;
                }
                else if(SrsCodecVideoHEVC == codec_id)
                {
                    vpt = SRS_RTSP_HEVC_PAYLOAD_TYPE;
                }
                gen_h264_rtp_map_info(vpt, video_url, video_track);
                gen_aac_rtp_map_info(97, aac_url, aac_track);
                if(m_pvideo_rtp_info)
                {
                    //res->add_media_video("video", 0, m_pvideo_rtp_info->pt, m_pvideo_rtp_info->track_name, NULL, 0, NULL, 0);
                    res->add_media_video("video", 0, m_pvideo_rtp_info->pt, m_pvideo_rtp_info->track_name,  vps.size() ? (uint8_t*)vps.data() : NULL, vps.size(), (uint8_t*)sps.data(), sps.size(), (uint8_t*)pps.data(), pps.size());
                    srs_rtsp_debug("res->add_media_video(video, 0, m_pvideo_rtp_info->pt:%d, m_pvideo_rtp_info->track_name:%s,  vps.size() ? vps.data():%p : NULL, vps.size():%ld, (uint8_t*)sps.data():%p, sps.size():%ld, (uint8_t*)pps.data():%p, pps.size():%ld)\n", m_pvideo_rtp_info->pt, m_pvideo_rtp_info->track_name.c_str(),  vps.data(), vps.size(), sps.data(), sps.size(), pps.data(), pps.size());
                }
                //srs_trace("after m_pvideo_rtp_info, prtsp_play_dispatcher:%p\n", prtsp_play_dispatcher);
                if(m_paudio_rtp_info)
                {
                    res->add_media_audio("audio", 0, m_paudio_rtp_info->pt, m_paudio_rtp_info->track_name, (uint8_t*)aac_cfg.data(), aac_cfg.size());
                }
               
                //srs_trace("after m_paudio_rtp_info, prtsp_play_dispatcher:%p\n", prtsp_play_dispatcher);
                res->content_base = url;//rtspreq->uri;
                if ((ret = rtsp->send_message(res)) != ERROR_SUCCESS) {
                    if (!srs_is_client_gracefully_close(ret)) {
                        srs_error("rtsp: send ANNOUNCE response failed. ret=%d", ret);
                    }
                    return ret;
                }
                //srs_trace("desc end, prtsp_play_dispatcher:%p\n", prtsp_play_dispatcher);
            }
        }
        else if (rtspreq->is_setup()) {
            srs_assert(rtspreq->transport);
            //srs_trace("setup begin, prtsp_play_dispatcher:%p\n", prtsp_play_dispatcher);
            // create session.
            if (session.empty()) {
                session = "DA3CD929"; //string_format("%0x", lazy_get_random32());// TODO: FIXME: generate session id.
            }
            if(NULL == rtspreq->transport)
            {
                srs_error("error, transport property not found!\n");
                return -1;
            }
            SrsRtspSetupResponse* res = new SrsRtspSetupResponse(rtspreq->seq);
            LB_ADD_MEM(res, sizeof(SrsRtspSetupResponse));
            SrsAutoFree(SrsRtspSetupResponse, res);
            if(rtspreq->transport->lower_transport == "TCP")
            {
                int fd = rtsp->get_fd();
                if(fd == -1)
                {
                    srs_error("Invalid socket fd:%d\n", fd);
                    return -1;
                }

                std::string dst_ip = srs_get_peer_ip(fd);
                std::string src_ip = srs_get_local_ip(fd, NULL);
                ret = res->set_transport_protocol(rtspreq->transport->lower_transport, dst_ip, src_ip, rtspreq->transport->rtp_channel_id, rtspreq->transport->rtcp_channel_id, 65);
                //srs_rtsp_debug("ret:%d = res->set_transport_protocol(rtspreq->transport->lower_transport:%s, dst_ip:%s, src_ip:%s, rtp_channel_id:%d, rtcp_channel_id:%d, 65)\n", ret, rtspreq->transport->lower_transport.c_str(), dst_ip.c_str(), src_ip.c_str(), rtspreq->transport->rtp_channel_id, rtspreq->transport->rtcp_channel_id); 
                if(m_pvideo_rtp_info)
                {
                    srs_rtsp_debug("m_pvideo_rtp_info->url:%s, rtspreq->uri:%s\n", m_pvideo_rtp_info->url.c_str(), rtspreq->uri.c_str());
                    if(m_pvideo_rtp_info->url == rtspreq->uri)
                    {
                        m_pvideo_rtp_info->rtp_channel_id = rtspreq->transport->rtp_channel_id;
                        m_pvideo_rtp_info->rtcp_channel_id = rtspreq->transport->rtcp_channel_id;
                        srs_rtsp_debug("m_pvideo_rtp_info->rtp_channel_id:%d, m_pvideo_rtp_info->rtcp_channel_id:%d\n", m_pvideo_rtp_info->rtp_channel_id, m_pvideo_rtp_info->rtcp_channel_id);
                    }
                    
                    //res->vrtp_info_list.push_back(*m_pvideo_rtp_info);
                }

                if(m_paudio_rtp_info)
                {
                    srs_rtsp_debug("m_pvideo_rtp_info->url:%s, rtspreq->uri:%s\n", m_pvideo_rtp_info->url.c_str(), rtspreq->uri.c_str());
                    if(m_paudio_rtp_info->url == rtspreq->uri)
                    {
                        m_paudio_rtp_info->rtp_channel_id = rtspreq->transport->rtp_channel_id;
                        m_paudio_rtp_info->rtcp_channel_id = rtspreq->transport->rtcp_channel_id;
                        srs_rtsp_debug("m_paudio_rtp_info->rtp_channel_id:%d, m_paudio_rtp_info->rtcp_channel_id:%d\n", m_paudio_rtp_info->rtp_channel_id, m_paudio_rtp_info->rtcp_channel_id);
                    }
 
                    //res->vrtp_info_list.push_back(*m_paudio_rtp_info);
                }
            }
            else
            {
                int lpm = 0;
                if ((ret = caster->alloc_port(&lpm)) != ERROR_SUCCESS) {
                    srs_error("rtsp: alloc port failed. ret=%d", ret);
                    return ret;
                }

                SrsRtpConn* rtp = NULL;
                if (rtspreq->stream_id == video_id) {
                    srs_freep(video_rtp);
                    rtp = video_rtp = new SrsRtpConn(this, lpm, video_id);
                    LB_ADD_MEM(rtp, sizeof(SrsRtpConn));
                } else {
                    srs_freep(audio_rtp);
                    rtp = audio_rtp = new SrsRtpConn(this, lpm, audio_id);
                    LB_ADD_MEM(rtp, sizeof(SrsRtpConn));
                }
                if ((ret = rtp->listen()) != ERROR_SUCCESS) {
                    srs_error("rtsp: rtp listen at port=%d failed. ret=%d", lpm, ret);
                    return ret;
                }
                srs_trace("rtsp: #%d %s over %s/%s/%s %s client-port=%d-%d, server-port=%d-%d", 
                    rtspreq->stream_id, (rtspreq->stream_id == video_id)? "Video":"Audio", 
                    rtspreq->transport->transport.c_str(), rtspreq->transport->profile.c_str(), rtspreq->transport->lower_transport.c_str(), 
                    rtspreq->transport->cast_type.c_str(), rtspreq->transport->client_port_min, rtspreq->transport->client_port_max, 
                    lpm, lpm + 1
                );
                    res->client_port_min = rtspreq->transport->client_port_min;
                    res->client_port_max = rtspreq->transport->client_port_max;
                    res->local_port_min = lpm;
                    res->local_port_max = lpm + 1;
                }
                res->session = session;
                //srs_rtsp_debug("before rtsp->send_message(res)\n");
                if ((ret = rtsp->send_message(res)) != ERROR_SUCCESS) {
                    if (!srs_is_client_gracefully_close(ret)) {
                        srs_error("rtsp: send SETUP response failed. ret=%d", ret);
                    }
                    else
                    {
                        srs_error("rtsp send SETUP response failed. ret=%d", ret);
                    }
                    return ret;
                }
                //srs_trace("setup end, prtsp_play_dispatcher:%p\n", prtsp_play_dispatcher);
                //srs_rtsp_debug("ret:%d = rtsp->send_message(res)\n", ret);
        } else if (rtspreq->is_record()) {
            SrsRtspResponse* res = new SrsRtspResponse(rtspreq->seq);
            LB_ADD_MEM(res, sizeof(SrsRtspResponse));
            SrsAutoFree(SrsRtspResponse, res);
            res->session = session;
            if ((ret = rtsp->send_message(res)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: send SETUP response failed. ret=%d", ret);
                }
                return ret;
            }
        }
        else if(rtspreq->is_play())
        {
            char rtpinfo[256] = {0};
            srs_debug("request play prtsp_play_dispatcher:%p, req:%p\n", prtsp_play_dispatcher, req);
            SrsRtspResponse* res = new SrsRtspResponse(rtspreq->seq);
            LB_ADD_MEM(res, sizeof(SrsRtspResponse));
            SrsAutoFree(SrsRtspResponse, res);
            res->session = session;
            if(rtspreq->start_range < 0)
            {
                rtspreq->start_range = 0.0;
            }
            start_time = res->start_range = rtspreq->start_range;
            stop_time = res->stop_range  = rtspreq->stop_range;
            sprintf(rtpinfo, "%s url=%s/%s;seq:%d;rtptime=%u", "RTP-Info:", rtsp_tcUrl.c_str(), "track1", 0, 0);
            ret = SrsHttpHooks::thirdpart_event_notify(req, "rtsp_dispatch");
            srs_debug(" ret:%d = SrsHttpHooks::thirdpart_event_notify(req:%p, rtsp_dispatch)\n", ret, req);
            /*char req_url[256] = {0};
            string event_type = "http_flv_dispatch";
            sprintf(req_url, "https://alexa-auth-dev.sunvalleycloud.com/third/auth/timelog?sn=%s&type=%s", _req->devicesn.c_str(), event_type.c_str());
            ret = SrsHttpHooks::thirdpart_event_notify(req_url, _req->devicesn, event_type);
            srs_debug("ret:%d = thirdpart_event_notify(url:%s, devicesn:%s, event_type:%s)\n", ret, req_url, _req->devicesn.c_str(), event_type.c_str());*/
            //uint32_t rtp_timestamp = lazy_get_random_int()%1000000000;

            if(m_pvideo_rtp_info)
            {
#ifdef SRS_FIX_RTSP_PARAM
                m_pvideo_rtp_info->seq_number = 0;//46464;//27835;
                m_pvideo_rtp_info->rtp_timestamp = 0;//4268892304;//2371927681;//rtp_timestamp;//get_random_int()%1000000;//2371927681;
                m_pvideo_rtp_info->rtcp_timestamp = lazy_get_random32();
                m_pvideo_rtp_info->ussrc = 0x290809d8;//0x2a693627;//srand((unsigned)time(NULL)-3);
                m_pvideo_rtp_info->urtcp_ssrc = 0x84B4883E;
#else
                m_pvideo_rtp_info->seq_number = lazy_get_random32() %10000; //27835;
                m_pvideo_rtp_info->rtp_timestamp = 0;//lazy_get_random32();//get_random_int()%1000000;//2371927681;
                m_pvideo_rtp_info->rtcp_timestamp = lazy_get_random32();
                m_pvideo_rtp_info->ussrc = lazy_get_random32();//0x2a693627;//srand((unsigned)time(NULL)-3);
                m_pvideo_rtp_info->urtcp_ssrc = lazy_get_random32();
#endif
                //srs_rtsp_debug("video rtp info: pt:%d, track_name:%s, url:%s, seq_number:%d, rtp_timestamp:%u, rtp_channel_id:%e, rtcp_channel_id:%d", 
                //m_pvideo_rtp_info->pt, m_pvideo_rtp_info->track_name.c_str(), m_pvideo_rtp_info->url.c_str(), m_pvideo_rtp_info->seq_number, m_pvideo_rtp_info->rtp_timestamp, m_pvideo_rtp_info->rtp_channel_id, m_pvideo_rtp_info->rtcp_channel_id);
                m_pvideo_rtp_info->time_scale = 90000;
                res->vrtp_info_list.push_back(*m_pvideo_rtp_info);
                rtsp->add_rtp_info(m_pvideo_rtp_info->pt, m_pvideo_rtp_info);
            }

            if(m_paudio_rtp_info)
            {
                
#ifdef SRS_FIX_RTSP_PARAM
                m_paudio_rtp_info->seq_number = 0;//5185;//32176;
                m_paudio_rtp_info->rtp_timestamp = 0;//2839439843;//945717140;//rtp_timestamp;//get_random_int()%1000000;;
                m_paudio_rtp_info->ussrc = 0xBAC1C071;//0x4ee746fd;//srand((unsigned)time(NULL));
                m_paudio_rtp_info->urtcp_ssrc = 0x2CD4B9EB;
#else
                m_paudio_rtp_info->seq_number = lazy_get_random32()%10000;//32176;
                m_paudio_rtp_info->rtp_timestamp =  0;//945717140;//rtp_timestamp;//lazy_get_random_int()%1000000;;
                m_paudio_rtp_info->rtcp_timestamp = lazy_get_random32();
                m_paudio_rtp_info->ussrc = lazy_get_random32();//0x4ee746fd;//srand((unsigned)time(NULL));
                m_paudio_rtp_info->urtcp_ssrc = lazy_get_random32();
#endif
                //srs_rtsp_debug("audio rtp info: pt:%d, track_name:%s, url:%s, seq_number:%d, rtp_timestamp:%u, rtp_channel_id:%e, rtcp_channel_id:%d", 
                //m_paudio_rtp_info->pt, m_paudio_rtp_info->track_name.c_str(), m_paudio_rtp_info->url.c_str(), m_paudio_rtp_info->seq_number, m_paudio_rtp_info->rtp_timestamp, m_paudio_rtp_info->rtp_channel_id, m_paudio_rtp_info->rtcp_channel_id);
                m_paudio_rtp_info->time_scale = 8000;
                res->vrtp_info_list.push_back(*m_paudio_rtp_info);
                rtsp->add_rtp_info(m_paudio_rtp_info->pt, m_paudio_rtp_info);
            }
            /*if(NULL == prtsp_play_dispatcher)
            {
                prtsp_play_dispatcher = new SrsRtspPlayDispatcher();
                srs_trace("prtsp_play_dispatcher:%p = new SrsRtspPlayDispatcher()\n", prtsp_play_dispatcher);
                LB_ADD_MEM(prtsp_play_dispatcher, sizeof(SrsRtspPlayDispatcher));
                prtsp_play_dispatcher->init_rtsp_dispatch(rtsp, req->devicesn);
            }*/
            if(prtsp_play_dispatcher)
            {
                if(m_pvideo_rtp_info)
                {
                    prtsp_play_dispatcher->add_rtp_info(m_pvideo_rtp_info->pt, m_pvideo_rtp_info);//m_pvideo_rtp_info->url, m_pvideo_rtp_info->track_name, m_pvideo_rtp_info->seq_number, m_pvideo_rtp_info->rtp_timestamp);
                }

                if(m_paudio_rtp_info)
                {
                    prtsp_play_dispatcher->add_rtp_info(m_paudio_rtp_info->pt, m_paudio_rtp_info);//m_paudio_rtp_info->url, m_paudio_rtp_info->track_name, m_paudio_rtp_info->seq_number, m_paudio_rtp_info->rtp_timestamp);
                }
                
                ret = prtsp_play_dispatcher->start();
                if(ret < 0)
                {
                    srs_error("ret:%d = prtsp_play_dispatcher->start()\n", ret);
                    return ret;
                }
                srs_trace("ret:%d = prtsp_play_dispatcher->start()\n", ret);
            }
            else
            {
                srs_error("prtsp_play_dispatcher == NULL\n");
            }

            if ((ret = rtsp->send_message(res)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: send SETUP response failed. ret=%d", ret);
                }
                return ret;
            }
        }
        else if(rtspreq->is_shutdown())
        {
            if(prtsp_play_dispatcher)
            {
                prtsp_play_dispatcher->stop();
                srs_freep(prtsp_play_dispatcher);
            }
            SrsRtspResponse* res = new SrsRtspResponse(rtspreq->seq);
            LB_ADD_MEM(res, sizeof(SrsRtspResponse));
            SrsAutoFree(SrsRtspResponse, res);
            res->session = session;
            if ((ret = rtsp->send_message(res)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: send SETUP response failed. ret=%d", ret);
                }
                return ret;
            }
            
        }
        else if(rtspreq->is_rtcp())
        {
            srs_rtsp_debug("recv rtcp packet\n");
            rtcp_packet* rtcp_pkt;
            ret = rtsp->read_rtcp_packet(rtcp_pkt);
            if(ret < 0)
            {
                srs_error("ret:%d = rtsp->read_rtcp_packet(&rtcp_pkt) failed\n", ret);
                return ret;
            }
            srs_rtsp_debug("recv rtcp packet success\n");
        }

    }

    return ret;
}

int SrsRtspConn::on_rtp_packet(SrsRtpPacket* pkt, int stream_id)
{
    int ret = ERROR_SUCCESS;

    // ensure rtmp connected.
    if ((ret = connect()) != ERROR_SUCCESS) {
        return ret;
    }

    if (stream_id == video_id) {
        // rtsp tbn is ts tbn.
        int64_t pts = pkt->timestamp;
        if ((ret = vjitter->correct(pts)) != ERROR_SUCCESS) {
            srs_error("rtsp: correct by jitter failed. ret=%d", ret);
            return ret;
        }

        // TODO: FIXME: set dts to pts, please finger out the right dts.
        int64_t dts = pts;

        return on_rtp_video(pkt, dts, pts);
    } else {
        // rtsp tbn is ts tbn.
        int64_t pts = pkt->timestamp;
        if ((ret = ajitter->correct(pts)) != ERROR_SUCCESS) {
            srs_error("rtsp: correct by jitter failed. ret=%d", ret);
            return ret;
        }

        return on_rtp_audio(pkt, pts);
    }

    return ret;
}

int SrsRtspConn::cycle()
{
    // serve the rtsp client.
    int ret = do_cycle();
    
    // if socket io error, set to closed.
    if (srs_is_client_gracefully_close(ret)) {
        ret = ERROR_SOCKET_CLOSED;
    }

    // success.
    if (ret == ERROR_SUCCESS) {
        srs_trace("client finished.");
    }
    
    // client close peer.
    if (ret == ERROR_SOCKET_CLOSED) {
        //srs_warn("client disconnect peer. ret=%d", ret);
    }
    
    // add by dawson
    if(req)
    {
        on_close(req);
    }
    if(prtsp_play_dispatcher)
    {
        prtsp_play_dispatcher->stop();
        srs_freep(prtsp_play_dispatcher);
    }
    return ERROR_SUCCESS;
}

void SrsRtspConn::on_thread_stop()
{
    if (video_rtp) {
        caster->free_port(video_rtp->port(), video_rtp->port() + 1);
    }

    if (audio_rtp) {
        caster->free_port(audio_rtp->port(), audio_rtp->port() + 1);
    }

    caster->remove(this);
}

int SrsRtspConn::on_rtp_video(SrsRtpPacket* pkt, int64_t dts, int64_t pts)
{
    int ret = ERROR_SUCCESS;

    if ((ret = kickoff_audio_cache(pkt, dts)) != ERROR_SUCCESS) {
        return ret;
    }

    if ((ret = write_h264_ipb_frame(pkt->get_payload()->bytes(), pkt->get_payload()->length(), dts / 90, pts / 90)) != ERROR_SUCCESS) {
        return ret;
    }

    return ret;
}

int SrsRtspConn::on_rtp_audio(SrsRtpPacket* pkt, int64_t dts)
{
    int ret = ERROR_SUCCESS;

    if ((ret = kickoff_audio_cache(pkt, dts)) != ERROR_SUCCESS) {
        return ret;
    }

    // cache current audio to kickoff.
    acache->dts = dts;
    acache->audio_samples = pkt->audio_samples;
    //acache->payload = pkt->payload;
    for(size_t i = 0; i <  pkt->vrtp_packet_list.size(); i++)
    {
        if( i == 0)
        {
            acache->payload = pkt->vrtp_packet_list[i];
        }
        else
        {
            assert(0);
        }
    }

    pkt->vrtp_packet_list.clear();
    pkt->audio_samples = NULL;

    return ret;
}

int SrsRtspConn::kickoff_audio_cache(SrsRtpPacket* pkt, int64_t dts)
{
    int ret = ERROR_SUCCESS;

    // nothing to kick off.
    if (!acache->payload) {
        return ret;
    }

    if (dts - acache->dts > 0 && acache->audio_samples->nb_sample_units > 0) {
        int64_t delta = (dts - acache->dts) / acache->audio_samples->nb_sample_units;
        for (int i = 0; i < acache->audio_samples->nb_sample_units; i++) {
            char* frame = acache->audio_samples->sample_units[i].bytes;
            int nb_frame = acache->audio_samples->sample_units[i].size;
            int64_t timestamp = (acache->dts + delta * i) / 90;
            acodec->aac_packet_type = 1;
            if ((ret = write_audio_raw_frame(frame, nb_frame, acodec, timestamp)) != ERROR_SUCCESS) {
                return ret;
            }
        }
    }

    acache->dts = 0;
    srs_freep(acache->audio_samples);
    srs_freep(acache->payload);

    return ret;
}

int SrsRtspConn::write_sequence_header()
{
    int ret = ERROR_SUCCESS;

    // use the current dts.
    int64_t dts = vjitter->timestamp() / 90;

    // send video sps/pps
    if ((ret = write_h264_sps_pps(dts, dts)) != ERROR_SUCCESS) {
        return ret;
    }

    // generate audio sh by audio specific config.
    if (true) {
        std::string sh = aac_specific_config;

        SrsAvcAacCodec dec;
        if ((ret = dec.audio_aac_sequence_header_demux((char*)sh.c_str(), (int)sh.length())) != ERROR_SUCCESS) {
            return ret;
        }

        acodec->sound_format = SrsCodecAudioAAC;
        acodec->sound_type = (dec.aac_channels == 2)? SrsCodecAudioSoundTypeStereo : SrsCodecAudioSoundTypeMono;
        acodec->sound_size = SrsCodecAudioSampleSize16bit;
        acodec->aac_packet_type = 0;

        static int aac_sample_rates[] = {
            96000, 88200, 64000, 48000,
            44100, 32000, 24000, 22050,
            16000, 12000, 11025,  8000,
            7350,     0,     0,    0
        };
        switch (aac_sample_rates[dec.aac_sample_rate]) {
            case 11025:
                acodec->sound_rate = SrsCodecAudioSampleRate11025;
                break;
            case 22050:
                acodec->sound_rate = SrsCodecAudioSampleRate22050;
                break;
            case 44100:
                acodec->sound_rate = SrsCodecAudioSampleRate44100;
                break;
            default:
                break;
        };

        if ((ret = write_audio_raw_frame((char*)sh.data(), (int)sh.length(), acodec, dts)) != ERROR_SUCCESS) {
            return ret;
        }
    }

    return ret;
}

int SrsRtspConn::write_h264_sps_pps(u_int32_t dts, u_int32_t pts)
{
    int ret = ERROR_SUCCESS;
    
    // h264 raw to h264 packet.
    std::string sh;
    if ((ret = avc->mux_sequence_header(h264_sps, h264_pps, dts, pts, sh)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // h264 packet to flv packet.
    int8_t frame_type = SrsCodecVideoAVCFrameKeyFrame;
    int8_t avc_packet_type = SrsCodecVideoAVCTypeSequenceHeader;
    char* flv = NULL;
    int nb_flv = 0;
    if ((ret = avc->mux_avc2flv(sh, frame_type, avc_packet_type, dts, pts, &flv, &nb_flv)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // the timestamp in rtmp message header is dts.
    u_int32_t timestamp = dts;
    if ((ret = rtmp_write_packet(SrsCodecFlvTagVideo, timestamp, flv, nb_flv)) != ERROR_SUCCESS) {
        return ret;
    }

    return ret;
}

int SrsRtspConn::write_h264_ipb_frame(char* frame, int frame_size, u_int32_t dts, u_int32_t pts) 
{
    int ret = ERROR_SUCCESS;
    
    // 5bits, 7.3.1 NAL unit syntax,
    // H.264-AVC-ISO_IEC_14496-10.pdf, page 44.
    //  7: SPS, 8: PPS, 5: I Frame, 1: P Frame
    SrsAvcNaluType nal_unit_type = (SrsAvcNaluType)(frame[0] & 0x1f);
    
    // for IDR frame, the frame is keyframe.
    SrsCodecVideoAVCFrame frame_type = SrsCodecVideoAVCFrameInterFrame;
    if (nal_unit_type == SrsAvcNaluTypeIDR) {
        frame_type = SrsCodecVideoAVCFrameKeyFrame;
    }

    std::string ibp;
    if ((ret = avc->mux_ipb_frame(frame, frame_size, ibp)) != ERROR_SUCCESS) {
        return ret;
    }
    
    int8_t avc_packet_type = SrsCodecVideoAVCTypeNALU;
    char* flv = NULL;
    int nb_flv = 0;
    if ((ret = avc->mux_avc2flv(ibp, frame_type, avc_packet_type, dts, pts, &flv, &nb_flv)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // the timestamp in rtmp message header is dts.
    u_int32_t timestamp = dts;
    return rtmp_write_packet(SrsCodecFlvTagVideo, timestamp, flv, nb_flv);
}

int SrsRtspConn::write_audio_raw_frame(char* frame, int frame_size, SrsRawAacStreamCodec* codec, u_int32_t dts)
{
    int ret = ERROR_SUCCESS;

    char* data = NULL;
    int size = 0;
    if ((ret = aac->mux_aac2flv(frame, frame_size, codec, dts, &data, &size)) != ERROR_SUCCESS) {
        return ret;
    }
    
    return rtmp_write_packet(SrsCodecFlvTagAudio, dts, data, size);
}

int SrsRtspConn::rtmp_write_packet(char type, u_int32_t timestamp, char* data, int size)
{
    int ret = ERROR_SUCCESS;
    
    SrsSharedPtrMessage* msg = NULL;

    if ((ret = srs_rtmp_create_msg(type, timestamp, data, size, stream_id, &msg)) != ERROR_SUCCESS) {
        srs_error("rtsp: create shared ptr msg failed. ret=%d", ret);
        return ret;
    }
    srs_assert(msg);

    // send out encoded msg.
    if ((ret = client->send_and_free_message(msg, stream_id)) != ERROR_SUCCESS) {
        return ret;
    }
    
    return ret;
}

// TODO: FIXME: merge all client code.
int SrsRtspConn::connect()
{
    int ret = ERROR_SUCCESS;

    // when ok, ignore.
    if (io || client) {
        return ret;
    }
    
    // parse uri
    if (!req) {
        req = new SrsRequest();
        srs_rtsp_debug("req:%p = new SrsRequest()\n", req);
        LB_ADD_MEM(req, sizeof(SrsRequest));
        std::string schema, host, vhost, app, port, param;
        srs_discovery_tc_url(rtsp_tcUrl, schema, host, vhost, app, rtsp_stream, port, param);

        // generate output by template.
        std::string output = output_template;
        output = srs_string_replace(output, "[app]", app);
        output = srs_string_replace(output, "[stream]", rtsp_stream);

        size_t pos = string::npos;
        string uri = req->tcUrl = output;

        // tcUrl, stream
        if ((pos = uri.rfind("/")) != string::npos) {
            req->stream = uri.substr(pos + 1);
            req->tcUrl = uri = uri.substr(0, pos);
        }
    
        srs_discovery_tc_url(req->tcUrl, 
            req->schema, req->host, req->vhost, req->app, req->stream, req->port,
            req->param);
    }

    // connect host.
    if ((ret = srs_socket_connect(req->host, ::atoi(req->port.c_str()), ST_UTIME_NO_TIMEOUT, &stfd)) != ERROR_SUCCESS) {
        srs_error("rtsp: connect server %s:%s failed. ret=%d", req->host.c_str(), req->port.c_str(), ret);
        return ret;
    }
    io = new SrsStSocket(stfd);
    LB_ADD_MEM(io, sizeof(SrsStSocket));
    client = new SrsRtmpClient(io);
    LB_ADD_MEM(client, sizeof(SrsRtmpClient));

    client->set_recv_timeout(SRS_CONSTS_RTMP_RECV_TIMEOUT_US);
    client->set_send_timeout(SRS_CONSTS_RTMP_SEND_TIMEOUT_US);
    
    // connect to vhost/app
    if ((ret = client->handshake()) != ERROR_SUCCESS) {
        srs_error("rtsp: handshake with server failed. ret=%d", ret);
        return ret;
    }
    if ((ret = connect_app(req->host, req->port)) != ERROR_SUCCESS) {
        srs_error("rtsp: connect with server failed. ret=%d", ret);
        return ret;
    }
    if ((ret = client->create_stream(stream_id)) != ERROR_SUCCESS) {
        srs_error("rtsp: connect with server failed, stream_id=%d. ret=%d", stream_id, ret);
        return ret;
    }
    
    // publish.
    if ((ret = client->publish(req->stream, stream_id)) != ERROR_SUCCESS) {
        srs_error("rtsp: publish failed, stream=%s, stream_id=%d. ret=%d", 
            req->stream.c_str(), stream_id, ret);
        return ret;
    }

    return write_sequence_header();
}

// TODO: FIXME: refine the connect_app.
int SrsRtspConn::connect_app(string ep_server, string ep_port)
{
    int ret = ERROR_SUCCESS;
    
    // args of request takes the srs info.
    if (req->args == NULL) {
        req->args = SrsAmf0Any::object();
    }
    
    // notify server the edge identity,
    // @see https://github.com/ossrs/srs/issues/147
    SrsAmf0Object* data = req->args;
    data->set("srs_sig", SrsAmf0Any::str(RTMP_SIG_SRS_KEY));
    data->set("srs_server", SrsAmf0Any::str(RTMP_SIG_SRS_KEY" "RTMP_SIG_SRS_VERSION" ("RTMP_SIG_SRS_URL_SHORT")"));
    data->set("srs_license", SrsAmf0Any::str(RTMP_SIG_SRS_LICENSE));
    data->set("srs_role", SrsAmf0Any::str(RTMP_SIG_SRS_ROLE));
    data->set("srs_url", SrsAmf0Any::str(RTMP_SIG_SRS_URL));
    data->set("srs_version", SrsAmf0Any::str(RTMP_SIG_SRS_VERSION));
    data->set("srs_site", SrsAmf0Any::str(RTMP_SIG_SRS_WEB));
    data->set("srs_email", SrsAmf0Any::str(RTMP_SIG_SRS_EMAIL));
    data->set("srs_copyright", SrsAmf0Any::str(RTMP_SIG_SRS_COPYRIGHT));
    data->set("srs_primary", SrsAmf0Any::str(RTMP_SIG_SRS_PRIMARY));
    data->set("srs_authors", SrsAmf0Any::str(RTMP_SIG_SRS_AUTHROS));
    // for edge to directly get the id of client.
    data->set("srs_pid", SrsAmf0Any::number(getpid()));
    data->set("srs_id", SrsAmf0Any::number(_srs_context->get_id()));
    
    // local ip of edge
    std::vector<std::string> ips = srs_get_local_ipv4_ips();
    assert(_srs_config->get_stats_network() < (int)ips.size());
    std::string local_ip = ips[_srs_config->get_stats_network()];
    data->set("srs_server_ip", SrsAmf0Any::str(local_ip.c_str()));
    
    // generate the tcUrl
    std::string param = "";
    std::string tc_url = srs_generate_tc_url(ep_server, req->vhost, req->app, ep_port, param);
    
    // upnode server identity will show in the connect_app of client.
    // @see https://github.com/ossrs/srs/issues/160
    // the debug_srs_upnode is config in vhost and default to true.
    bool debug_srs_upnode = _srs_config->get_debug_srs_upnode(req->vhost);
    if ((ret = client->connect_app(req->app, tc_url, req, debug_srs_upnode)) != ERROR_SUCCESS) {
        srs_error("rtsp: connect with server failed, tcUrl=%s, dsu=%d. ret=%d", 
            tc_url.c_str(), debug_srs_upnode, ret);
        return ret;
    }
    
    return ret;
}

 int SrsRtspConn::gen_h264_rtp_map_info(int pt, std::string url, std::string track_name)
 {
     if(NULL == m_pvideo_rtp_info)
     {
         m_pvideo_rtp_info = new RTP_INFO;
         LB_ADD_MEM(m_pvideo_rtp_info, sizeof(RTP_INFO));
         //srs_rtsp_debug("new RTP_INFO, m_pvideo_rtp_info->seq_number:%d, m_pvideo_rtp_info->rtp_timestamp:%u\n", m_pvideo_rtp_info->seq_number, m_pvideo_rtp_info->rtp_timestamp);
         //memset(m_pvideo_rtp_info, 0, sizeof(RTP_INFO));
     }
    m_pvideo_rtp_info->pt = pt;
    m_pvideo_rtp_info->track_name = track_name;
    m_pvideo_rtp_info->url = url;
    m_pvideo_rtp_info->seq_number = 0;
    m_pvideo_rtp_info->rtp_timestamp = 0;
    m_pvideo_rtp_info->rtp_channel_id = 0;
    m_pvideo_rtp_info->rtcp_channel_id = 0;

     return 0;
 }

int SrsRtspConn::gen_aac_rtp_map_info(int pt, std::string url, std::string track_name)
{
    if(NULL == m_paudio_rtp_info)
    {
        m_paudio_rtp_info = new RTP_INFO();
        LB_ADD_MEM(m_paudio_rtp_info, sizeof(RTP_INFO));
        //srs_rtsp_debug("new RTP_INFO(), m_paudio_rtp_info->seq_number:%d, m_paudio_rtp_info->rtp_timestamp:%u\n", m_paudio_rtp_info->seq_number, m_paudio_rtp_info->rtp_timestamp);
    }

    m_paudio_rtp_info->pt = pt;
    m_paudio_rtp_info->url = url;
    m_paudio_rtp_info->track_name = track_name;
    m_paudio_rtp_info->seq_number = 0;
    m_paudio_rtp_info->rtp_timestamp = 0;
    m_paudio_rtp_info->rtp_channel_id = 0;
    m_paudio_rtp_info->rtcp_channel_id = 0;

     return 0;
}

int SrsRtspConn::on_connect(SrsRequest* preq)
{
    if(preq)
    {
        return http_hooks_on_play_action(preq->vhost, preq->devicesn, "rtsp", preq->token, "authorize");
    }
    return -1;
    //return http_hooks_on_connect(preq);
}

int SrsRtspConn::on_close(SrsRequest* preq)
{
    if(preq)
    {
        return http_hooks_on_play_action(preq->vhost, preq->devicesn, "rtsp", preq->token, "close");
    }
    return -1;
    //return http_hooks_on_close(preq);
}

int SrsRtspConn::http_hooks_on_connect(SrsRequest* preq)
{
    int ret = -1;
    if(!_srs_config->get_bool_config("enabled", false, req->vhost.c_str(), "rtsp_http_hooks"))
    {
        srs_rtsp_debug("rtsp http hooks disable\n");
        return 0;
    }

    std::vector<std::string> vallist = _srs_config->get_string_config_list("on_play_authorize", req->vhost.c_str(), "rtsp_http_hooks");
    for(size_t i = 0; i < vallist.size(); i++)
    {
        ret = SrsHttpHooks::on_play_action(vallist[i], "application/json", preq->devicesn, "rtsp", req->token, "authorize");
        SRS_CHECK_RESULT(ret);
    }

    return ret;
}

int SrsRtspConn::http_hooks_on_close(SrsRequest* preq)
{
    int ret = -1;
    if(!_srs_config->get_bool_config("enabled", false, req->vhost.c_str(), "rtsp_http_hooks"))
    {
        srs_rtsp_debug("rtsp http hooks disable\n");
        return 0;
    }

    std::vector<std::string> vallist = _srs_config->get_string_config_list("on_play_close", req->vhost.c_str(), "rtsp_http_hooks");
    for(size_t i = 0; i < vallist.size(); i++)
    {
        ret = SrsHttpHooks::on_play_action(vallist[i], "application/json", preq->devicesn, "rtsp", req->token, "close");
        SRS_CHECK_RESULT(ret);
    }

    return ret;
    /*std::stringstream ss;
    string contenttype = "application/json";
    std::string data;
    int code = 0, ret = 0;
    std::string resp;
    if(NULL == preq)
    {
        return -1;
    }
    else if("application/json" == contenttype)
    {
        ss << SRS_JOBJECT_START << "\r\n"
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_DEVICE_SN, preq->devicesn) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_TOKEN, req->token) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_ACTION, "close") << "\r\n"
        << SRS_JOBJECT_END;
    }
    else
    {
        srs_error("Invalid content type %s\n", contenttype.c_str());
        return -1;
    }
    data = ss.str();
    std::vector<std::string> vallist = _srs_config->get_string_config_list("on_play_close", req->vhost.c_str(), "rtsp_http_hooks");
    for(size_t i = 0; i < vallist.size(); i++)
    {
        ret = SrsHttpHooks::do_post2(vallist[i], contenttype, data, code, resp);
        srs_rtsp_debug("ret:%d = SrsHttpHooks::do_post2(vallist[i]:%s, contenttype:%s, data:%s, code:%d, resp:%s)\n", ret, vallist[i].c_str(), contenttype.c_str(), data.c_str(), code, resp.c_str());
        SRS_CHECK_RESULT(ret);
    }
    return ret;*/
}

/*bool SrsRtspConn::digest_auth_enable()
{
    return _srs_config->get_vhost_on_http(req->vhost, "on_digest_auth") ? true : false;
}

bool SrsRtspConn::on_digest_auth(std::string method, SrsRtspAuthorization* pauthorize)
{
#ifdef SRS_AUTO_HTTP_CALLBACK
    if (!_srs_config->get_vhost_http_hooks_enabled(req->vhost)) {
        srs_trace("%s http hook disable", req->vhost.c_str());
        return true;
    }

    if(NULL == pauthorize || method.empty())
    {
        srs_error("Invalid parameter pauthorize:%p, method:%s\n", pauthorize, method.c_str());
        return false;
    }

    // the http hooks will cause context switch,
    // so we must copy all hooks for the on_connect may freed.
    // @see https://github.com/ossrs/srs/issues/475
    vector<string> hooks;
    if (true) {
        SrsConfDirective* conf = _srs_config->get_vhost_on_http(req->vhost, "on_digest_auth");
        
        if (!conf) {
            srs_trace("ignore the empty http callback: on_digest_auth");
            return true;
        }
        
        hooks = conf->args;
    }
    //int SrsHttpHooks::on_digest_authorize(std::string url, std::string contenttype, std::string user_name, std::string realm, std::string method, std::string uri, std::string nonce, std::string response)
    for (int i = 0; i < (int)hooks.size(); i++) {
        std::string url = hooks.at(i);
        int ret = -1;
        for(size_t i = 0; i < 3 && ret != 0; i++)
        {
            ret = SrsHttpHooks::on_digest_authorize(url, "application/json", pauthorize->get_attribute(SV_DIGEST_AUTH_PARAM_USER_NAME), pauthorize->get_attribute(SV_DIGEST_AUTH_PARAM_REALM), method, pauthorize->get_attribute(SV_DIGEST_AUTH_PARAM_URI), pauthorize->get_attribute(SV_DIGEST_AUTH_PARAM_NONCE), pauthorize->get_attribute(SV_DIGEST_AUTH_PARAM_RESPONSE));
            if(0 != ret)
            {
                srs_trace("SrsHttpHooks::on_digest_authorize failed, ret:%d\n", ret);
                //st_usleep(100*1000);
                return false;
            }
        }
        //SrsHttpHooks::on_close(url, req, kbps->get_send_bytes(), kbps->get_recv_bytes());
    }

    return true;
#endif
}*/

SrsRtspCaster::SrsRtspCaster(SrsConfDirective* c)
{
    // TODO: FIXME: support reload.
    output = _srs_config->get_stream_caster_output(c);
    local_port_min = _srs_config->get_stream_caster_rtp_port_min(c);
    local_port_max = _srs_config->get_stream_caster_rtp_port_max(c);
}

SrsRtspCaster::~SrsRtspCaster()
{
    std::vector<SrsRtspConn*>::iterator it;
    for (it = clients.begin(); it != clients.end(); ++it) {
        SrsRtspConn* conn = *it;
        srs_freep(conn);
    }
    clients.clear();
    used_ports.clear();
}

int SrsRtspCaster::alloc_port(int* pport)
{
    int ret = ERROR_SUCCESS;

    // use a pair of port.
    for (int i = local_port_min; i < local_port_max - 1; i += 2) {
        if (!used_ports[i]) {
            used_ports[i] = true;
            used_ports[i + 1] = true;
            *pport = i;
            break;
        }
    }
    srs_info("rtsp: alloc port=%d-%d", *pport, *pport + 1);

    return ret;
}

void SrsRtspCaster::free_port(int lpmin, int lpmax)
{
    for (int i = lpmin; i < lpmax; i++) {
        used_ports[i] = false;
    }
    srs_trace("rtsp: free rtp port=%d-%d", lpmin, lpmax);
}

int SrsRtspCaster::on_tcp_client(st_netfd_t stfd)
{
    int ret = ERROR_SUCCESS;

    SrsRtspConn* conn = new SrsRtspConn(this, stfd, output);
    LB_ADD_MEM(conn, sizeof(SrsRtspConn));
    if ((ret = conn->serve()) != ERROR_SUCCESS) {
        srs_error("rtsp: serve client failed. ret=%d", ret);
        srs_freep(conn);
        return ret;
    }

    clients.push_back(conn);
    srs_info("rtsp: start thread to serve client.");

    return ret;
}

void SrsRtspCaster::remove(SrsRtspConn* conn)
{
    std::vector<SrsRtspConn*>::iterator it = find(clients.begin(), clients.end(), conn);
    if (it != clients.end()) {
        clients.erase(it);
    }
    srs_info("rtsp: remove connection from caster.");

    srs_freep(conn);
}


#endif

