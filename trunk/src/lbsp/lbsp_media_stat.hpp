/**************************************************************************************
Copyright (C), 2018-2025, LeBo Technology Co.,Ltd.
File name:     mediasendermanager.h
Author:        zwu
Version:       1.0.0
Date:          2019-11-18
Description:   This class implement dispatch media statictis info
Platform:      windows,linux, ardroid
***************************************************************************************/
#ifndef LBSP_MEDIA_STATICTIS_H_
#define LBSP_MEDIA_STATICTIS_H_
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <string>
#include <sys/time.h>
#include <srs_kernel_log.hpp>
#ifndef lberror
#define lberror(...)  srs_error(__VA_ARGS__)
#endif
//#define ENABLE_TRACE_DISPATCH_BITRATE
namespace lbsp_util{
class media_stat
{
protected:
    int64_t             m_ldispatch_duration;
    int64_t             m_lpkt_count;
    int64_t             m_ltotal_bytes;
    int64_t             m_llast_static_pts;
    int64_t             m_lstatictis_interval;
    int64_t             m_lprepare_time;
    std::string         m_sstream_name;
public:
    media_stat(std::string stream_name, int64_t interval_ms = 1000)
    {
        m_ldispatch_duration = 0;
        m_lpkt_count = 0;
        m_ltotal_bytes = 0;
        m_llast_static_pts = INT64_MIN;
        m_lprepare_time = INT64_MIN;
        m_lstatictis_interval = interval_ms;
        m_sstream_name = stream_name;
        srs_info("stream_name:%s, m_lstatictis_interval:%" PRId64 "\n", stream_name.c_str(), m_lstatictis_interval);
    }

    void on_prepare_packet()
    {
        m_lprepare_time = get_current_time();
        //srs_info("%s media_stat::on_prepare_packet m_lprepare_time:%" PRId64 "\n", m_sstream_name.c_str(),  m_lprepare_time);
    }

    void on_packet(int64_t pkt_len, int64_t pts, int que_size)
    {
        if(INT64_MIN == m_lprepare_time)
        {
            srs_info("%s Invalid prepare time INT64_MIN == m_lprepare_time\n", m_sstream_name.c_str());
            return ;
        }
        m_ldispatch_duration += get_current_time() - m_lprepare_time;
        m_lpkt_count++;
        m_ltotal_bytes += pkt_len;
        //srs_info("%s on_packet pts:%" PRId64 ", pkt_len:%d, m_llast_static_pts:%" PRId64 ", m_lstatictis_interval:%" PRId64 "", m_sstream_name.c_str(), pts, pkt_len, m_llast_static_pts, m_lstatictis_interval);
        m_lprepare_time = INT64_MIN;
        
        if(INT64_MIN == m_llast_static_pts)
        {
            m_llast_static_pts = pts;
        }
        else if(pts - m_llast_static_pts > m_lstatictis_interval)
        {
            //double send_pkt_dur = m_lsend_duration / lpkt_count;
            int64_t bitrate = m_ltotal_bytes * 8 / (pts - m_llast_static_pts);
            srs_trace("%s total dispatch duration:%" PRId64 "ms, packet count:%" PRId64 ", average bitrate:%" PRId64 "kbps, statis duration:%" PRId64 "ms, que_size:%d, pts:%" PRId64 "\n", m_sstream_name.c_str(), m_ldispatch_duration, m_lpkt_count, bitrate, pts - m_llast_static_pts, que_size, pts);
            m_llast_static_pts = pts;
            m_ldispatch_duration = 0;
            m_lpkt_count = 0;
            m_ltotal_bytes = 0;
        }
    }

    void reset()
    {
        m_ldispatch_duration = 0;
        m_lpkt_count = 0;
        m_ltotal_bytes = 0;
        m_llast_static_pts = INT64_MIN;
        m_lprepare_time = INT64_MIN;
    }

    int64_t get_current_time()
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        int64_t curtime = (int64_t)tv.tv_sec*1000 + tv.tv_usec/1000;
        return curtime;
    }
};
};
#endif