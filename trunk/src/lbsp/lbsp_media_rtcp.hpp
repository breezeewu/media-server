/*********************************************************************************************************************************************************************************
 * Report fix header
 * 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|   SC    |        PT     |        length                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 SSRC of packet sender(32bit)                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * V : 2bit, version unusually is 2
 * P : 1bit, padding bit, unusually is 0
 * RC: 5bit, report counter, indicate chunk's count, can be 0
 * PT: 8bit, report payload type. SR:200, RR:201, SDES:202, BYE:203, APP:204
 * length:16bit, report packet length below, in 32 bits unit
 * ssrc: 32bit, packet sender's ssrc
 * 
 * Send report format
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            NTP timestamp most significant word(0-32)          |
 * |            NTP timestamp least significant word(32-64)        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       RTP timestamp(32bit)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               sender's packet count(32bit)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               sender's octet count(32bit)                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *******************************************************************************************************************************************************************************/
#pragma once
#include <stdint.h>
#include <map>
#include <unistd.h>
#include<sys/time.h>
#include "lbsp_media_bitstream.hpp"
#include <srs_kernel_log.hpp>

#define SEND_REPORT_PAYLOAD_TYPE     200
#define RECV_REPORT_PAYLOAD_TYPE     201
#define SDES_PAYLOAD_TYPE            202
#define BYE_PAYLOAD_TYPE             203
namespace lbsp_util
{
    class rtcp_packet
    {
    public:
        uint8_t         m_uversin;
        uint8_t         m_upadding;
        uint8_t         m_ureport_count;
        uint8_t         m_upayload_type;
        uint16_t        m_upkt_len;
        uint32_t        m_ussrc;

        uint32_t        m_utimestamp_base;
        uint32_t        m_utimestamp_scale;
        uint32_t        m_uchannel_id;
    public:
        rtcp_packet(int pt):m_upayload_type(pt)
        {
            m_uversin               = 2;
            m_upadding              = 0;
            m_ureport_count         = 0;
            m_upkt_len              = 0;
            m_ussrc                 = 0;
            m_utimestamp_base       = 0;
            m_uchannel_id           = 0;
            m_utimestamp_scale      = 90000;
        }

        virtual int init(uint32_t ssrc, uint32_t channel_id, uint32_t ts_base, uint32_t ts_scale)
        {
            m_ussrc = ssrc;
            m_utimestamp_base = ts_base;
            m_utimestamp_scale = ts_scale;
            m_uchannel_id = channel_id;
            return 0;
        }

        virtual int encode(uint8_t* pdata, int len)
        {
            srs_rtsp_debug("encode(pdata:%p, len:%d) begin\n", pdata, len);
            SRS_CHECK_PARAM_PTR(pdata, -1);
            lazy_bitstream bs(pdata, len);
            int ret = encode_header(&bs);
            srs_rtsp_debug("ret:%d = encode_header(&bs)\n", ret);
            SRS_CHECK_RESULT(ret);
            ret = encode_body(&bs);
            srs_rtsp_debug("ret:%d = encode_body(&bs)\n", ret);
             SRS_CHECK_RESULT(ret);

             return bs.pos();
        }

        virtual int encode_header(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);

            m_upkt_len = length();
            // write fixed header
            pbs->write_bit(m_uversin, 2);
            pbs->write_bit(m_upadding, 1);

            pbs->write_bit(m_ureport_count, 5);
            pbs->write_byte(m_upayload_type, 1);
            pbs->write_byte(length(), 2);

            pbs->write_byte(m_ussrc, 4);
            return 0;
        }

        virtual int decode(uint8_t* pdata, int len)
        {
            SRS_CHECK_PARAM_PTR(pdata, -1);
            lazy_bitstream bs(pdata, len);
            int ret = decode_header(&bs);
            SRS_CHECK_RESULT(ret);
            ret = decode_body(&bs);
            SRS_CHECK_RESULT(ret);

             return ret;
        }

        virtual int decode_header(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);

            m_uversin       = pbs->read_bit(2);
            m_upadding      = pbs->read_bit(1);
            m_ureport_count = pbs->read_bit(5);
            m_upayload_type = pbs->read_byte(1);
            m_upkt_len      = pbs->read_byte(2);
            m_ussrc         = pbs->read_byte(4);

            return 0;
        }

        virtual int channel_id() { return m_uchannel_id;}
        virtual int encode_body(lazy_bitstream* pbs) = 0;
        virtual int decode_body(lazy_bitstream* pbs) = 0;
        virtual int length() = 0;
    };
/********************************************************************************************************
 * sender's report
 * 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            NTP timestamp most significant word(sec)           |
 * |            NTP timestamp least significant word(usec)         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       RTP timestamp(32bit)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               sender's packet count(32bit)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               sender's octet count(32bit)                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * NTP timestamp: 64bit, hight 32bit, indicate system clock seconds from 1900, low 32 bit indicate usec of
 * report block
 * *****************************************************************************************************/

    class rtcp_report_block
    {
    public:
        uint32_t    m_ussrc;
        uint8_t     m_ulost;
        uint32_t    m_usum_lost;
        uint32_t    m_useq_num;
        uint32_t    m_uintelval_jitter;
        uint32_t    m_ulast_sr;
        uint32_t    m_udlsr; //delay since last sr
    public:

        int init(uint32_t ssrc, uint8_t drop_num, uint32_t drop_sum, uint32_t seq_num, uint32_t interval_jitter, uint32_t lsr, uint32_t dlsr)
        {
            m_ussrc         = ssrc;
            m_ulost         = drop_num;
            m_usum_lost     = drop_sum;
            m_useq_num      = seq_num;
            m_uintelval_jitter  = interval_jitter;
            m_ulast_sr      = lsr;
            m_udlsr         = dlsr;

            return 0;
        }

        int encode(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);
            pbs->write_byte(m_ussrc, 4);
            pbs->write_byte(m_ulost, 1);
            pbs->write_byte(m_usum_lost, 3);
            pbs->write_byte(m_useq_num, 4);
            pbs->write_byte(m_uintelval_jitter, 4);
            pbs->write_byte(m_ulast_sr, 4);
            pbs->write_byte(m_udlsr, 4);

            return 0;
        }

        int decode(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);

            m_ussrc = pbs->read_byte(4);
            m_ulost = pbs->read_byte(1);
            m_usum_lost = pbs->read_byte(3);
            m_useq_num = pbs->read_byte(4);
            m_uintelval_jitter = pbs->read_byte(4);
            m_ulast_sr = pbs->read_byte(4);
            m_udlsr = pbs->read_byte(4);

            return 0;
        }
    };

    class rtcp_recv_report:public rtcp_packet
    {
    protected:
        std::map<uint32_t, rtcp_report_block*>     m_mreport_blk_list;

    public:
        rtcp_recv_report():rtcp_packet(RECV_REPORT_PAYLOAD_TYPE)
        {
        }

        ~rtcp_recv_report()
        {
            for(std::map<uint32_t, rtcp_report_block*>::iterator it = m_mreport_blk_list.begin(); it != m_mreport_blk_list.end(); it++)
            {
               delete it->second;
            }
            m_mreport_blk_list.clear();
        }
        
        virtual int add_report(uint32_t ssrc, uint8_t drop_num, uint32_t drop_sum, uint32_t seq, uint32_t interval_jitter, uint32_t lsr, uint32_t dlsr)
        {
            remove_report(ssrc);
            rtcp_report_block* prb = new rtcp_report_block();
            prb->init(ssrc, drop_num, drop_sum, seq, interval_jitter, lsr, dlsr);
            m_mreport_blk_list[ssrc] = prb;

            return 0;
        }

        virtual void remove_report(uint32_t ssrc)
        {
            std::map<uint32_t, rtcp_report_block*>::iterator it = m_mreport_blk_list.find(ssrc);
            if(m_mreport_blk_list.end() != it)
            {
                delete it->second;
                m_mreport_blk_list.erase(it);
            }
        }

        int encode_body(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);
            int ret = 0;
            for(std::map<uint32_t, rtcp_report_block*>::iterator it = m_mreport_blk_list.begin(); it != m_mreport_blk_list.end(); it++)
            {
               ret = it->second->encode(pbs);
               srs_rtsp_debug("ret:%d = it->second->encode(pbs)\n", ret);
               SRS_CHECK_RESULT(ret);
            }

            return ret;
        }

        int decode_body(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);

            int ret = 0;
            for(int i = 0; i < m_ureport_count; i++)
            {
                rtcp_report_block* prrb = new rtcp_report_block();
                ret = prrb->decode(pbs);
                SRS_CHECK_RESULT(ret);
                remove_report(prrb->m_ussrc);
                m_mreport_blk_list[prrb->m_ussrc] = prrb;
            }

            return ret;
        }

        virtual int length()
        {
            return 1 + m_mreport_blk_list.size()*6;
        }
    };

    class rtcp_sender_report:public rtcp_packet
    {
    protected:
        uint32_t        m_untp_timestamp_sec;
        uint32_t        m_untp_timestamp_usec;
        uint32_t        m_urtp_timestamp;
        uint32_t        m_upacket_count;
        uint32_t        m_uoctet_count;
        uint32_t        m_utimestamp_base;
        uint32_t        m_utimestamp_scale;

        std::map<uint32_t, rtcp_report_block*>     m_mreport_blk_list;

    public:
        rtcp_sender_report():rtcp_packet(200)
        {
            m_untp_timestamp_sec    = 0;
            m_untp_timestamp_usec   = 0;
            m_urtp_timestamp        = 0;
            m_upacket_count         = 0;
            m_uoctet_count          = 0;
            m_utimestamp_base       = 0;
            m_utimestamp_scale      = 0;
        }
        ~rtcp_sender_report()
        {
            for(std::map<uint32_t, rtcp_report_block*>::iterator it = m_mreport_blk_list.begin(); it != m_mreport_blk_list.end(); it++)
            {
               delete it->second;
            }
            m_mreport_blk_list.clear();
        }

        virtual int init(uint32_t ssrc, uint32_t channel_id, uint32_t ts_base, uint32_t ts_scale, int pkt_num, int octet_num)
        {
            //m_upayload_type = pt;
            srs_rtsp_debug("ssrc:%u, channel_id:%d, ts_base:%u, ts_scale:%u, pkt_num:%d, octet_num:%d\n", ssrc, channel_id, ts_base, ts_scale, pkt_num, octet_num);
            m_ussrc = ssrc;
            m_utimestamp_base = ts_base;
            m_utimestamp_scale = ts_scale;
            m_upacket_count = pkt_num;
            m_uoctet_count = octet_num;
            m_uchannel_id = channel_id;
            return 0;
        }

        virtual int add_report(uint32_t ssrc, uint8_t drop_num, uint32_t drop_sum, uint32_t seq, uint32_t interval_jitter, uint32_t lsr, uint32_t dlsr)
        {
            remove_report(ssrc);
            rtcp_report_block* prb = new rtcp_report_block();
            prb->init(ssrc, drop_num, drop_sum, seq, interval_jitter, lsr, dlsr);
            m_mreport_blk_list[ssrc] = prb;

            return 0;
        }

        virtual void remove_report(uint32_t ssrc)
        {
            std::map<uint32_t, rtcp_report_block*>::iterator it = m_mreport_blk_list.find(ssrc);
            if(m_mreport_blk_list.end() != it)
            {
                delete it->second;
                m_mreport_blk_list.erase(it);
            }
        }

        virtual int encode_body(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);
            struct timeval timeNow;
            int ret = 0;
            gettimeofday(&timeNow, NULL);
            m_untp_timestamp_sec = timeNow.tv_sec + 0x83AA7E80; // times from 1970 convert to times from 1900
            m_untp_timestamp_usec = uint32_t((timeNow.tv_usec/ 15625.0) * 0x4000000 + 0.5);
            m_urtp_timestamp = m_utimestamp_scale * timeNow.tv_sec;
            m_urtp_timestamp += (m_utimestamp_scale * (timeNow.tv_usec / 1000000.0) + 0.5);
            m_urtp_timestamp = m_utimestamp_base + m_urtp_timestamp;
            lbtrace("m_untp_timestamp_sec:%u, m_untp_timestamp_usec:%u, m_urtp_timestamp:%u\n", m_untp_timestamp_sec, m_untp_timestamp_usec, m_urtp_timestamp);
            pbs->write_byte(m_untp_timestamp_sec, sizeof(m_untp_timestamp_sec));
            pbs->write_byte(m_untp_timestamp_usec, sizeof(m_untp_timestamp_usec));
            pbs->write_byte(m_urtp_timestamp, sizeof(m_urtp_timestamp));
            pbs->write_byte(m_upacket_count, sizeof(m_upacket_count));
            pbs->write_byte(m_uoctet_count, sizeof(m_uoctet_count));

            for(std::map<uint32_t, rtcp_report_block*>::iterator it = m_mreport_blk_list.begin(); it != m_mreport_blk_list.end(); it++)
            {
               ret = it->second->encode(pbs);
               SRS_CHECK_RESULT(ret);
            }
            return ret;
        }

        int decode_body(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);
            int ret = 0;
            m_untp_timestamp_sec = pbs->read_byte(sizeof(m_untp_timestamp_sec));
            m_untp_timestamp_usec = pbs->read_byte(sizeof(m_untp_timestamp_usec));
            m_urtp_timestamp = pbs->read_byte(sizeof(m_urtp_timestamp));
            m_upacket_count = pbs->read_byte(sizeof(m_upacket_count));
            m_uoctet_count = pbs->read_byte(sizeof(m_uoctet_count));
            for(int i = 0; i < m_ureport_count; i++)
            {
                rtcp_report_block* prrb = new rtcp_report_block();
                ret = prrb->decode(pbs);
                SRS_CHECK_RESULT(ret);
                remove_report(prrb->m_ussrc);
                m_mreport_blk_list[prrb->m_ussrc] = prrb;
            }
            return 0;
        }

        virtual int length()
        {
            return 6 + m_mreport_blk_list.size() * 6;
        }
    };
/***********************************************************************************************************
 * source description option:
 * 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      TYPE     | length        |  description option of source |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                            ...                                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * TYPE: 8bit, value can be
 * 1:CNAME, user and domain name
 * 2:NAME, common name of source
 * 3:EMAIL, email address of source
 * 4:PHONE, phone number of source
 * 5:LDC, geographic location of sit
 * 6:TOOL, application tool name of the source
 * 7:NOTE, note about the source
 * 8:PRIV, private extension of the source
 * 
 * length: 8bit, length of the description
 * description option of source: description string of the source
 * ********************************************************************************************************/
    class source_description
    {
    public:
        uint8_t     m_utype;
        uint8_t     m_ulen;
        uint8_t     m_u32_len;
        std::string m_src_desc;

    public:

        int init(int type, int len, std::string desc)
        {
            m_utype = type;
            m_ulen = len;
            m_src_desc = desc;
            m_u32_len = (m_ulen + 2 + 1 + 3)/4; // 2 bytes lenth and 1 byte string end flag '\0'
            return 0;
        }

        int encode(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);

            pbs->write_byte(m_utype, 1);
            pbs->write_byte(m_ulen, 1);
            pbs->write_bytes((uint8_t*)m_src_desc.c_str(), m_src_desc.length()+1);
            int remain = m_u32_len * 4 - m_ulen - 3;
            while(remain-- > 0)
            {
                pbs->write_byte(0, 1);
            }
            return 0;
        }

        int decode(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);
            SRS_CHECK_VALUE(pbs->require(2), -1);
            m_utype = pbs->read_byte(1);
            m_ulen = pbs->read_byte(1);
            SRS_CHECK_VALUE(pbs->require(m_ulen), -1);
            m_src_desc.clear();
            m_src_desc.append((char*)pbs->cur_ptr(), m_ulen);
            return 0;
        }

        int uint32_length()
        {
            return m_u32_len;
        }
    };

    class rtcp_source_description:public rtcp_packet
    {
    public:
        std::map<int, source_description*>        m_msrc_desc_list;
    public:
        rtcp_source_description():rtcp_packet(SDES_PAYLOAD_TYPE)
        {
        }

        ~rtcp_source_description()
        {
        }
        
        int add_sdes(int type, int len, std::string desc)
        {
            remove_sdes(type);
            srs_rtsp_debug("desc:%s, len:%d\n", desc.c_str(), len);
            source_description* pdesc = new source_description();
            pdesc->init(type, len, desc);
            m_msrc_desc_list[type] = pdesc;
            m_ureport_count = m_msrc_desc_list.size();
            return 0;
        }
        
        int add_cname()
        {
            char hostname[256] = {0};
            gethostname(hostname, 256);
            srs_rtsp_debug("hostname:%s\n", hostname);
            std::string desc = hostname;
            return add_sdes(1, strlen(hostname), desc);

        }
        void remove_sdes(int type)
        {
            std::map<int, source_description*>::iterator it = m_msrc_desc_list.find(type);
            if(m_msrc_desc_list.end() != it)
            {
                delete it->second;
                m_msrc_desc_list.erase(it);
            }
        }
        virtual int encode_body(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);
            int ret = 0;
            for(std::map<int, source_description*>::iterator it = m_msrc_desc_list.begin(); it != m_msrc_desc_list.end(); it++)
            {
                ret = it->second->encode(pbs);
                SRS_CHECK_RESULT(ret);
            }

            return ret;
        }

        virtual int decode_body(lazy_bitstream* pbs)
        {
            SRS_CHECK_PARAM_PTR(pbs, -1);
            int ret = 0;
            for(std::map<int, source_description*>::iterator it = m_msrc_desc_list.begin(); it != m_msrc_desc_list.end(); it++)
            {
                ret = it->second->decode(pbs);
                SRS_CHECK_RESULT(ret);
            }

            return ret;
        }

        virtual int length()
        {
            int u32_len = 1;
            for(std::map<int, source_description*>::iterator it = m_msrc_desc_list.begin(); it != m_msrc_desc_list.end(); it++)
            {
                u32_len += it->second->uint32_length();
            }
            return u32_len;
        }
    };

    static rtcp_packet* decode_rtcp_packet(int channel_id, uint8_t* pdata, int len)
    {
        rtcp_packet* prp = NULL;
        uint8_t pt = pdata[1];
        if(SEND_REPORT_PAYLOAD_TYPE == pt)
        {
            prp = new rtcp_sender_report();
        }
        else if(RECV_REPORT_PAYLOAD_TYPE == pt)
        {
            prp = new rtcp_recv_report();
        }
        else if(SDES_PAYLOAD_TYPE == pt)
        {
            prp = new rtcp_source_description();
        }
        else if(BYE_PAYLOAD_TYPE == pt)
        {
            return NULL;
        }
        else
        {
            srs_error("Invalid payload type:%d\n", (int)pt);
            return NULL;
        }
        
        lazy_bitstream bs(pdata, len);
        int ret = prp->decode(pdata, len);
        prp->m_uchannel_id = channel_id;
        if(ret < 0)
        {
            srs_error("ret:%d = prp->decode(pdata:%p, len:%d) failed\n", ret, pdata, len);
            return NULL;
        }

            return prp;
    }
};
