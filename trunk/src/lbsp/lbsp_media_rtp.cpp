/****************************************************************************************************
 * RTP Data Transfer Protocol, @see rtp-rfc3550-2003.pdf, page 12
 * RTSP Header
 * 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|      Magic    |    channel    |			packet length 	      |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * Magic  : 8 bit, must be 0x24('$')
 * channel: 8 bit, channel id of rtp payload
 * packet length: 16 bit, rtsp packet length, not include rtsp header size
 * 
 * RTP Header format:
 * 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|V=2|P|X|  CC   |M|     PT      |			sequence number 	  |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|							timestamp							  |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *							  SSRC								  |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *							  CSRC								  |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * V   	: 2bit, rtp protocol version, current version is 2
 * P	: 1bit, padding bit, If the padding bit is set, the packet contains one or more additional padding octets at the end which are not part of the payload. 
 * The last octet of the padding contains a count of how many padding octets should be ignored
 * X 	: 1bit, extension bit, if set, indicate there are extendsion header followed by rtp packet header
 * CC	: 4bit, CSRC counter, indicate the numbers of CSRC in RTP header
 * M 	: 1bit, mark flag, for video, 1 indicate a frame's end, for audio, 1 indicate a session begin
 * PT	: 7bit, payload type, use to indicate RTP packet payload type, so that app can parser this rtp packet with right ways
 * seq  : 16bit, sequence number, increase 1 for every send packet, so that app can receive it in sequnece
 * ts	: 32bit, rtp packet timestamp in 90000hz per second
 * SSRC : 32bit, RTP synchronization source identifier, idenfity a media source
 * CSRC : 32bit, contributing source identifier, idenfity contributing media source
 * 
 * H264 NAL header
 * 0 1 2 3 4 5 6 7 
 *+-+-+-+-+-+-+-+-+
 *|F|NRI|  TYPE   |
 *+-+-+-+-+-+-+-+-+
 * F	: 1bit, forbiden bit, must be 0
 * NRI	: 2bit, NAL reference idc, indicate rtp important level
 * TYPE	: 5bit, H264 NAL type
 * 
 * H264 FU-A header
 * 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|F|NRI| PT TYPE |S|E|R| NAL TYPE|
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * F	: 1bit, forbiden bit, must be 0
 * NRI	: 2bit, NAL reference idc, indicate rtp important level
 * PT TYPE	: 5bit, RTP packet type(FU-A:28)
 * S	: 1bit, if 1, indicate the rtp pacekt is a start of NAL UNIT
 * E	: 1bit, if 1, indicate the rtp packet is a end of NAL UNIT
 * R	: 1bit, reserve, must be 0
 * NAL TYPE: 5bit, RTP payload's NAL UNIT type, 1~12 use by h264, 13~23:reserve, 24~29 use by rtp segment, 30~31 not define
 * 
 * HEVC NAL header
 * 1 
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 * |F|   Type    |  LayerId  | TID | 
 * +-------------+-----------------+ 
 * F		: 1 bit, forbidden_zero_bit, must be 1
 * Type		: 6 bit, nal unit type or Fragmentation unit(FU:49), 0~40 HEVC NAL type, 41~63 RTP fragment type
 * LayerId	: 6 bit, LayerId, usually is 0
 * TID		: 6 bit, temporal id plus 1
 * 
 * Temporal sub-layer access picture(key frame)
 * NAL_TRAIL_N    = 0,
 * NAL_TRAIL_R    = 1,
 * NAL_TSA_N      = 2,
 * NAL_TSA_R      = 3,
 * NAL_STSA_N     = 4,
 * NAL_STSA_R     = 5,
 * Leading picture(NON key frame)
 * NAL_RADL_N     = 6,
 * NAL_RADL_R     = 7,
 * NAL_RASL_N     = 8,
 * NAL_RASL_R     = 9,
 * Random access pointer picture(NON key frame)
 * NAL_BLA_W_LP   = 16,
 * NAL_BLA_W_RADL = 17,
 * NAL_BLA_N_LP   = 18,
 * NAL_IDR_W_RADL = 19,
 * NAL_IDR_N_LP   = 20,
 * NAL_CRA        = 21,
 * 
 * NAL_UNIT_VPS	  = 32,
 * NAL_UNIT_SPS	  = 33,
 * NAL_UNIT_PPS	  = 34,
 * NAL_UNIT_ACCESS_UNIT_DELIMITER = 35,
 * NAL_UNIT_EOS   = 36,
 * NAL_UNIT_EOB	  = 37,
 * NAL_UNIT_FILTER_DATE = 38,
 * NAL_UNIT_SEI	  = 39,
 * NAL_UNIT_SET_SUFFIX = 40,
 * RTP FU header
 * 0 1 2 3 4 5 6 7 
 *+-+-+-+-+-+-+-+-+
 *|S|E|  NalType  |
 *+-+-+-+-+-+-+-+-+
 * S 	  : 1 bit, if 1, indicate the rtp pacekt is a start of NAL UNIT
 * E	  : 1 bit, if 1, indicate the rtp packet is a end of NAL UNIT
 * FuType : 5 bit, NAL unit type
 * 
 * AU-HEADER-length
 * 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *|      au-header-length(16bit)  | aac packet length 13bit |  0  |
 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * au-header-length : 16bit, au-header length in bits, unusally is 16
 * aac packet length: 13bit, aac packet length
 * reserver			: 3bit, must be 0
 * ***************************************************************************************************/
#pragma once
#include <assert.h>
#include <vector>
#include <memory>
//#include "lbsp_rtsp_stack.h"
#include "lbsp_media_bitstream.hxx"
#include "lbsp_media_avcc.hxx"
#include "lbsp_media_aac_cfg.hxx"
#include "lbsp_media_rtp.hpp"
using namespace std;
// rtsp header magic number
#define RTSP_MAGIC_NUM 					0x24

#define LBSP_PAYLOAD_SEGMENT_TYPE_FU_A 			28

// rtp segment max packet size
#define LBSP_MAX_RTP_PACKET_SIZE 		1400

// fixed rtsp header
#define LBSP_CONST_RTSP_HEADER			4
// min rtp header
#define LBSP_MIN_RTP_HEADER				12

// rtp payload type
#define LBSP_PAYLOAD_TYPE_H264			96
#define LBSP_PAYLOAD_TYPE_AAC			97
#define LBSP_PAYLOAD_TYPE_HEVC			98


namespace lbsp_util
{

	sample_buffer::sample_buffer()
	{

	}

	sample_buffer::~sample_buffer()
	{

	}

	int sample_buffer::length()
	{
		m_vdata.size();
	}

	char* sample_buffer::bytes()
	{
		return m_vdata.size() ? NULL : &m_vdata.at(0);
	}

	void sample_buffer::erase(int begin_pos, int size)
	{
		if(begin_pos + size > m_vdata.size())
		{
			assert(0);
			return ;
		}
		
		m_vdata.erase(m_vdata.begin() + begin_pos, m_vdata.begin() + begin_pos + size);
	}

	void sample_buffer::reset()
	{
		m_vdata.clear();
	}

	void sample_buffer::append(const char* bytes, int size, int pos = -1)
	{
		assert(size > 0 && bytes);
		vector<char>::iterator it = m_vdata.begin();
		if(pos < 0)
		{
			it = m_vdata.end();
		}
		else
		{
			it = m_vdata.begin() + pos;
		}
		
		m_vdata.insert(it, bytes, bytes + size);
	}
	

	rtp_packet::rtp_packet()
	{
		m_uversion = 2;
		m_upadding = 0;
		m_uextension = 0;
		m_ucsrc_count = 0;
		m_umark = 0;
		m_upayload_type = 0;
		m_usequence_number = 0;
		m_utimestamp = -1;
		m_ussrc == NULL;
		m_nchannel = -1;
		m_ertp_segment_type = ertp_segment_type_unknown;
		m_prtp_buffer = NULL;
		m_nrtp_buf_len = 0;
		m_bcomplete	= false;

		m_uforbiden	= 0;
		m_unal_refernece_idc = 0;
		m_unal_type = 0;
		m_ulayer_id = 0;
		m_utid = 0;
		m_ustart = 0;
		m_uend = 0;
		m_ufu_type = 0;
	}

	rtp_packet::~rtp_packet()
	{

	}

	int rtp_packet::encode(int pt, ertp_segment_type segment_type, int& seq_num, uint32_t timestamp, uint32_t ssrc, int channel_id, void* pkt, int size)
	{
		int ret = 0;
		int offset = 0, pkt_len = 0;
		int start = 1, end = 0, nri = 0, nal_type;
		uint8_t* pbegin = (uint8_t*)pkt;
		if(LBSP_PAYLOAD_TYPE_H264 == pt)
		{
			int nal_type = 0, start_code_size = 0;
			string sps, pps;
			pkt_len = m_h264_parser.get_frame_nalu(5, pbegin, size, &offset, &nal_type, &start_code_size);
			CHECK_RESULT(pkt_len);
			offset += start_code_size;
			pkt_len -= start_code_size;
			if(5 == nal_type)
			{
				ret = m_h264_parser.parser_sps_pps(pbegin, size);
				CHECK_RESULT(ret);
				ret = m_h264_parser.get_sps_pps(sps, pps);
				CHECK_RESULT(ret);
				ret = encode_rtp_packet((uint8_t*)sps.c_str(), sps.length());
				CHECK_RESULT(ret);
				ret = encode_rtp_packet((uint8_t*)pps.c_str(), pps.length());
				CHECK_RESULT(ret);
			}
		}
		else if(LBSP_PAYLOAD_TYPE_AAC == pt)
		{
			pkt_len = CAacConfig::demux_aac_frame(pbegin, size, &offset);

		}
		else if(LBSP_PAYLOAD_TYPE_HEVC == pt)
		{
			lbdump(error, "payload hevc not support now! %d\n", 3);
			return -1;
		}
		else
		{
			lbdump(error, "not support payload type %d\n", pt);
			return -1;
		}
		
		ret = encode_rtp_packet(pbegin + offset, pkt_len);
		CHECK_RESULT(ret);
		return 0;
	}

		virtual int encode_rtp_packet(uint8_t* pdata, int size)
		{
			lbtrace("encode_rtp_packet(pdata:%d, size:%d)\n", pdata, size);
			int ret = 0;
			int start = 1, end = 0, forbiden = 0, nri = 0, nal_type = 0;
			int layer_id = 0, tid = 0;
			if(LBSP_PAYLOAD_TYPE_H264 == m_upayload_type)
			{
				int start = 1, end = 0;
				ret = m_pbitstream->initialize(pdata, size);
				CHECK_RESULT(ret);
				int forbiden = m_pbitstream->read_bit(1);
				int nri = m_pbitstream->read_bit(2);
				int nal_type = m_pbitstream->read_bit(5);
				pdata++;
				size--;
				int offset = 0;
				do
				{
					shared_ptr<packet_buffer> ppb(new packet_buffer());
					m_pbitstream->initialize(m_prtp_buffer, m_nrtp_buf_len);
					int pkt_len = get_max_packet_size();
					pkt_len = size - offset > pkt_len ? pkt_len : size - offset;
					ret = encode_rtp_header(m_pbitstream.get());
					CHECK_RESULT(ret);
					if(LBSP_PAYLOAD_TYPE_H264 == m_upayload_type)
					{
						if(0 != offset)
						{
							start = 0;
						}
						
						pkt_len = size - offset > pkt_len ? pkt_len : size - offset;
						end = size - offset == pkt_len ? 1 : 0;
						ret = encoder_rtp_fu_a_segment(m_pbitstream.get(), nri, start, end, nal_type, pdata + offset, pkt_len);
						CHECK_RESULT(ret);
					}
					else if(LBSP_PAYLOAD_TYPE_AAC == m_upayload_type)
					{
						ret = encode_hevc_fragment_unit(m_pbitstream.get(), nal_type, layer_id, tid, start, end, pdata, size);
						CHECK_RESULT(ret);
					}
					
					m_pbitstream->modify_value(m_pbitstream->pos() - 4 + pkt_len, 16, 2);
					ppb->append((char*)m_pbitstream->data(), (int)m_pbitstream->pos());
					ppb->append((char*)pdata, pkt_len);
					m_vpacket_buffer_list.push_back(ppb);
					offset += pkt_len;
					m_usequence_number++;
					lbdump(trace, "header len:%d, pkt_len:%d\n", m_pbitstream->pos(), pkt_len);
				} while (offset < size);
				return 0;
			}
			else if(LBSP_PAYLOAD_TYPE_AAC == m_upayload_type)
			{
				shared_ptr<packet_buffer> ppb(new packet_buffer());
				m_pbitstream->initialize(m_prtp_buffer, m_nrtp_buf_len);
				ret = encode_rtp_header(m_pbitstream.get());
				CHECK_RESULT(ret);
				ret = encode_au_header(m_pbitstream.get(), pdata, size);
				CHECK_RESULT(ret);
				return 0;
			}

			return -1;
		}

		virtual int encode_rtp_header(lazybitstream* pbs)
		{
			CHECK_VALUE(pbs, -1);

			if(!pbs->require(m_nchannel >= 0 ? 16 : 12))
			{
				assert(0);
				return -1;
			}
			if(m_nchannel > 0)
			{
				pbs->write_byte(RTSP_MAGIC_NUM, 1);
				pbs->write_byte(m_nchannel, 1);
				pbs->write_byte(0, 2);
			}
			
			pbs->write_bit(m_uversion, 2);
			pbs->write_bit(m_upadding, 1);
			pbs->write_bit(m_uextension, 1);
			pbs->write_bit(m_ucsrc_count, 4);
			pbs->write_bit(m_umark, 1);
			pbs->write_bit(m_upayload_type, 7);
			pbs->write_byte(m_usequence_number, 2);
			pbs->write_byte(m_utimestamp, sizeof(m_utimestamp));
			pbs->write_byte(m_ussrc, sizeof(m_ussrc));
			lbtrace("m_uversion:%d, m_upadding:%d, m_uextension:%d, m_ucsrc_count:%u, m_umark:%d, m_upayload_type:%u, m_usequence_number:%u, m_utimestamp:%u, m_ussrc:%u\n", m_uversion, m_upadding, m_uextension, m_ucsrc_count, m_umark, m_upayload_type, m_usequence_number, m_utimestamp, m_ussrc);
			return pbs->pos();
		}
	
		virtual int encoder_rtp_fu_a_segment(lazybitstream* pbs, int nri, int start, int end, int nal_type, uint8_t* pdata, int size)
		{
			CHECK_VALUE(pbs, -1);
			CHECK_VALUE(pdata, -1);
			lbdump(trace, "encoder_rtp_fu_a_segment(pbs:%p,  nri:%d,  start:%d, end:%d, nal_type:%d, pdata:%p, size:%d)\n", pbs,  nri,  start, end, nal_type, pdata, size);
			if(!pbs->require(size + 2))
			{
				assert(0);
				return -1;
			}

			pbs->write_bit(0, 1);
			pbs->write_bit(nri, 2);
			if(1 == start && 1 == end)
			{
				pbs->write_bit(nal_type, 5);
			}
			else
			{
				pbs->write_bit(LBSP_PAYLOAD_SEGMENT_TYPE_FU_A, 5);
				pbs->write_bit(start, 1);
				pbs->write_bit(end, 1);
				pbs->write_bit(0, 1);
				pbs->write_bit(nal_type, 5);
			}
			pbs->write_bytes(pdata, size);

			return (int)pbs->pos();
		}

		virtual int encode_hevc_fragment_unit(lazybitstream* pbs, int nal_type, int layer_id,  int tid, int start, int end, uint8_t* pdata, int size)
		{
			CHECK_VALUE(pbs, -1);
			CHECK_VALUE(pdata, -1);
			int type = 42;
			pbs->write_bit(0, 1);
			if(1 == start && 1 == end)
			{
				type = nal_type;
			}
			pbs->write_bit(0, 1);
			pbs->write_bit(nal_type, 6);
			pbs->write_bit(layer_id, 6);
			pbs->write_bit(tid, 6);

			if(42 == type)
			{
				pbs->write_bit(start, 1);
				pbs->write_bit(end, 1);
				pbs->write_bit(nal_type, 6);
			}

			pbs->write_bytes(pdata, size);

			return (int)pbs->pos();
		}
		virtual int encode_au_header(lazybitstream* pbs, uint8_t* pdata, int size)
		{
			CHECK_VALUE(pbs, -1);
			CHECK_VALUE(pdata, -1);
			if(!pbs->require(size + 4))
			{
				assert(0);
				return -1;
			}

			pbs->write_byte(16, 2);
			pbs->write_bit(size, 13);
			pbs->write_bit(0, 3);
			pbs->write_bytes(pdata, size);

			return (int)pbs->pos();
		}

		virtual int get_max_packet_size()
		{
			if(ertp_segment_type_fu_a ==  m_ertp_segment_type || ertp_segment_type_fu_b == m_ertp_segment_type)
			{
				return LBSP_MAX_RTP_PACKET_SIZE;
			}

			return INT32_MAX;
		}

		virtual bool is_complete()
		{
			return m_bcomplete;
		}

		virtual int get_rtp_header_size(int nal_size)
		{
			int size = 12;
			if(m_nchannel > 0)
			{
				size += 4;
			}

			if(ertp_segment_type_fu_a ==  m_ertp_segment_type && nal_size > LBSP_MAX_RTP_PACKET_SIZE)
			{
				size += 1;
			}
			else if(ertp_segment_type_nal == m_ertp_segment_type)
			{
				
			}
			else if(ertp_segment_type_au_header == m_ertp_segment_type)
			{
				size += 4;
			}

			return size;
		}

		virtual int decode(void* pdata, int len)
		{
			CHECK_PARAM_PTR(pdata, -1);
			int ret = m_pbitstream->initialize(pdata, len);
			CHECK_RESULT(ret);
			ret = on_decode_rtp_header(m_pbitstream.get());
			CHECK_RESULT(ret);
			return ret;
		}

			virtual int on_decode_rtp_header(lazybitstream* pbs)
			{
				int forbiden = 0, nri = 0, type = 0;
				int start = 0, end = 0, reserve = 0, nal_type = 0;
				int seq_num = 0;
				shared_ptr<packet_buffer> payload;
				CHECK_PARAM_PTR(pbs, -1);
				CHECK_VALUE(pbs->require(LBSP_CONST_RTSP_HEADER), -1);
				int rtp_pkt_size = pbs->remain();
				if(RTSP_MAGIC_NUM == *pbs->data())
				{
					// read rtsp header
					m_pbitstream->read_byte(1);
					m_nchannel = m_pbitstream->read_byte(1);
					rtp_pkt_size = m_pbitstream->read_byte(2);
				}

				CHECK_VALUE(pbs->require(LBSP_MIN_RTP_HEADER), -1);

				// rtp header
				m_uversion = m_pbitstream->read_bit(2);
				m_upadding = m_pbitstream->read_bit(1);
				m_uextension = m_pbitstream->read_bit(1);
				m_ucsrc_count = m_pbitstream->read_bit(4);
				m_umark = m_pbitstream->read_bit(1);
				m_upayload_type = m_pbitstream->read_bit(7);
				seq_num = m_pbitstream->read_byte(2);
				m_utimestamp = m_pbitstream->read_byte(4);
				m_ussrc = m_pbitstream->read_byte(4);
				rtp_pkt_size -= LBSP_MIN_RTP_HEADER;

				if(LBSP_PAYLOAD_TYPE_H264 == m_upayload_type)
				{
					forbiden = m_pbitstream->read_bit(1);
					nri = m_pbitstream->read_bit(2);
					type = m_pbitstream->read_bit(5);
					rtp_pkt_size--;
					if(type > 23)
					{
						start = m_pbitstream->read_bit(1);
						end = m_pbitstream->read_bit(1);
						reserve = m_pbitstream->read_bit(1);
						nal_type = m_pbitstream->read_bit(5);
						rtp_pkt_size--;
					}
					else
					{
						nal_type = type;
					}
					
					if(1 == start)
					{
						*m_prtp_buffer = forbiden << 7 | nri << 5 | nal_type;
						m_bcomplete = false;
						payload = get_payload(true);
						m_usequence_number = seq_num;
					}
					else
					{
						payload = get_payload();
						if(m_usequence_number + 1 != seq_num)
						{
							lberror("m_usequence_number:%u + 1 != seq_num:%d, rtp packet not continue!\n", m_usequence_number , seq_num);
							return -1;
						}
					}
					
					if(1 == end)
					{
						m_bcomplete = true;
					}
					if(payload)
					{
						payload->append((char*)m_prtp_buffer, 1);
						payload->append((char*)m_pbitstream->data() + m_pbitstream->pos(), rtp_pkt_size);
					}
					m_pbitstream->move(rtp_pkt_size);
				}
				else if(LBSP_PAYLOAD_TYPE_HEVC == m_upayload_type)
				{
					uint8_t	forbiden = m_pbitstream->read_bit(1);
					uint8_t type = m_pbitstream->read_bit(6);
					uint8_t layer_id = m_pbitstream->read_bit(6);
					uint8_t tid = m_pbitstream->read_bit(3);
					uint8_t start = 0, end = 0;
					uint8_t nal_type = 0;
					rtp_pkt_size -= 2;
					if(type > 40)
					{
						start = m_pbitstream->read_bit(1);
						end = m_pbitstream->read_bit(1);
						nal_type = m_pbitstream->read_bit(6);
						rtp_pkt_size--;
					}
					else
					{
						nal_type = type;
					}
					if(start)
					{
						payload = get_payload(true);
					}
					else
					{
						payload = get_payload();
					}
					
					if(end)
					{
						m_bcomplete = true;
					}
					char buf[256] = {0};
					lazybitstream bs(buf, 256);
					bs.write_bit(forbiden, 1);
					bs.write_bit(nal_type, 6);
					bs.write_bit(layer_id, 6);
					bs.write_bit(tid, 3);

					if(payload)
					{
						payload->append((const char*)bs.data(), bs.pos());
						payload->append((const char*)m_pbitstream->cur_ptr(), rtp_pkt_size);
						
					}
					m_pbitstream->move(rtp_pkt_size);
				}
				else if(LBSP_PAYLOAD_TYPE_AAC == m_upayload_type)
				{
					int au_theader_length = m_pbitstream->read_byte(2);
					int pkt_len = m_pbitstream->read_bit(13);
					m_pbitstream->read_bit(3);
					payload = get_payload(true);
					payload->append((char*)m_pbitstream->data() + m_pbitstream->pos(), pkt_len);
					m_pbitstream->move(pkt_len);
				}

				return 0;
			}

protected:
		shared_ptr<packet_buffer> get_payload(bool bnext = false)
		{
			if(bnext)
			{
				shared_ptr<packet_buffer> ppb(new packet_buffer()); 
				m_vpacket_buffer_list.push_back(ppb);
			}
			
			return m_vpacket_buffer_list[m_vpacket_buffer_list.size()-1];
		}
	};
};