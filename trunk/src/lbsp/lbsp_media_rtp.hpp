#pragma once
#include <assert.h>
#include <vector>
#include <memory>

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
	class lazybitstream;
	enum ertp_segment_type
	{
		ertp_segment_type_unknown = -1,
		ertp_segment_type_nal,
		ertp_segment_type_fu_a,
		ertp_segment_type_fu_b,
		ertp_segment_type_au_header,

	};

	class sample_buffer
	{
	protected:
		vector<char>		m_vdata;
	
	public:
		sample_buffer(){}
		~sample_buffer(){}
	public:
		/**
		* get the length of buffer
		* @remark assert length() is not negative.
		**/
		virtual int length();
		/**
		* get packet buffer pointer
		* @return buffer ptr, NULL if empty
		**/
		virtual char* bytes();
		/**
		* erase bytes of data from specify pos
		* @param begin_pos: position of begin erase
		* @param size: size to erase from begin_pos
		**/
		virtual void erase(int begin_pos, int size);
		/**
		* reset packet buffer to empty
		**/
		virtual void reset();
		/**
		* append data to specified packet buffer
		* @param bytes: bytes to append
		* @param size: append bytes size
		* @param pos: append bytes position
		**/
		// append specified bytes to packet buffer
		virtual void append(const char* bytes, int size, int pos = -1);
	};
	
	class rtp_packet
	{
	protected:
		// rtp packet version(V), 2 bits, current verssion number is 2
		uint8_t			m_uversion;

		// padding(P), 1 bit, if set, the packet contains one or more additional padding at the end of payload, the last occtet of padding indicate numbers of padding octets should be ignored.
		uint8_t			m_upadding;

		// extension(X), 1 bit, if set, a extension header must by followed by rtp header
		uint8_t			m_uextension;

		// CSRC count(CC) count, 4 bit, indicate RTP header contian the number of CSRC identiers in rtp header
		uint8_t			m_ucsrc_count;

		// Mark(M)), 1 bit, 
		uint8_t			m_umark;

		// payload type(PT), 7 bit, identies the format of the RTP payload type
		uint8_t			m_upayload_type;

		// sequence number, 16 bit, ncrements by one for each RTP data packet sent
		uint16_t		m_usequence_number;

		// timestamp, 32 bits, rtp packet's timestamp, in 90000hz per second
		uint32_t		m_utimestamp;

		// SSRC 32 bits, , identies the synchronization source, This identier should be chosen randomly
		uint32_t		m_ussrc;

		// channel id;
		int8_t			m_nchannel;

		bool			m_bcomplete;

		// segment type
		ertp_segment_type	m_ertp_segment_type;				

		vector<shared_ptr<packet_buffer>>		m_vpacket_buffer_list;
		uint8_t* 								m_prtp_buffer;
		int										m_nrtp_buf_len;

		// rtp header
		uint8_t			m_uforbiden;
		uint8_t			m_unal_refernece_idc;
		uint8_t			m_unal_type;
		uint8_t			m_ulayer_id;
		uint8_t			m_utid;
		uint8_t			m_ustart;
		uint8_t			m_uend;
		uint8_t			m_ufu_type;

	public:
		rtp_packet();

		~rtp_packet();

		//void init(int pt, ertp_segment_type segment_type, int* pseq_num, uint32_t timestamp, uint32_t ssrc, int channel_id = -1);

		virtual int encode(int pt, ertp_segment_type segment_type, int& seq_num, uint32_t timestamp, uint32_t ssrc, int channel_id, void* pkt, int size);

		virtual int encode_rtp_packet(uint8_t* pdata, int size);

		virtual int encode_rtp_header(lazybitstream* pbs);

		virtual int encode_hevc_fragment_unit(lazybitstream* pbs, int nal_type, int layer_id,  int tid, int start, int end, uint8_t* pdata, int size);

		virtual int encode_au_header(lazybitstream* pbs, uint8_t* pdata, int size);

		virtual int get_max_packet_size();

		virtual bool is_complete();

		virtual int get_rtp_header_size(int nal_size);

		virtual int decode(void* pdata, int len);

		virtual int on_decode_rtp_header(lazybitstream* pbs);

protected:
		shared_ptr<packet_buffer> get_payload(bool bnext = false);
	};
};