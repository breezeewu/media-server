#pragma once
#include <string>
#include <vector>
#include <lbsp_media_bitstream.hpp>
#define AVC_NAL_TYPE_MASK	0x1f
#define HEVC_NAL_TYPE_MASK	0x7e

#define AVC_PROFILE_BASELINE		66
#define AVC_PROFILE_MAIN			77
#define AVC_PROFILE_EXTENDED		88
#define AVC_PROFILE_HIGHT_FREXT		100
#define AVC_PROFILE_HIGHT10_FREXT   110
#define AVC_PROFILE_HIGHT_422_FREXT 122
#define AVC_PROFILE_HIGHT_444_FREXT 144

#define AVC_STREAM_TYPE				4
#define HEVC_STREAM_TYPE			5
#define ue_size uint8_t
#define se_size uint8_t
using namespace std;
namespace lbsp_util
{
	enum EAVC_NAL_TYPE
	{
		EAVC_NAL_UNKNOWN			= 0, // not use
		EAVC_NAL_SLICE				= 1, // not idr slice
		EAVC_NAL_DPA				= 2, // slice data partition a layer
		EAVC_NAL_DPB				= 3, // slice data partition b layer
		EAVC_NAL_DPC				= 4, // slice data partition c layer
		EAVC_NAL_IDR				= 5, // instantaneous decoding refresh slice
		EAVC_NAL_SEI				= 6, // supplemental enhancement information
		EAVC_NAL_SPS				= 7, // sequence parameter set
		EAVC_NAL_PPS				= 8, // picture parameter set
		EAVC_NAL_AUD				= 9, // access unit delimiter
		EAVC_NAL_END_SEQ			= 10,// end of sequence
		EAVC_NAL_END_STREAM			= 11,// end of stream
		EAVC_NAL_FILLER_DATA		= 12,// fill data
		// 13-23 reserved
		// 24-31 not use
	};

	enum EHEVC_NAL_TYPE {
		HEVC_NAL_TRAIL_N = 0,
		HEVC_NAL_TRAIL_R = 1,
		HEVC_NAL_TSA_N = 2,
		HEVC_NAL_TSA_R = 3,
		HEVC_NAL_STSA_N = 4,
		HEVC_NAL_STSA_R = 5,
		HEVC_NAL_RADL_N = 6,
		HEVC_NAL_RADL_R = 7,
		HEVC_NAL_RASL_N = 8,
		HEVC_NAL_RASL_R = 9,
		HEVC_NAL_VCL_N10 = 10,
		HEVC_NAL_VCL_R11 = 11,
		HEVC_NAL_VCL_N12 = 12,
		HEVC_NAL_VCL_R13 = 13,
		HEVC_NAL_VCL_N14 = 14,
		HEVC_NAL_VCL_R15 = 15,
		// hevc keyframe
		HEVC_NAL_BLA_W_LP = 16,
		HEVC_NAL_BLA_W_RADL = 17,
		HEVC_NAL_BLA_N_LP = 18,
		HEVC_NAL_IDR_W_RADL = 19,
		HEVC_NAL_IDR_N_LP = 20,
		HEVC_NAL_CRA_NUT = 21,

		HEVC_NAL_IRAP_VCL22 = 22,
		HEVC_NAL_IRAP_VCL23 = 23,
		HEVC_NAL_RSV_VCL24 = 24,
		HEVC_NAL_RSV_VCL25 = 25,
		HEVC_NAL_RSV_VCL26 = 26,
		HEVC_NAL_RSV_VCL27 = 27,
		HEVC_NAL_RSV_VCL28 = 28,
		HEVC_NAL_RSV_VCL29 = 29,
		HEVC_NAL_RSV_VCL30 = 30,
		HEVC_NAL_RSV_VCL31 = 31,
		HEVC_NAL_VPS = 32,
		HEVC_NAL_SPS = 33,
		HEVC_NAL_PPS = 34,
		HEVC_NAL_AUD = 35,
		HEVC_NAL_EOS_NUT = 36,
		HEVC_NAL_EOB_NUT = 37,
		HEVC_NAL_FD_NUT = 38,
		HEVC_NAL_SEI_PREFIX = 39,
		HEVC_NAL_SEI_SUFFIX = 40,
		HEVC_NAL_RSV_NVCL41 = 41,
		HEVC_NAL_RSV_NVCL42 = 42,
		HEVC_NAL_RSV_NVCL43 = 43,
		HEVC_NAL_RSV_NVCL44 = 44,
		HEVC_NAL_RSV_NVCL45 = 45,
		HEVC_NAL_RSV_NVCL46 = 46,
		HEVC_NAL_RSV_NVCL47 = 47,
		HEVC_NAL_UNSPEC48 = 48,
		HEVC_NAL_UNSPEC49 = 49,
		HEVC_NAL_UNSPEC50 = 50,
		HEVC_NAL_UNSPEC51 = 51,
		HEVC_NAL_UNSPEC52 = 52,
		HEVC_NAL_UNSPEC53 = 53,
		HEVC_NAL_UNSPEC54 = 54,
		HEVC_NAL_UNSPEC55 = 55,
		HEVC_NAL_UNSPEC56 = 56,
		HEVC_NAL_UNSPEC57 = 57,
		HEVC_NAL_UNSPEC58 = 58,
		HEVC_NAL_UNSPEC59 = 59,
		HEVC_NAL_UNSPEC60 = 60,
		HEVC_NAL_UNSPEC61 = 61,
		HEVC_NAL_UNSPEC62 = 62,
		HEVC_NAL_UNSPEC63 = 63,
	};

	class lazy_xvc_stream :public lazy_bitstream
	{
	protected:
		int				m_nstream_type;
		uint8_t			m_unal_type_mask;
		uint8_t			m_unal_type_vps;
		uint8_t			m_unal_type_sps;
		uint8_t			m_unal_type_pps;

		uint8_t			m_uxvcc_fixed_header_size;
		uint8_t			m_uxvcc_fixed_metadata_prefix_size;
		uint8_t			m_uxvcc_fixed_nal_prefix_size;

		int				m_nwidth;
		int				m_nheight;
		string			m_vsh;
		//string			m_ash;

		vector<string>	m_vps_list;
		vector<string>	m_sps_list;
		vector<string>	m_pps_list;
		
	public:
		// 4: h.264, 5:h.265
		lazy_xvc_stream(int xvc_stream_type, const void* pdata = NULL, int len = 0) :lazy_bitstream((void*)pdata, len)
		{
			m_nstream_type = xvc_stream_type;
			if (AVC_STREAM_TYPE == m_nstream_type)
			{
				// h264 stream
				m_unal_type_vps = 0;
				m_unal_type_sps = EAVC_NAL_SPS;
				m_unal_type_pps = EAVC_NAL_PPS;
				m_unal_type_mask = AVC_NAL_TYPE_MASK;
				m_uxvcc_fixed_header_size = 5;
				m_uxvcc_fixed_metadata_prefix_size = 1;
				m_uxvcc_fixed_nal_prefix_size = 2;
			}
			else if (HEVC_STREAM_TYPE == m_nstream_type)
			{
				// h265 stream
				m_unal_type_vps = HEVC_NAL_VPS;
				m_unal_type_sps = HEVC_NAL_SPS;
				m_unal_type_pps = HEVC_NAL_PPS;
				m_unal_type_mask = HEVC_NAL_TYPE_MASK;
				m_uxvcc_fixed_header_size = 23;
				m_uxvcc_fixed_metadata_prefix_size = 3;
				m_uxvcc_fixed_nal_prefix_size = 2;
			}
			else
			{
				assert(0);
			}
		}

		void reset()
		{
			m_pcur_ptr		= m_pdata;
			m_nbit_offset	= 0;
			m_nwidth		= 0;
			m_nheight		= 0;

			m_vsh.clear();
			m_vps_list.clear();
			m_sps_list.clear();
			m_pps_list.clear();
		}

		bool is_sequence_header(int nal_type)
		{
			if (AVC_STREAM_TYPE == m_nstream_type)
			{
				// h264 stream
				if(EAVC_NAL_SPS == nal_type || EAVC_NAL_PPS == nal_type)
				{
					return true;
				}
			}
			else if (HEVC_STREAM_TYPE == m_nstream_type)
			{
				// h265 stream
				// h264 stream
				if(HEVC_NAL_VPS == nal_type || HEVC_NAL_SPS == nal_type || HEVC_NAL_PPS == nal_type)
				{
					return true;
				}
			}
			else
			{
				assert(0);
			}
			

			return false;
		}

		string get_vps(int idx = 0)
		{
			if(idx >= (int)m_vps_list.size())
			{
				return string();
			}
			return m_vps_list[idx];
		}

		string get_sps(int idx = 0)
		{
			if(idx >= (int)m_sps_list.size())
			{
				return string();
			}
			return m_sps_list[idx];
		}

		string get_pps(int idx = 0)
		{
			if(idx >= (int)m_pps_list.size())
			{
				return string();
			}
			return m_pps_list[idx];
		}

		string get_sequence_header()
		{
			return m_vsh;
		}

		int get_vps_sps_pps(std::string& vps, std::string& sps, std::string& pps)
		{
			if (m_vps_list.size() > 0)
			{
				vps = m_vps_list[0];
			}

			if (m_sps_list.size() > 0)
			{
				sps = m_sps_list[0];
			}

			if (m_pps_list.size() > 0)
			{
				pps = m_pps_list[0];
			}

			return 0;
		}
		bool is_sequence_header_type(int nal_type)
		{
			if(m_unal_type_vps == nal_type || m_unal_type_sps == nal_type || m_unal_type_pps == nal_type)
			{
				return true;
			}

			return false;
		}
		bool is_frame_nalu(int nal_type, bool idr = false)
		{
			if(AVC_STREAM_TYPE == m_nstream_type)
			{
				if(EAVC_NAL_IDR == nal_type)
				{
					return true;
				}
				else if(!idr && nal_type >= 1 && nal_type < EAVC_NAL_IDR)
				{
					return true;
				}
			}
			else if(HEVC_STREAM_TYPE == m_nstream_type)
			{
				if(HEVC_NAL_BLA_W_LP <= nal_type && HEVC_NAL_CRA_NUT >= nal_type)
				{
					return true;
				}
				else if(!idr && HEVC_NAL_TRAIL_N < nal_type && HEVC_NAL_BLA_W_LP > nal_type)
				{
					return true;
				}
			}

			return false;
		}

		bool is_start_code(const char* pdata, int len, int* pstart_code_len = NULL)
		{
			int i = 0;
			if(NULL == pdata || len < 4)
			{
				return false;
			}
			while(0 == pdata[i] && i < 4)i++;
			if(1 == pdata[i] && (2 == i || 3 == i))
			{
				if(pstart_code_len)
				{
					*pstart_code_len = i + 1;
				}
				return true;
			}

			return false;
		}

		int get_start_code_size(const char* pdata, int len)
		{
			int i = 0;
			for(i = 0; i < len; i++) if(0 != pdata[i])break;
			if(i > 0 && 1 == pdata[i])
			{
				i++;
				//break;
			}

			return i;
		}

		int parse_stream(const void* pdata = NULL, int len = 0)
		{
			int ret = 0;
			int nal_len = 0;
			int nal_type = 0;
			const char* pnal_begin = NULL;
			if(pdata && len > 0)
			{
				initialize((void*)pdata, len);
			}

			if (remain() <= 4)
			{
				lberror("Not enought stream for parser remain:%d\n", remain());
				return -1;
			}

			while (remain() > 0)
			{
				pnal_begin = get_nal((char*)m_pcur_ptr, remain(), &nal_len, &nal_type, true);
				if (pnal_begin)
				{
					ret = on_parse_nalu(nal_type, pnal_begin, nal_len);
					if (ret != 0)
					{
						break;
					}
					m_pcur_ptr = (uint8_t*)pnal_begin + nal_len;
				}
				else
				{
					return 0;
				}
			}

			return ret;
		}

		virtual int on_parse_nalu(int nal_type, const char* pdata, int len)
		{
			string str;
			int start_code_size = get_start_code_size(pdata, len);
			if(AVC_STREAM_TYPE == m_nstream_type)
			{
				if(EAVC_NAL_SPS == nal_type)
				{
					m_vsh.clear();
					str.append(pdata + start_code_size, len - start_code_size);
					m_sps_list.push_back(str);
					m_vsh.append(pdata, len);
				}
				else if(EAVC_NAL_PPS == nal_type)
				{
					str.append(pdata + start_code_size, len - start_code_size);
					m_pps_list.push_back(str);
					m_vsh.append(pdata, len);
				}
			}
			else if(HEVC_STREAM_TYPE == m_nstream_type)
			{
				if(HEVC_NAL_VPS == nal_type)
				{
					m_vsh.clear();
					str.append(pdata + start_code_size, len - start_code_size);
					m_vps_list.push_back(str);
				}
				else if(HEVC_NAL_SPS == nal_type)
				{
					str.append(pdata + start_code_size, len - start_code_size);
					m_sps_list.push_back(str);
					m_vsh.append(pdata, len);
				}
				else if(HEVC_NAL_PPS == nal_type)
				{
					str.append(pdata + start_code_size, len - start_code_size);
					m_pps_list.push_back(str);
					m_vsh.append(pdata, len);
				}
			}

			return 0;
		}

		int read_nal_type(const char* pdata = NULL, int len = 0)
		{
			int ret = -1;
			uint8_t nal_type = -1;
			lazy_bitstream* pbs = this;
			do {
				if (pdata && len > 0)
				{
					pbs = new lazy_bitstream((uint8_t*)pdata, len);
				}
				uint8_t forbiden = pbs->read_bit(1);
				if (0 != forbiden)
				{
					//lberror("Invalid nal data, forbiden bit is not zero\n");
					//lbmemory(pbs->data(), 16);
					break;
				}
				
				if (AVC_STREAM_TYPE == m_nstream_type)
				{
					pbs->read_bit(2);
					nal_type = pbs->read_bit(5);
				}
				else if (HEVC_STREAM_TYPE == m_nstream_type)
				{
					nal_type = pbs->read_bit(6);
					pbs->read_bit(6);
					pbs->read_bit(3);
				}
				else
				{
					break;
				}
				ret = 0;
			} while (0);

			if (pbs != this)
			{
				delete pbs;
				pbs = NULL;
			}

			return 0 == ret ? nal_type : ret;
		}

		const char* find_start_code(const char* pdata, int len, int* pstart_code_size = NULL, int* pnal_type = NULL)
		{
			int i = 0;
			int start_code_size = 3;
			while ((i < len - 3) && (0 != pdata[i] || 0 != pdata[i + 1] || 1 != pdata[i + 2])) i++;
			if (i >= len - 4)
			{
				// can't find start code
				return NULL;
			}
			else
			{
				if ((i > 0 && 0 == pdata[i - 1]))
				{
					start_code_size += 1;
					i--;
				}
				if (pstart_code_size)
				{
					*pstart_code_size = start_code_size;
				}
				if (pnal_type)
				{
					*pnal_type = read_nal_type(pdata + i + start_code_size, 2);//(pdata[i + start_code_size] & m_unal_type_mask) >> 1;
				}
			}

			return pdata + i;
		}

		const char* get_nal(const char* pdata, int len, int* pnal_len, int* pnal_type = NULL, bool has_start_code = false)
		{
			int offset = 0;
			int start_code_size = 0;
			const char* pnal_begin = find_start_code(pdata + offset, len - offset, &start_code_size, pnal_type);
			if (NULL == pnal_begin)
			{
				//lberror("can't find start code in stream data\n");
				return pnal_begin;
			}
			offset += pnal_begin - pdata + 4;
			const char* pnal_end = find_start_code(pdata + offset, len - offset, NULL, NULL);
			if (NULL == pnal_end)
			{
				pnal_end = pdata + len;
			}
			if (!has_start_code)
			{
				pnal_begin += start_code_size;
			}
			if (pnal_len)
			{
				*pnal_len = pnal_end - pnal_begin;
			}
			return pnal_begin;
		}

		const char* find_nal(const char* pdata, int len, int nal_type, int* pnal_len, bool has_start_code = false)
		{
			int naltype = 0;
			int offset = 0;
			int start_code_size = 0;
			const char* pnal_begin = NULL;
			const char* pnal_end = NULL;
			while (offset < len)
			{
				pnal_begin = find_start_code(pdata + offset, len - offset, &start_code_size, &naltype);
				if (NULL == pnal_begin)
				{
					return NULL;
				}
				offset = pnal_begin + start_code_size - pdata;
				if (nal_type == naltype)
				{
					pnal_end = find_start_code(pdata + offset, len - offset, NULL, NULL);
					if (NULL == pnal_end)
					{
						pnal_end = pdata + len;
					}
					if (!has_start_code)
					{
						pnal_begin += start_code_size;

					}
					if (pnal_len)
					{
						*pnal_len = pnal_end - pnal_begin;
					}
					return pnal_begin;
				}
			}
			return 0;
		}

		string rbsp_from_nalu(const char* pdata, int len)
		{
			string rbsp_data;
			//char* rbsp = new char[len];
			//int rbsp_len;
			int i = 0, j = 0;
			while (i < len)
			{
				if (j >= 2 && pdata[i] == 0x3)
				{
					i++;
					j = 0;
					continue;
				}
				else if (0 == pdata[i])
				{
					j++;
				}
				else
				{
					j = 0;
				}


				rbsp_data.append(&pdata[i], 1);
				i++;
			}

			return rbsp_data;
		}

		const char* skip_start_code(const char* pdata = NULL, int len = 0, int* pnal_len = NULL)
		{
			int zero_num = 0;
			if (NULL == pdata)
			{
				pdata = (const char*)m_pcur_ptr;
				len = remain();
			}
			for (int i = 0; i < len; i++)
			{
				if (0 == pdata[i])
				{
					zero_num++;
				}
				else if (zero_num >= 2 && 1 == pdata[i])
				{
					if (*pnal_len)
					{
						*pnal_len = len - i - 1;
					}
					m_pcur_ptr = (uint8_t*)pdata + i + 1;
					return (const char*)m_pcur_ptr;
				}
				else
				{
					if (pnal_len && *pnal_len)
					{
						*pnal_len = len;
					}
					return pdata;
				}
			}

			return NULL;
		}

		const char* get_nalu_frame(const char* pdata, int len, int* pframe_size, bool bparser_to_end = false)
		{
			int naltype = 0;
			int offset = 0;
			int start_code_size = 0;
			int nal_size = 0;
			const char* pnal_begin = NULL;
			const char* pnal_end = NULL;
			while (offset < len)
			{
				pnal_begin = find_start_code(pdata + offset, len - offset, &start_code_size, &naltype);
				//lbtrace("pnal_begin:%p, offset:%d, len - offset:%d, naltype:%d\n", pnal_begin, offset, len - offset, naltype);
				if (NULL == pnal_begin)
				{
					return NULL;
				}
				offset = pnal_begin + start_code_size - pdata;
				if(is_frame_nalu(naltype))
				{
					if(!bparser_to_end)
					{
						nal_size = len - offset;
						break;
					}
					else
					{
						pnal_end = find_start_code(pdata + offset, len - offset, NULL, NULL);
						if(NULL == pnal_end)
						{
							nal_size = len - offset;
							break;
						}
					}
				}
			}

			if(pframe_size)
			{
				*pframe_size = nal_size;
			}
			return pnal_begin + 4;
		}

		int add_metadata(const char* pdata, int len)
		{
			vector<string>* pvlist = NULL;
			string seq;
			char start_code[4] = {0, 0, 0, 1};
			seq.append(pdata, len);
			int nal_type = read_nal_type(pdata, len);
			if (m_unal_type_vps == nal_type)
			{
				pvlist = &m_vps_list;
				m_vsh.append(start_code, sizeof(start_code));
				m_vsh.append(pdata, len);
			}
			else if (m_unal_type_sps == nal_type)
			{
				pvlist = &m_sps_list;
				m_vsh.append(start_code, sizeof(start_code));
				m_vsh.append(pdata, len);
			}
			else if (m_unal_type_pps == nal_type)
			{
				pvlist = &m_sps_list;
				m_vsh.append(start_code, sizeof(start_code));
				m_vsh.append(pdata, len);
			}
			else
			{
				lberror("Invaid metadata nal_type:%d\n", nal_type);
				return -1;
			}
			for (size_t i = 0; i < pvlist->size(); i++)
			{
				if (seq == pvlist->at(i))
				{
					lbtrace("sequence header has already exist, nal_type:%d\n", nal_type);
					return 1;
				}
			}
			pvlist->push_back(seq);
			return 0;
		}

		int get_extradata_size()
		{
			size_t i = 0;
			int extradata_size = m_uxvcc_fixed_header_size;
			extradata_size += m_vps_list.size() > 0 ? m_uxvcc_fixed_metadata_prefix_size : 0;
			extradata_size += m_sps_list.size() > 0 ? m_uxvcc_fixed_metadata_prefix_size : 0;
			extradata_size += m_pps_list.size() > 0 ? m_uxvcc_fixed_metadata_prefix_size : 0;
			for (i = 0; i < m_vps_list.size(); i++)
			{
				extradata_size += m_vps_list[i].size() + m_uxvcc_fixed_nal_prefix_size;
			}
			
			for (i = 0; i < m_sps_list.size(); i++)
			{
				extradata_size += m_sps_list[i].size() + m_uxvcc_fixed_nal_prefix_size;
			}
			
			for (i = 0; i < m_pps_list.size(); i++)
			{
				extradata_size += m_pps_list[i].size() + m_uxvcc_fixed_nal_prefix_size;
			}
			return extradata_size;
		}

		bool is_key_frame(const char* pdata, int len)
		{
			int frame_size = 0;
			const char* pnal = skip_start_code(pdata, len, &frame_size);
			//lbtrace("pnal:%p = skip_start_code(pdata:%p, len:%d, &frame_size:%d)\n", pnal, pdata, len, frame_size);
			if(NULL == pnal || frame_size <= 0)
			{
				return false;
			}
			int nal_type = read_nal_type(pnal, frame_size);
			//lbtrace("nal_type:%d = read_nal_type(pnal:%p, frame_size:%d)\n", nal_type, pnal, frame_size);
			return is_frame_nalu(nal_type, true);
		}
	};
	struct lbsp_rational
	{
		int num;
		int den;
	};
	static const lbsp_rational avc_sample_aspect_ratio[17] = {
		{ 0,  1 },
		{ 1,  1 },
		{ 12, 11 },
		{ 10, 11 },
		{ 16, 11 },
		{ 40, 33 },
		{ 24, 11 },
		{ 20, 11 },
		{ 32, 11 },
		{ 80, 33 },
		{ 18, 11 },
		{ 15, 11 },
		{ 64, 33 },
		{ 160, 99 },
		{ 4,  3 },
		{ 3,  2 },
		{ 2,  1 },
	};

	class avc_sps_ctx
	{
	public:
		uint8_t	id;
		uint8_t	profile_idc;			// 8 bit, 66 baseline,77:main,88:extend,100:high(FRExt),110 high10(FRExt),122 high4:2:2(FRExt),144 high4:4:4(FRExt)
		uint8_t constraint_set_flag;    // 8 bit
		uint8_t level_idc;				// 8 bit
		ue_size seq_parameter_set_id;	// ue
		ue_size chroma_format_idc;		// ue
		uint8_t	separate_colour_plane_flag;	// 1 bit
		ue_size bit_depth_luma_minus8; // ue
		ue_size bit_depth_chroma_minus8; // ue
		uint8_t qpprime_y_zero_transform_bypass_flag;	// 1 bit
		uint8_t seq_scaling_matrix_present_flag;		//1 bit
		uint8_t* seq_scaling_list_present_flag;			// 1 bit, 
		ue_size log2_max_frame_num_minus4;				// ue
		ue_size pic_order_cnt_type;						// ue
		ue_size log2_max_pic_order_cnt_lsb_minus4;		// ue
		ue_size delta_pic_order_always_zero_flag;		// 1bit, if 1 == pic_order_cnt_type
		se_size offset_for_non_ref_pic;					// se
		se_size offset_for_top_to_bottom_field;			// se
		ue_size num_ref_frames_in_pic_order_cnt_cycle;  // ue
		se_size* offset_for_ref_frame;					// se, list
		ue_size max_num_ref_frames;						// ue
		uint8_t gaps_in_frame_num_value_allowed_flag;	// 1 bit
		uint16_t m_nsar_width;
		uint16_t m_nsar_height;
	public:
		avc_sps_ctx()
		{
			seq_scaling_list_present_flag = NULL;
			offset_for_ref_frame = NULL;
		}
		~avc_sps_ctx()
		{
			if (seq_scaling_list_present_flag)
			{
				delete[] seq_scaling_list_present_flag;
				seq_scaling_list_present_flag = NULL;
			}

			if (offset_for_ref_frame)
			{
				delete[] offset_for_ref_frame;
				offset_for_ref_frame = NULL;
			}
		}
	};

	class lazy_avc_parser :public lazy_xvc_stream
	{
	protected:
		avc_sps_ctx*	m_psps_ctx;
	public:
		lazy_avc_parser(const void* pdata = NULL, long len = 0) :lazy_xvc_stream(4, (void*)pdata, len)
		{
			m_psps_ctx = NULL;
		}

		~lazy_avc_parser()
		{
		}

		virtual int on_parse_nalu(int nal_type, const char* pdata, int len)
		{
			int ret = 0;
			switch (nal_type)
			{
			case EAVC_NAL_SPS:
				ret = demux_sps(pdata, len);
				CHECK_RESULT(ret);
				break;
			case EAVC_NAL_PPS:
				ret = demux_pps(pdata, len);
				CHECK_RESULT(ret);
				break;
			default:
				break;
			}

			return ret;
		}

		int mux_extradata(char* pextradata, int len)
		{
			size_t i = 0;
			lazy_bitstream bs((void*)pextradata, len);
			if (m_sps_list.size() <= 0 || m_pps_list.size() <= 0)
			{
				lberror("no sps or pps avaiable, m_sps_list.size():%ld, m_pps_list.size():%ld\n", m_sps_list.size(), m_pps_list.size());
				return -1;
			}

			if (NULL == pextradata || len < get_extradata_size())
			{
				lberror("not enought buffer for sps and pps, need:%d, have len:%d\n", get_extradata_size(), len);
				return -1;
			}

			// 6( + 1) bytes fix header
			bs.write_byte(0x01, 1); // version
			bs.write_byte(m_psps_ctx->profile_idc, 1); // profile
			bs.write_byte(0x0, 1);	//	
			bs.write_byte(m_psps_ctx->level_idc, 1); //  level
			bs.write_bit(63, 6);		// reserved, all bits on
			bs.write_bit(3, 2);			//NALU Length Size minus1
			bs.write_bit(7, 3);			// seserved2, all bits on

			bs.write_bit(m_sps_list.size(), 5);			// write sps nalu blocks count(5bit), usually 1
			for (i = 0; i < m_sps_list.size(); i++)
			{
				bs.write_byte(m_sps_list[i].size(), 2);	// 32 bits sps len
				bs.write_bytes((uint8_t*)m_sps_list[i].data(), m_sps_list[i].size());	// write sps data block
			}
			bs.write_byte(m_pps_list.size(), 1);		// write pps nalu block count(8bit), usually 1
			for (i = 0; i < m_pps_list.size(); i++)
			{
				bs.write_byte(m_pps_list[i].size(), 2);	// 32 bits pps len
				bs.write_bytes((uint8_t*)m_pps_list[i].data(), m_pps_list[i].size()); // write pps data block
			}

			return bs.pos();
		}

		int demux_extradata(const char* pextradata, int len)
		{
			int i = 0, ret = 0, sps_num = 0, pps_num = 0;
			lazy_bitstream bs((void*)pextradata, len);
			if (NULL == pextradata || len <= m_uxvcc_fixed_header_size)
			{
				lberror("extradata not avaiable, pextradata:%p, len:%d <= m_uxvcc_fixed_header_size:%d\n", pextradata, len, (int)m_uxvcc_fixed_header_size);
				return -1;
			}

			uint8_t version = bs.read_bit(8);
			if (0x1 != version)
			{
				lberror("Invalid extradata, avcc version:%d\n", (int)version);
				return -1;
			}
			bs.read_byte(1); // profile
			bs.read_byte(1); // compatibility
			bs.read_byte(1); // level
			bs.read_bit(6);  // reserved
			bs.read_bit(2);  // nal_size_minus1
			bs.read_bit(3);	 // reserved
			sps_num = bs.read_bit(5);
			reset();
			for (i = 0; i < sps_num; i++)
			{
				int sps_len = (int)bs.read_byte(2);
				ret = demux_sps((char*)bs.cur_ptr(), sps_len);
				CHECK_RESULT(ret);
				bs.move(sps_len);
			}

			pps_num = (int)bs.read_byte(1);
			for (i = 0; i < pps_num; i++)
			{
				int pps_len = (int)bs.read_byte(2);
				ret = demux_pps((char*)bs.cur_ptr(), pps_len);
				CHECK_RESULT(ret);
				bs.move(pps_len);
			}
			return ret;
		}
	protected:
		int demux_sps(const char* pdata, int len)
		{
			lazy_xvc_stream bs(4, pdata, len);
			//srs_trace("demux_sps(sps:%p, sps_len:%d)\n", pdata, len);
			lbmemory(pdata, len);
			const char* sps = bs.skip_start_code();
			//srs_trace("sps:%p = bs.skip_start_code()\n", sps);
			lbmemory(pdata, len);
			int sps_len = bs.remain();
			int forbiden = bs.read_bit(1);
			int nri = bs.read_bit(2);
			int nal_type = bs.read_bit(5);
			int ret = 0;

			if (0 != forbiden || EAVC_NAL_SPS != nal_type)
			{
				lberror("Invalid sps nal heaer forbiden:%d, nri:%d, nal_type:%d\n", forbiden, nri, nal_type);
				return -1;
			}

			if (m_psps_ctx)
			{
				delete m_psps_ctx;
				m_psps_ctx = NULL;
			}
			m_psps_ctx = new avc_sps_ctx();
			m_psps_ctx->profile_idc = (uint8_t)bs.read_byte(1);
			m_psps_ctx->constraint_set_flag = (uint8_t)bs.read_byte(1);
			m_psps_ctx->level_idc = (uint8_t)bs.read_byte(1);
			m_psps_ctx->seq_parameter_set_id = (uint8_t)bs.read_ue();
			m_psps_ctx->chroma_format_idc = (uint8_t)bs.read_ue();
			if (AVC_PROFILE_HIGHT_FREXT == m_psps_ctx->profile_idc
				|| AVC_PROFILE_HIGHT10_FREXT == m_psps_ctx->profile_idc
				|| AVC_PROFILE_HIGHT_422_FREXT == m_psps_ctx->profile_idc
				|| AVC_PROFILE_HIGHT_444_FREXT == m_psps_ctx->profile_idc)
			{
				m_psps_ctx->chroma_format_idc = (uint8_t)bs.read_ue();
				if (3 == m_psps_ctx->chroma_format_idc)
				{
					m_psps_ctx->separate_colour_plane_flag = bs.read_bit(1);
				}
				m_psps_ctx->bit_depth_luma_minus8 = (uint8_t)bs.read_ue();
				m_psps_ctx->bit_depth_chroma_minus8 = (uint8_t)bs.read_ue();
				m_psps_ctx->qpprime_y_zero_transform_bypass_flag = bs.read_bit(1);
				m_psps_ctx->seq_scaling_matrix_present_flag = bs.read_bit(1);
				if (m_psps_ctx->seq_scaling_matrix_present_flag)
				{
					int len = m_psps_ctx->chroma_format_idc != 3 ? 8 : 12;
					m_psps_ctx->seq_scaling_list_present_flag = new uint8_t[len];
					for (int i = 0; i < len; i++)
					{
						m_psps_ctx->seq_scaling_list_present_flag[i] = bs.read_bit(1);
					}
				}
			}
			m_psps_ctx->log2_max_frame_num_minus4 = (uint8_t)bs.read_ue();
			m_psps_ctx->pic_order_cnt_type = (uint8_t)bs.read_ue();
			if (m_psps_ctx->pic_order_cnt_type == 0)
			{
				m_psps_ctx->log2_max_pic_order_cnt_lsb_minus4 = (uint8_t)bs.read_ue();
			}
			else if (m_psps_ctx->pic_order_cnt_type == 1)
			{
				m_psps_ctx->delta_pic_order_always_zero_flag = (uint8_t)bs.read_bit(1);
				m_psps_ctx->offset_for_non_ref_pic = (uint8_t)bs.read_se();
				m_psps_ctx->offset_for_top_to_bottom_field = (uint8_t)bs.read_se();
				m_psps_ctx->num_ref_frames_in_pic_order_cnt_cycle = (uint8_t)bs.read_ue();

				m_psps_ctx->offset_for_ref_frame = new se_size[m_psps_ctx->num_ref_frames_in_pic_order_cnt_cycle];
				for (int i = 0; i < m_psps_ctx->num_ref_frames_in_pic_order_cnt_cycle; i++)
					m_psps_ctx->offset_for_ref_frame[i] = (uint8_t)bs.read_se();
			}
			bs.read_ue(); //num_ref_frames
			m_psps_ctx->gaps_in_frame_num_value_allowed_flag = bs.read_bit(1);//U(1, buf, StartBit);
			int pic_width_in_mbs_minus1 = (uint8_t)bs.read_ue();//Ue(buf, nLen, StartBit);
			int pic_height_in_map_units_minus1 = (uint8_t)bs.read_ue();//Ue(buf, nLen, StartBit);

			int encwidth = (pic_width_in_mbs_minus1 + 1) * 16;
			int encheight = (pic_height_in_map_units_minus1 + 1) * 16;

			if (!bs.read_bit(1))
				bs.read_bit(1);//mb_adaptive_frame_field_flag

			bs.read_bit(1); //direct_8x8_inference_flag
			if (bs.read_bit(1))
			{
				int frame_crop_left_offset = bs.read_ue();//Ue(buf, nLen, StartBit);
				int frame_crop_right_offset = bs.read_ue();//Ue(buf, nLen, StartBit);
				int frame_crop_top_offset = bs.read_ue();//Ue(buf, nLen, StartBit);
				int frame_crop_bottom_offset = bs.read_ue();//Ue(buf, nLen, StartBit);

				//todo: deal with frame_mbs_only_flag
				m_nwidth = encwidth - 2 * frame_crop_left_offset
					- 2 * frame_crop_right_offset;
				m_nheight = encheight - 2 * frame_crop_top_offset
					- 2 * frame_crop_bottom_offset;
			}
			else
			{
				m_nwidth = encwidth;
				m_nheight = encheight;
			}

			if (bs.read_bit(1)) // vui_parameters_present_flag
			{
				if (bs.read_bit(1)) // aspect_ratio_info_present_flag
				{
					int aspect_ratio_idc = bs.read_byte(1);
					if (0xff == aspect_ratio_idc)
					{
						m_psps_ctx->m_nsar_width = bs.read_bit_int(16);
						m_psps_ctx->m_nsar_height = bs.read_bit_int(16);
					}
					else if (aspect_ratio_idc < (int)(sizeof(avc_sample_aspect_ratio) / sizeof(lbsp_rational)))
					{
						m_psps_ctx->m_nsar_width = avc_sample_aspect_ratio[aspect_ratio_idc].num;
						m_psps_ctx->m_nsar_height = avc_sample_aspect_ratio[aspect_ratio_idc].den;
					}
				}
			}

			if (m_psps_ctx->m_nsar_width <= 0 || m_psps_ctx->m_nsar_height <= 0)
			{
				m_psps_ctx->m_nsar_width = 1;
				m_psps_ctx->m_nsar_height = 1;
			}
			ret = add_metadata(sps, sps_len);
			return ret;
		}

		int demux_pps(const char* pdata, int len)
		{
			//srs_trace("demux_pps(pps:%p, sps_len:%d)\n", pdata, len);
			//lbmemory(pdata, len);
			lazy_xvc_stream bs(4, pdata, len);
			const char* pps = bs.skip_start_code();
			int pps_len = bs.remain();
			int ret = add_metadata(pps, pps_len);
			return ret;
		}
	};

#define MAX_SPATIAL_SEGMENTATION 4096 // max. value of u(12) field

	enum HEVCSliceType {
		HEVC_SLICE_B = 0,
		HEVC_SLICE_P = 1,
		HEVC_SLICE_I = 2,
	};

	enum {
		// 7.4.3.1: vps_max_layers_minus1 is in [0, 62].
		HEVC_MAX_LAYERS = 63,
		// 7.4.3.1: vps_max_sub_layers_minus1 is in [0, 6].
		HEVC_MAX_SUB_LAYERS = 7,
		// 7.4.3.1: vps_num_layer_sets_minus1 is in [0, 1023].
		HEVC_MAX_LAYER_SETS = 1024,

		// 7.4.2.1: vps_video_parameter_set_id is u(4).
		HEVC_MAX_VPS_COUNT = 16,
		// 7.4.3.2.1: sps_seq_parameter_set_id is in [0, 15].
		HEVC_MAX_SPS_COUNT = 16,
		// 7.4.3.3.1: pps_pic_parameter_set_id is in [0, 63].
		HEVC_MAX_PPS_COUNT = 64,

		// A.4.2: MaxDpbSize is bounded above by 16.
		HEVC_MAX_DPB_SIZE = 16,
		// 7.4.3.1: vps_max_dec_pic_buffering_minus1[i] is in [0, MaxDpbSize - 1].
		HEVC_MAX_REFS = HEVC_MAX_DPB_SIZE,

		// 7.4.3.2.1: num_short_term_ref_pic_sets is in [0, 64].
		HEVC_MAX_SHORT_TERM_REF_PIC_SETS = 64,
		// 7.4.3.2.1: num_long_term_ref_pics_sps is in [0, 32].
		HEVC_MAX_LONG_TERM_REF_PICS = 32,

		// A.3: all profiles require that CtbLog2SizeY is in [4, 6].
		HEVC_MIN_LOG2_CTB_SIZE = 4,
		HEVC_MAX_LOG2_CTB_SIZE = 6,

		// E.3.2: cpb_cnt_minus1[i] is in [0, 31].
		HEVC_MAX_CPB_CNT = 32,

		// A.4.1: in table A.6 the highest level allows a MaxLumaPs of 35 651 584.
		HEVC_MAX_LUMA_PS = 35651584,
		// A.4.1: pic_width_in_luma_samples and pic_height_in_luma_samples are
		// constrained to be not greater than sqrt(MaxLumaPs * 8).  Hence height/
		// width are bounded above by sqrt(8 * 35651584) = 16888.2 samples.
		HEVC_MAX_WIDTH = 16888,
		HEVC_MAX_HEIGHT = 16888,

		// A.4.1: table A.6 allows at most 22 tile rows for any level.
		HEVC_MAX_TILE_ROWS = 22,
		// A.4.1: table A.6 allows at most 20 tile columns for any level.
		HEVC_MAX_TILE_COLUMNS = 20,

		// A.4.2: table A.6 allows at most 600 slice segments for any level.
		HEVC_MAX_SLICE_SEGMENTS = 600,

		// 7.4.7.1: in the worst case (tiles_enabled_flag and
		// entropy_coding_sync_enabled_flag are both set), entry points can be
		// placed at the beginning of every Ctb row in every tile, giving an
		// upper bound of (num_tile_columns_minus1 + 1) * PicHeightInCtbsY - 1.
		// Only a stream with very high resolution and perverse parameters could
		// get near that, though, so set a lower limit here with the maximum
		// possible value for 4K video (at most 135 16x16 Ctb rows).
		HEVC_MAX_ENTRY_POINT_OFFSETS = HEVC_MAX_TILE_COLUMNS * 135,
	};

	typedef struct hevc_nal_header
	{
		uint8_t		forbiden;
		uint8_t		nal_type;
		uint8_t		layer_id;
		uint8_t		tid;
	} hevc_nal_hdr;
	typedef struct HVCCNALUnitArray {
		uint8_t  array_completeness;
		uint8_t  NAL_unit_type;
		uint16_t numNalus;
		uint16_t *nalUnitLength;
		uint8_t  **nalUnit;
	} HVCCNALUnitArray;

	typedef struct HEVCDecoderConfigurationRecord {
		uint8_t  configurationVersion;
		uint8_t  general_profile_space;
		uint8_t  general_tier_flag;
		uint8_t  general_profile_idc;
		uint32_t general_profile_compatibility_flags;
		uint64_t general_constraint_indicator_flags;
		uint8_t  general_level_idc;
		uint16_t min_spatial_segmentation_idc;
		uint8_t  parallelismType;
		uint8_t  chromaFormat;
		uint8_t  bitDepthLumaMinus8;
		uint8_t  bitDepthChromaMinus8;
		uint16_t avgFrameRate;
		uint8_t  constantFrameRate;
		uint8_t  numTemporalLayers;
		uint8_t  temporalIdNested;
		uint8_t  lengthSizeMinusOne;
		uint8_t  numOfArrays;
		HVCCNALUnitArray *array;
	} HEVCDecoderConfigurationRecord;

	typedef struct HVCCProfileTierLevel {
		uint8_t  profile_space;
		uint8_t  tier_flag;
		uint8_t  profile_idc;
		uint32_t profile_compatibility_flags;
		uint64_t constraint_indicator_flags;
		uint8_t  level_idc;
	} HVCCProfileTierLevel;
	using namespace std;
	/**
	Profile, tier and level
	@see 7.3.3 Profile, tier and level syntax
	*/
	typedef struct
	{
		uint8_t general_profile_space;
		uint8_t general_tier_flag;
		uint8_t general_profile_idc;
		uint8_t general_profile_compatibility_flag[32];
		uint8_t general_progressive_source_flag;
		uint8_t general_interlaced_source_flag;
		uint8_t general_non_packed_constraint_flag;
		uint8_t general_frame_only_constraint_flag;
		uint8_t general_max_12bit_constraint_flag;
		uint8_t general_max_10bit_constraint_flag;
		uint8_t general_max_8bit_constraint_flag;
		uint8_t general_max_422chroma_constraint_flag;
		uint8_t general_max_420chroma_constraint_flag;
		uint8_t general_max_monochrome_constraint_flag;
		uint8_t general_intra_constraint_flag;
		uint8_t general_one_picture_only_constraint_flag;
		uint8_t general_lower_bit_rate_constraint_flag;
		uint64_t general_reserved_zero_34bits; // todo
		uint64_t general_reserved_zero_43bits; // todo
		uint8_t general_inbld_flag;
		uint8_t general_reserved_zero_bit;
		uint8_t general_level_idc;
		vector<uint8_t> sub_layer_profile_present_flag;
		vector<uint8_t> sub_layer_level_present_flag;
		uint8_t reserved_zero_2bits[8];
		vector<uint8_t> sub_layer_profile_space;
		vector<uint8_t> sub_layer_tier_flag;
		vector<uint8_t> sub_layer_profile_idc;
		//vector<vector<uint8_t>> sub_layer_profile_compatibility_flag;
		vector<uint8_t> sub_layer_progressive_source_flag;
		vector<uint8_t> sub_layer_interlaced_source_flag;
		vector<uint8_t> sub_layer_non_packed_constraint_flag;
		vector<uint8_t> sub_layer_frame_only_constraint_flag;
		vector<uint8_t> sub_layer_max_12bit_constraint_flag;
		vector<uint8_t> sub_layer_max_10bit_constraint_flag;
		vector<uint8_t> sub_layer_max_8bit_constraint_flag;
		vector<uint8_t> sub_layer_max_422chroma_constraint_flag;
		vector<uint8_t> sub_layer_max_420chroma_constraint_flag;
		vector<uint8_t> sub_layer_max_monochrome_constraint_flag;
		vector<uint8_t> sub_layer_intra_constraint_flag;
		vector<uint8_t> sub_layer_one_picture_only_constraint_flag;
		vector<uint8_t> sub_layer_lower_bit_rate_constraint_flag;
		vector<uint64_t> sub_layer_reserved_zero_34bits;
		vector<uint64_t> sub_layer_reserved_zero_43bits;
		vector<uint8_t> sub_layer_inbld_flag;
		vector<uint8_t> sub_layer_reserved_zero_bit;
		vector<uint8_t> sub_layer_level_idc;

	} profile_tier_level_t;
	class lazy_hevc_parser :public lazy_xvc_stream
	{
	protected:
		HEVCDecoderConfigurationRecord*		m_phvcc;

		int				m_nsar_width;
		int				m_nsar_height;

		int				m_nwidth;
		int				m_nheight;

		vector<string>		m_vps_list;
		vector<string>		m_sps_list;
		vector<string>		m_pps_list;

	public:
		lazy_hevc_parser() :lazy_xvc_stream(5)
		{
			m_phvcc = new HEVCDecoderConfigurationRecord();
			reset();
			//memset(m_phvcc, 0, sizeof(HEVCDecoderConfigurationRecord));
			//m_phvcc->array = new HVCCNALUnitArray[3];
			//memset(m_phvcc->array, 0, sizeof(HVCCNALUnitArray) * 3);

			m_nsar_width = 0;
			m_nsar_height = 0;
			m_nwidth = 0;
			m_nheight = 0;
		}

		~lazy_hevc_parser()
		{
			if (m_phvcc)
			{
				delete m_phvcc;
				m_phvcc = NULL;
			}
		}

		void reset()
		{
			m_vps_list.clear();
			m_sps_list.clear();
			m_pps_list.clear();
			memset(m_phvcc, 0, sizeof(HEVCDecoderConfigurationRecord));
			m_phvcc->configurationVersion = 1;
			m_phvcc->lengthSizeMinusOne = 3;
			m_phvcc->general_profile_compatibility_flags = 0xffffffff;
			m_phvcc->general_constraint_indicator_flags = 0xffffffffffff;
			m_phvcc->min_spatial_segmentation_idc = MAX_SPATIAL_SEGMENTATION + 1;
			lazy_xvc_stream::reset();
		}

		virtual int on_parse_nalu(int nal_type, const char* pdata, int len)
		{
			int ret = 0;
			if (m_unal_type_vps == nal_type)
			{
				ret = demux_vps(pdata, len);
				CHECK_RESULT(ret);
			}
			else if (m_unal_type_sps == nal_type)
			{
				ret = demux_sps(pdata, len);
				CHECK_RESULT(ret);
			}
			else if (m_unal_type_pps == nal_type)
			{
				ret = demux_pps(pdata, len);
				CHECK_RESULT(ret);
			}
			else if (nal_type <= 22)
			{
				// hevc packet come
				return 1;
			}
			return ret;
		}

		int get_resolution(int& width, int& height)
		{
			width = m_nwidth;
			height = m_nheight;

			return 0;
		}

		int parse_sequence_header(const char* vps, int vps_len, const char* sps, int sps_len, const char* pps, int pps_len)
		{
			int ret = demux_vps((char*)vps, vps_len);
			CHECK_RESULT(ret);
			ret = demux_sps((char*)sps, sps_len);
			CHECK_RESULT(ret);
			ret = demux_pps((char*)pps, pps_len);
			CHECK_RESULT(ret);

			return ret;
		}

		int demux_vps(const char* vps, int vps_len)
		{
			unsigned int vps_max_sub_layers_minus1;
			lazy_xvc_stream bs(5);
			vps = bs.skip_start_code(vps, vps_len, &vps_len);
			string vps_str = rbsp_from_nalu(vps, vps_len);
			int ret = bs.initialize((char*)vps_str.data(), vps_str.size());
			CHECK_RESULT(ret);
			uint8_t nal_type = bs.read_nal_type();
			if (HEVC_NAL_VPS != nal_type)
			{
				lberror("Invalid hevc vps nal type %d\n", nal_type);
				lbmemory(vps, vps_len);
				return -1;
			}

			//dump_buffer("vps", (char*)vps, vps_len);
			/*
			* vps_video_parameter_set_id u(4)
			* vps_reserved_three_2bits   u(2)
			* vps_max_layers_minus1      u(6)
			*/
			bs.read_bit(4); // vps_video_parameter_set_id
			bs.read_bit(2); // vps_reserved_three_2bits
			bs.read_bit(6); // vps_max_layers_minus1
			//bs. bs.read_bit(12);

			vps_max_sub_layers_minus1 = bs.read_bit(3);//get_bits(gb, 3);

													   /*
													   * numTemporalLayers greater than 1 indicates that the stream to which this
													   * configuration record applies is temporally scalable and the contained
													   * number of temporal layers (also referred to as temporal sub-layer or
													   * sub-layer in ISO/IEC 23008-2) is equal to numTemporalLayers. Value 1
													   * indicates that the stream is not temporally scalable. Value 0 indicates
													   * that it is unknown whether the stream is temporally scalable.
													   */
			m_phvcc->numTemporalLayers = LBMAX(m_phvcc->numTemporalLayers,
				vps_max_sub_layers_minus1 + 1);

			/*
			* vps_temporal_id_nesting_flag u(1)
			* vps_reserved_0xffff_16bits   u(16)
			*/
			bs.read_bit(1); // vps_temporal_id_nesting_flag
			bs.read_bit_int(16); // vps_reserved_0xffff_16bits
			//bs.read_bit(17);

			parse_ptl(&bs, m_phvcc, vps_max_sub_layers_minus1);
			add_xps(HEVC_NAL_VPS, vps, vps_len);
			//add_xps(int nal_type, char* xps, int xps_len);
			/* nothing useful for hvcC past this point */
			return 0;
		}

		int demux_sps(const char* sps, int sps_len)
		{
			int ret = 0;
			unsigned int i = 0, sps_max_sub_layers_minus1 = 0, log2_max_pic_order_cnt_lsb_minus4 = 0, separate_colour_plane_flag = 0;
			unsigned int num_short_term_ref_pic_sets = 0, num_delta_pocs[HEVC_MAX_SHORT_TERM_REF_PIC_SETS];
			lazy_xvc_stream bs(5);
			sps = bs.skip_start_code(sps, sps_len, &sps_len);
			string sps_str = rbsp_from_nalu(sps, sps_len);
			ret = bs.initialize((char*)sps_str.data(), sps_str.size());
			CHECK_RESULT(ret);
			uint8_t nal_type = bs.read_nal_type();
			if (HEVC_NAL_SPS != nal_type)
			{
				lberror("Invalid hevc sps nal type %d\n", nal_type);
				lbmemory(sps, sps_len);
				return -1;
			}

			//dump_buffer("sps", (char*)sps, sps_len);
			bs.read_bit(4); // sps_video_parameter_set_id
			sps_max_sub_layers_minus1 = bs.read_bit(3);
			m_phvcc->numTemporalLayers = LBMAX(m_phvcc->numTemporalLayers, sps_max_sub_layers_minus1 + 1);
			m_phvcc->temporalIdNested = bs.read_bit(1);
			parse_ptl(&bs, m_phvcc, sps_max_sub_layers_minus1);
			bs.read_ue(); // sps_seq_parameter_set_id
			m_phvcc->chromaFormat = bs.read_ue(); // pitcure color space, 1 indicate 4:2:0(yuv420)
			if (3 == m_phvcc->chromaFormat)
			{
				separate_colour_plane_flag = bs.read_bit(1); // separate_colour_plane_flag, specity for solor space 4:4:4
			}
			m_nwidth = bs.read_ue(); // pic_width_in_luma_samples
			m_nheight = bs.read_ue(); // pic_height_in_luma_samples

			if (bs.read_bit(1)) // conformance_window_flag
			{
				int conf_win_left_offset = 0, conf_win_right_offset = 0, conf_win_top_offset = 0, conf_win_bottom_offset = 0;
				int sub_width_c = ((1 == m_phvcc->chromaFormat) || (2 == m_phvcc->chromaFormat)) && (0 == separate_colour_plane_flag) ? 2 : 1;
				int sub_height_c = (1 == m_phvcc->chromaFormat) && (0 == separate_colour_plane_flag) ? 2 : 1;

				conf_win_left_offset = bs.read_ue();	// conf_win_left_offset
				conf_win_right_offset = bs.read_ue();	// conf_win_right_offset
				conf_win_top_offset = bs.read_ue();	// conf_win_top_offset
				conf_win_bottom_offset = bs.read_ue();	// conf_win_bottom_offset
				m_nwidth -= (sub_width_c*conf_win_right_offset + sub_width_c*conf_win_left_offset);
				m_nheight -= (sub_height_c*conf_win_bottom_offset + sub_height_c*conf_win_top_offset);
				lbtrace("parser sps width:%d, height:%d\n", m_nwidth, m_nheight);
			}

			m_phvcc->bitDepthLumaMinus8 = bs.read_ue();			// luminance/(luma/brightness(Y)
			m_phvcc->bitDepthChromaMinus8 = bs.read_ue();		// chroma
			log2_max_pic_order_cnt_lsb_minus4 = bs.read_ue();
			// sps_sub_layer_ordering_info_present_flag
			i = bs.read_bit(1) ? 0 : sps_max_sub_layers_minus1;
			for (; i <= sps_max_sub_layers_minus1; i++)
			{
				bs.read_ue();	// max_dec_pic_buffering_minus1
				bs.read_ue();	// max_num_reorder_pics
				bs.read_ue();	// max_latency_increase_plus1
			}
			bs.read_ue();	// log2_min_luma_coding_block_size_minus3
			bs.read_ue();	// log2_diff_max_min_luma_coding_block_size
			bs.read_ue();	// log2_min_transform_block_size_minus2
			bs.read_ue();	// log2_diff_max_min_transform_block_size
			bs.read_ue();	// max_transform_hierarchy_depth_inter
			bs.read_ue();	// max_transform_hierarchy_depth_intra

			if (bs.read_bit(1) && bs.read_bit(1)) // scaling_list_enabled_flag && sample_adaptive_offset_enabled_flag
			{
				int i = 0, j = 0, k = 0, num_coeffs = 0;

				for (i = 0; i < 4; i++)
					for (j = 0; j < (i == 3 ? 2 : 6); j++)
						if (!bs.read_bit(1))         // scaling_list_pred_mode_flag[i][j]
							bs.read_ue(); // scaling_list_pred_matrix_id_delta[i][j]
						else {
							num_coeffs = LBMIN(64, 1 << (4 + (i << 1)));

							if (i > 1)
								bs.read_se(); // scaling_list_dc_coef_minus8[i-2][j]

							for (k = 0; k < num_coeffs; k++)
								bs.read_se(); // scaling_list_delta_coef
						}
			}
			bs.read_bit(1);	// amp_enabled_flag
			bs.read_bit(1);	// sample_adaptive_offset_enabled_flag

			if (bs.read_bit(1))	// pcm_enabled_flag
			{
				bs.read_bit(4);	// pcm_sample_bit_depth_luma_minus1
				bs.read_bit(4);	// pcm_sample_bit_depth_chroma_minus1
				bs.read_ue();	// log2_min_pcm_luma_coding_block_size_minus3
				bs.read_ue();	// log2_diff_max_min_pcm_luma_coding_block_size
				bs.read_bit(1); // pcm_loop_filter_disabled_flag
			}

			num_short_term_ref_pic_sets = bs.read_ue();
			if (num_short_term_ref_pic_sets > HEVC_MAX_SHORT_TERM_REF_PIC_SETS)
			{
				lberror("Invalid hevc data, num_short_term_ref_pic_sets:%d\n", num_short_term_ref_pic_sets);
				return -1;
			}

			for (i = 0; i < num_short_term_ref_pic_sets; i++)
			{
				int ret = parse_rps(&bs, i, num_short_term_ref_pic_sets, num_delta_pocs);
				if (ret < 0)
				{
					lberror("ret:%d = parser_rps(&bs, i:%u, num_short_term_ref_pic_sets:%u, num_delta_pocs:%p)\n", ret, i, num_short_term_ref_pic_sets, num_delta_pocs);
					return ret;
				}
			}

			if (bs.read_bit(1))
			{
				unsigned num_long_term_ref_pics_sps = bs.read_ue();
				if (num_long_term_ref_pics_sps > 31U)
				{
					lberror("Invalid sps data, num_long_term_ref_pics_sps:%d > 31U\n", num_long_term_ref_pics_sps);
					return -1;
				}
				for (i = 0; i < num_long_term_ref_pics_sps; i++) { // num_long_term_ref_pics_sps
					int len = LBMIN(log2_max_pic_order_cnt_lsb_minus4 + 4, 16);
					bs.read_bit_int(len);	// lt_ref_pic_poc_lsb_sps[i]
					bs.read_bit(1);      // used_by_curr_pic_lt_sps_flag[i]
				}
			}

			bs.read_bit(1);	// sps_temporal_mvp_enabled_flag
			bs.read_bit(1); // strong_intra_smoothing_enabled_flag

			if (bs.read_bit(1)) // vui_parameters_present_flag
			{
				unsigned int min_spatial_segmentation_idc;

				if (bs.read_bit(1))              // aspect_ratio_info_present_flag
					if (bs.read_bit(8) == 255)	// aspect_ratio_idc
						bs.read_bit_int(32);		// sar_width u(16), sar_height u(16)

				if (bs.read_bit(1))				// overscan_info_present_flag
					bs.read_bit(1);				// overscan_appropriate_flag

				if (bs.read_bit(1)) {			// video_signal_type_present_flag
					bs.read_bit(4);				// video_format u(3), video_full_range_flag u(1)

					if (bs.read_bit(1))			// colour_description_present_flag
												/*
												* colour_primaries         u(8)
												* transfer_characteristics u(8)
												* matrix_coeffs            u(8)
												*/
						bs.read_bit_int(24);
				}

				if (bs.read_bit(1)) {        // chroma_loc_info_present_flag
					bs.read_ue(); // chroma_sample_loc_type_top_field
					bs.read_ue(); // chroma_sample_loc_type_bottom_field
				}

				/*
				* neutral_chroma_indication_flag u(1)
				* field_seq_flag                 u(1)
				* frame_field_info_present_flag  u(1)
				*/
				bs.read_bit(1); // neutral_chroma_indication_flag
				bs.read_bit(1); // field_seq_flag
				bs.read_bit(1); // frame_field_info_present_flag
				//int default_display_window_flag = bs.read_bit(1);
				if (bs.read_bit(1)) {        // default_display_window_flag
					bs.read_ue(); // def_disp_win_left_offset
					bs.read_ue(); // def_disp_win_right_offset
					bs.read_ue(); // def_disp_win_top_offset
					bs.read_ue(); // def_disp_win_bottom_offset
				}

				if (bs.read_bit(1)) { // vui_timing_info_present_flag
									  //skip_timing_info(gb);
					bs.read_bit_int(32);
					bs.read_bit_int(32);
					if (bs.read_bit(1))
					{
						bs.read_ue();
					}

					if (bs.read_bit(1)) // vui_hrd_parameters_present_flag
						skip_hrd_parameters(&bs, 1, sps_max_sub_layers_minus1);
				}

				if (bs.read_bit(1)) { // bitstream_restriction_flag
									  /*
									  * tiles_fixed_structure_flag              u(1)
									  * motion_vectors_over_pic_boundaries_flag u(1)
									  * restricted_ref_pic_lists_flag           u(1)
									  */
					bs.read_bit(3);

					min_spatial_segmentation_idc = bs.read_ue();

					/*
					* unsigned int(12) min_spatial_segmentation_idc;
					*
					* The min_spatial_segmentation_idc indication must indicate a level of
					* spatial segmentation equal to or less than the lowest level of
					* spatial segmentation indicated in all the parameter sets.
					*/
					m_phvcc->min_spatial_segmentation_idc = LBMIN(m_phvcc->min_spatial_segmentation_idc,
						min_spatial_segmentation_idc);

					bs.read_ue(); // max_bytes_per_pic_denom
					bs.read_ue(); // max_bits_per_min_cu_denom
					bs.read_ue(); // log2_max_mv_length_horizontal
					bs.read_ue(); // log2_max_mv_length_vertical
				}
			}
			add_xps(HEVC_NAL_SPS, sps, sps_len);
			return 0;
		}

		int demux_pps(const char* pps, int pps_len)
		{
			uint8_t tiles_enabled_flag = 0, entropy_coding_sync_enabled_flag = 0;
			uint8_t nal_type = 0;
			int ret = 0;
			lazy_xvc_stream bs(5);
			pps = bs.skip_start_code(pps, pps_len, &pps_len);
			string pps_str = rbsp_from_nalu(pps, pps_len);
			ret = bs.initialize((char*)pps_str.data(), pps_str.size());
			CHECK_RESULT(ret);
			nal_type = bs.read_nal_type();
			if (HEVC_NAL_PPS != nal_type)
			{
				lberror("Invalid hevc pps nal type %d\n", nal_type);
				lbmemory(pps, pps_len);
				return -1;
			}

			//dump_buffer("pps", (char*)pps, pps_len);

			bs.read_ue(); // pps_pic_parameter_set_id
			bs.read_ue(); // pps_seq_parameter_set_id

						  /*
						  * dependent_slice_segments_enabled_flag u(1)
						  * output_flag_present_flag              u(1)
						  * num_extra_slice_header_bits           u(3)
						  * sign_data_hiding_enabled_flag         u(1)
						  * cabac_init_present_flag               u(1)
						  */
			bs.read_bit(7);

			bs.read_ue(); // num_ref_idx_l0_default_active_minus1
			bs.read_ue(); // num_ref_idx_l1_default_active_minus1
			bs.read_se(); // init_qp_minus26

						  /*
						  * constrained_intra_pred_flag u(1)
						  * transform_skip_enabled_flag u(1)
						  */
			bs.read_bit(2);

			if (bs.read_bit(1))          // cu_qp_delta_enabled_flag
				bs.read_ue(); // diff_cu_qp_delta_depth

			bs.read_se(); // pps_cb_qp_offset
			bs.read_se(); // pps_cr_qp_offset

						  /*
						  * pps_slice_chroma_qp_offsets_present_flag u(1)
						  * weighted_pred_flag               u(1)
						  * weighted_bipred_flag             u(1)
						  * transquant_bypass_enabled_flag   u(1)
						  */
			bs.read_bit(4);

			tiles_enabled_flag = bs.read_bit(1);
			entropy_coding_sync_enabled_flag = bs.read_bit(1);

			if (entropy_coding_sync_enabled_flag && tiles_enabled_flag)
				m_phvcc->parallelismType = 0; // mixed-type parallel decoding
			else if (entropy_coding_sync_enabled_flag)
				m_phvcc->parallelismType = 3; // wavefront-based parallel decoding
			else if (tiles_enabled_flag)
				m_phvcc->parallelismType = 2; // tile-based parallel decoding
			else
				m_phvcc->parallelismType = 1; // slice-based parallel decoding

											  /* nothing useful for hvcC past this point */
			add_xps(HEVC_NAL_PPS, pps, pps_len);
			return 0;
		}

		int mux_extradata(char* pdata, int len)
		{
			lazy_xvc_stream bs(5);
			bs.initialize(pdata, len);
			int need_bytes = get_mux_hvcc_size();
			if (!bs.require(need_bytes))
			{
				lberror("not enought buffer for hvcc metadata, need %d, have %d\n", need_bytes, len);
				return -1;
			}
			/*
			* We only support writing HEVCDecoderConfigurationRecord version 1.
			*/
			m_phvcc->configurationVersion = 1;

			/*
			* If min_spatial_segmentation_idc is invalid, reset to 0 (unspecified).
			*/
			if (m_phvcc->min_spatial_segmentation_idc > MAX_SPATIAL_SEGMENTATION)
				m_phvcc->min_spatial_segmentation_idc = 0;

			/*
			* parallelismType indicates the type of parallelism that is used to meet
			* the restrictions imposed by min_spatial_segmentation_idc when the value
			* of min_spatial_segmentation_idc is greater than 0.
			*/
			if (!m_phvcc->min_spatial_segmentation_idc)
				m_phvcc->parallelismType = 0;

			/*
			* It's unclear how to properly compute these fields, so
			* let's always set them to values meaning 'unspecified'.
			*/
			m_phvcc->avgFrameRate = 0;
			m_phvcc->constantFrameRate = 0;
			m_phvcc->numOfArrays = 3;
			bs.write_bit(m_phvcc->configurationVersion, 8);
			bs.write_bit(m_phvcc->general_profile_space, 2);
			bs.write_bit(m_phvcc->general_tier_flag, 1);
			bs.write_bit(m_phvcc->general_profile_idc, 5);
			bs.write_bit(m_phvcc->general_profile_compatibility_flags, 32);
			bs.write_bit(m_phvcc->general_constraint_indicator_flags, 48);

			bs.write_bit(m_phvcc->general_level_idc, 8);// 13
			bs.write_bit(0xf, 4);
			bs.write_bit(m_phvcc->min_spatial_segmentation_idc, 12);
			bs.write_bit(0x3f, 6);
			bs.write_bit(m_phvcc->parallelismType, 2);
			bs.write_bit(0x3f, 6);
			bs.write_bit(m_phvcc->chromaFormat, 2);
			bs.write_bit(0x1f, 5);
			bs.write_bit(m_phvcc->bitDepthLumaMinus8, 3);
			bs.write_bit(0x1f, 5);
			bs.write_bit(m_phvcc->bitDepthChromaMinus8, 3);
			bs.write_bit(m_phvcc->avgFrameRate, 16);

			bs.write_bit(m_phvcc->constantFrameRate, 2);
			bs.write_bit(m_phvcc->numTemporalLayers, 3);
			bs.write_bit(m_phvcc->temporalIdNested, 1);
			bs.write_bit(m_phvcc->lengthSizeMinusOne, 2);

			bs.write_bit(m_phvcc->numOfArrays, 8);//23

			int ret = write_xps(&bs);
			CHECK_RESULT(ret);

			return bs.pos();
		}

		int demux_extradata(char* phvcc, int len)
		{
			lazy_xvc_stream bs(5);
			int ret = bs.initialize(phvcc, len);
			CHECK_RESULT(ret);
			//srs_trace("phvcc:%p, len:%d\n", phvcc, len);
			m_phvcc->configurationVersion = bs.read_bit(8);
			m_phvcc->general_profile_space = bs.read_bit(2);
			m_phvcc->general_tier_flag = bs.read_bit(1);
			m_phvcc->general_profile_idc = bs.read_bit(5);
			m_phvcc->general_profile_compatibility_flags = bs.read_bit_int(32);
			m_phvcc->general_constraint_indicator_flags = bs.read_bit_int64(48);

			m_phvcc->general_level_idc = bs.read_bit(8);// 13
			bs.read_bit(4);
			m_phvcc->min_spatial_segmentation_idc = bs.read_bit_int(12);
			bs.read_bit(6);
			m_phvcc->parallelismType = bs.read_bit(2);
			bs.read_bit(6);
			m_phvcc->chromaFormat = bs.read_bit(2);
			bs.read_bit(5);
			m_phvcc->bitDepthLumaMinus8 = bs.read_bit(3);
			bs.read_bit(5);
			m_phvcc->bitDepthChromaMinus8 = bs.read_bit(3);
			m_phvcc->avgFrameRate = bs.read_bit_int(16);

			m_phvcc->constantFrameRate = bs.read_bit(2);
			m_phvcc->numTemporalLayers = bs.read_bit(3);
			m_phvcc->temporalIdNested = bs.read_bit(1);
			m_phvcc->lengthSizeMinusOne = bs.read_bit(2);

			m_phvcc->numOfArrays = bs.read_bit(8);

			//dump_hvcc();
			reset();
			ret = read_xps(&bs);
			CHECK_RESULT(ret);

			return ret;
		}

		void dump_hvcc()
		{
			if (m_phvcc)
			{
				printf("configurationVersion:%d\n", m_phvcc->configurationVersion);
				printf("general_profile_space:%d\n", m_phvcc->general_profile_space);
				printf("general_tier_flag:%d\n", m_phvcc->general_tier_flag);
				printf("general_profile_idc:%d\n", m_phvcc->general_profile_idc);
				printf("general_profile_compatibility_flags:%d\n", m_phvcc->general_profile_compatibility_flags);
				printf("general_constraint_indicator_flags:% " PRId64 " \n", m_phvcc->general_constraint_indicator_flags);
				printf("general_level_idc:%d\n", m_phvcc->general_level_idc);
				printf("min_spatial_segmentation_idc:%d\n", m_phvcc->min_spatial_segmentation_idc);
				printf("parallelismType:%d\n", m_phvcc->parallelismType);
				printf("chromaFormat:%d\n", m_phvcc->chromaFormat);
				printf("bitDepthLumaMinus8:%d\n", m_phvcc->bitDepthLumaMinus8);
				printf("bitDepthChromaMinus8:%d\n", m_phvcc->bitDepthChromaMinus8);
				printf("avgFrameRate:%d\n", m_phvcc->avgFrameRate);
				printf("constantFrameRate:%d\n", m_phvcc->constantFrameRate);
				printf("numTemporalLayers:%d\n", m_phvcc->numTemporalLayers);
				printf("temporalIdNested:%d\n", m_phvcc->temporalIdNested);
				printf("lengthSizeMinusOne:%d\n", m_phvcc->lengthSizeMinusOne);
				printf("numOfArrays:%d\n", m_phvcc->numOfArrays);
			}
		}
	protected:
		void dump_buffer(char* pname, char* pbuf, int len)
		{
			printf("%s, len:%d\n", pname, len);
			for (int i = 0; i < len; i++)
			{
				printf("%02x", pbuf[i] & 0xff);
			}
			printf("\n");
		}

		int write_xps(lazy_bitstream* pbs)
		{
			if (!pbs || !pbs->require(get_mux_hvcc_size()))
			{
				lberror("write xps failed, no enought memory buffer, require %d, have %ld\n", get_mux_hvcc_size(), remain());
				return -1;
			}

			size_t i = 0;
			pbs->write_bit(0, 1);
			pbs->write_bit(0, 1);
			pbs->write_bit(HEVC_NAL_VPS, 6);
			pbs->write_bit(m_vps_list.size(), 16);
			for (i = 0; i < m_vps_list.size(); i++)
			{
				pbs->write_bit(m_vps_list[i].size(), 16);
				pbs->write_bytes((uint8_t*)m_vps_list[i].data(), m_vps_list[i].size());
			}

			pbs->write_bit(0, 1);
			pbs->write_bit(0, 1);
			pbs->write_bit(HEVC_NAL_SPS, 6);
			pbs->write_bit(m_sps_list.size(), 16);
			for (i = 0; i < m_sps_list.size(); i++)
			{
				pbs->write_bit(m_sps_list[i].size(), 16);
				pbs->write_bytes((uint8_t*)m_sps_list[i].data(), m_sps_list[i].size());
			}

			pbs->write_bit(0, 1);
			pbs->write_bit(0, 1);
			pbs->write_bit(HEVC_NAL_PPS, 6);
			pbs->write_bit(m_pps_list.size(), 16);
			for (i = 0; i < m_pps_list.size(); i++)
			{
				pbs->write_bit(m_pps_list[i].size(), 16);
				pbs->write_bytes((uint8_t*)m_pps_list[i].data(), m_pps_list[i].size());
			}
			return 0;
		}

		int read_xps(lazy_bitstream* pbs)
		{
			int ret = 0;
			vector<string>* pxps_list = NULL;
			if (!pbs || !pbs->require(5))
			{
				return -1;
			}
			int num_of_array = 3;// m_phvcc->numOfArrays;
			while (num_of_array > 0)
			{
				pbs->read_bit(1); //array_completeness
				pbs->read_bit(1); //reserved
				uint8_t nal_type = pbs->read_bit(6); // nal_type
				int numNalus = pbs->read_bit_int(16);
				if (HEVC_NAL_VPS == nal_type)
				{
					pxps_list = &m_vps_list;
				}
				else if (HEVC_NAL_SPS == nal_type)
				{
					pxps_list = &m_sps_list;
				}
				else if (HEVC_NAL_PPS == nal_type)
				{
					pxps_list = &m_pps_list;
				}
				else
				{
					lberror("Invalid hevc nal type %d\n", nal_type);
					return -1;
				}
				pxps_list->clear();
				//srs_trace("nal_type:%d, numNalus:%d\n", (int)nal_type, (int)numNalus);
				for (int i = 0; i < numNalus; i++)
				{
					string nal_str;
					int nal_size = pbs->read_bit_int(16);
					char nal_buf[256] = { 0 };
					ret = pbs->read_bytes((uint8_t*)nal_buf, nal_size);
					CHECK_RESULT(ret);

					nal_str.append((const char*)nal_buf, nal_size);
					//pxps_list->push_back(nal_str);
					if (HEVC_NAL_VPS == nal_type)
					{
						ret = demux_vps(nal_buf, nal_size);
						CHECK_RESULT(ret);
					}
					else if (HEVC_NAL_SPS == nal_type)
					{
						ret = demux_sps(nal_buf, nal_size);
						CHECK_RESULT(ret);
					}
					else if (HEVC_NAL_PPS == nal_type)
					{
						ret = demux_pps(nal_buf, nal_size);
						CHECK_RESULT(ret);
					}

				}

				num_of_array--;
			}

			return ret;
		}
		int parse_rps(lazy_bitstream* pbs, unsigned int rps_idx, unsigned int num_rps, unsigned int num_delta_pocs[HEVC_MAX_SHORT_TERM_REF_PIC_SETS])
		{
			unsigned int i = 0;
			if (rps_idx && pbs->read_bit(1)) // inter_ref_pic_set_prediction_flag
			{
				if (rps_idx >= num_rps)
				{
					lberror("Invalid hevc data, rps_idx:%u >= num_rps:%u\n", rps_idx, num_rps);
					return -1;
				}
				pbs->read_bit(1);	//	delta_rps_sign
				pbs->read_ue();		//	abs_delta_rps_minus1

				num_delta_pocs[rps_idx] = 0;

				for (i = 0; i <= num_delta_pocs[rps_idx - 1]; i++)
				{
					uint8_t use_delta_flag = 0;
					uint8_t used_by_curr_pic_flag = pbs->read_bit(1);
					if (!used_by_curr_pic_flag)
						use_delta_flag = pbs->read_bit(1);

					if (used_by_curr_pic_flag || use_delta_flag)
						num_delta_pocs[rps_idx]++;
				}
			}
			else
			{
				unsigned int num_negative_pics = pbs->read_ue();
				unsigned int num_positive_pics = pbs->read_ue();

				if (!pbs->require_bit((num_positive_pics + (uint64_t)num_negative_pics) * 2))
				{
					lberror("Invalid hevc data, require bits %" PRId64 " not enught\n", (num_positive_pics + (int64_t)num_negative_pics) * 2);
					return -1;
				}

				num_delta_pocs[rps_idx] = num_negative_pics + num_positive_pics;

				for (i = 0; i < num_negative_pics; i++) {
					pbs->read_ue(); // delta_poc_s0_minus1[rps_idx]
					pbs->read_bit(1); // used_by_curr_pic_s0_flag[rps_idx]
				}

				for (i = 0; i < num_positive_pics; i++) {
					pbs->read_ue(); // delta_poc_s1_minus1[rps_idx]
					pbs->read_bit(1); // used_by_curr_pic_s1_flag[rps_idx]
				}
			}
			return 0;
		}

		void hvcc_parse_vui(lazy_bitstream* pbs,
			HEVCDecoderConfigurationRecord *hvcc,
			unsigned int max_sub_layers_minus1)
		{
			unsigned int min_spatial_segmentation_idc;

			if (pbs->read_bit(1))              // aspect_ratio_info_present_flag
				if (pbs->read_bit(8) == 255) // aspect_ratio_idc
					m_nsar_width = pbs->read_byte(2);	// sar_width u(16)
			m_nsar_height = pbs->read_byte(2);	// sar_height u(16)

			if (pbs->read_bit(1))  // overscan_info_present_flag
				pbs->read_bit(1); // overscan_appropriate_flag

			if (pbs->read_bit(1)) {  // video_signal_type_present_flag
				pbs->read_bit(4); // video_format u(3), video_full_range_flag u(1)

				if (pbs->read_bit(1)) // colour_description_present_flag
									  /*
									  * colour_primaries         u(8)
									  * transfer_characteristics u(8)
									  * matrix_coeffs            u(8)
									  */
					pbs->read_byte(3);
			}

			if (pbs->read_bit(1)) {        // chroma_loc_info_present_flag
				pbs->read_ue(); // chroma_sample_loc_type_top_field
				pbs->read_ue(); // chroma_sample_loc_type_bottom_field
			}

			/*
			* neutral_chroma_indication_flag u(1)
			* field_seq_flag                 u(1)
			* frame_field_info_present_flag  u(1)
			*/
			pbs->read_bit(3);

			if (pbs->read_bit(1)) {        // default_display_window_flag
				pbs->read_ue(); // def_disp_win_left_offset
				pbs->read_ue(); // def_disp_win_right_offset
				pbs->read_ue(); // def_disp_win_top_offset
				pbs->read_ue(); // def_disp_win_bottom_offset
			}

			if (pbs->read_bit(1)) { // vui_timing_info_present_flag
									//skip_timing_info(gb);
				pbs->read_byte(4);	// num_units_in_tick
				pbs->read_byte(4);	// time_scale
				if (pbs->read_bit(1))          // poc_proportional_to_timing_flag
					pbs->read_ue(); // num_ticks_poc_diff_one_minus1

				if (pbs->read_bit(1)) // vui_hrd_parameters_present_flag
					skip_hrd_parameters(pbs, 1, max_sub_layers_minus1);
			}

			if (pbs->read_bit(1)) { // bitstream_restriction_flag
									/*
									* tiles_fixed_structure_flag              u(1)
									* motion_vectors_over_pic_boundaries_flag u(1)
									* restricted_ref_pic_lists_flag           u(1)
									*/
				pbs->read_bit(3);

				min_spatial_segmentation_idc = pbs->read_ue();

				/*
				* unsigned int(12) min_spatial_segmentation_idc;
				*
				* The min_spatial_segmentation_idc indication must indicate a level of
				* spatial segmentation equal to or less than the lowest level of
				* spatial segmentation indicated in all the parameter sets.
				*/
				hvcc->min_spatial_segmentation_idc = LBMIN(hvcc->min_spatial_segmentation_idc,
					min_spatial_segmentation_idc);

				pbs->read_ue(); // max_bytes_per_pic_denom
				pbs->read_ue(); // max_bits_per_min_cu_denom
				pbs->read_ue(); // log2_max_mv_length_horizontal
				pbs->read_ue(); // log2_max_mv_length_vertical
			}
		}

		void parse_ptl(lazy_bitstream* pbs, HEVCDecoderConfigurationRecord *hvcc, unsigned int max_sub_layers_minus1)
		{
			unsigned int i;
			HVCCProfileTierLevel general_ptl;
			uint8_t sub_layer_profile_present_flag[HEVC_MAX_SUB_LAYERS];
			uint8_t sub_layer_level_present_flag[HEVC_MAX_SUB_LAYERS];

			general_ptl.profile_space = (uint8_t)pbs->read_bit(2);
			general_ptl.tier_flag = (uint8_t)pbs->read_bit(1);
			general_ptl.profile_idc = (uint8_t)pbs->read_bit(5);
			general_ptl.profile_compatibility_flags = pbs->read_bit_int(32);
			general_ptl.constraint_indicator_flags = pbs->read_bit_int64(48);
			general_ptl.level_idc = (uint8_t)pbs->read_bit(8);
			//hvcc_update_ptl(hvcc, &general_ptl);
			hvcc->general_profile_space = general_ptl.profile_space;
			if (hvcc->general_tier_flag < general_ptl.tier_flag)
			{
				hvcc->general_level_idc = general_ptl.level_idc;
			}
			else
			{
				hvcc->general_level_idc = LBMAX(hvcc->general_level_idc, general_ptl.level_idc);
			}
			hvcc->general_tier_flag = LBMAX(hvcc->general_tier_flag, general_ptl.tier_flag);
			hvcc->general_profile_idc = LBMAX(hvcc->general_profile_idc, general_ptl.profile_idc);

			/*
			* Each bit in general_profile_compatibility_flags may only be set if all
			* the parameter sets set that bit.
			*/
			hvcc->general_profile_compatibility_flags &= general_ptl.profile_compatibility_flags;

			/*
			* Each bit in general_constraint_indicator_flags may only be set if all
			* the parameter sets set that bit.
			*/
			hvcc->general_constraint_indicator_flags &= general_ptl.constraint_indicator_flags;

			for (i = 0; i < max_sub_layers_minus1; i++) {
				sub_layer_profile_present_flag[i] = (uint8_t)pbs->read_bit(1);
				sub_layer_level_present_flag[i] = (uint8_t)pbs->read_bit(1);
			}

			if (max_sub_layers_minus1 > 0)
				for (i = max_sub_layers_minus1; i < 8; i++)
					pbs->read_bit(2); // reserved_zero_2bits[i]

			for (i = 0; i < max_sub_layers_minus1; i++) {
				if (sub_layer_profile_present_flag[i]) {
					/*
					* sub_layer_profile_space[i]                     u(2)
					* sub_layer_tier_flag[i]                         u(1)
					* sub_layer_profile_idc[i]                       u(5)
					* sub_layer_profile_compatibility_flag[i][0..31] u(32)
					* sub_layer_progressive_source_flag[i]           u(1)
					* sub_layer_interlaced_source_flag[i]            u(1)
					* sub_layer_non_packed_constraint_flag[i]        u(1)
					* sub_layer_frame_only_constraint_flag[i]        u(1)
					* sub_layer_reserved_zero_44bits[i]              u(44)
					*/
					pbs->read_bit_int(32);
					pbs->read_bit_int(32);
					pbs->read_bit_int(24);
				}

				if (sub_layer_level_present_flag[i])
					pbs->read_bit(8);
			}
		}

		int skip_hrd_parameters(lazy_bitstream* pbs, uint8_t cprms_present_flag, unsigned int max_sub_layers_minus1)
		{
			unsigned int i = 0;
			uint8_t sub_pic_hrd_params_present_flag = 0;
			uint8_t nal_hrd_parameters_present_flag = 0;
			uint8_t vcl_hrd_parameters_present_flag = 0;

			if (cprms_present_flag) {
				nal_hrd_parameters_present_flag = (uint8_t)pbs->read_bit(1);
				vcl_hrd_parameters_present_flag = (uint8_t)pbs->read_bit(1);

				if (nal_hrd_parameters_present_flag || vcl_hrd_parameters_present_flag) {
					sub_pic_hrd_params_present_flag = (uint8_t)pbs->read_bit(1);

					if (sub_pic_hrd_params_present_flag)
						/*
						* tick_divisor_minus2                          u(8)
						* du_cpb_removal_delay_increment_length_minus1 u(5)
						* sub_pic_cpb_params_in_pic_timing_sei_flag    u(1)
						* dpb_output_delay_du_length_minus1            u(5)
						*/
						pbs->read_bit(19);

					/*
					* bit_rate_scale u(4)
					* cpb_size_scale u(4)
					*/
					pbs->read_bit(8);

					if (sub_pic_hrd_params_present_flag)
						pbs->read_bit(4); // cpb_size_du_scale

										  /*
										  * initial_cpb_removal_delay_length_minus1 u(5)
										  * au_cpb_removal_delay_length_minus1      u(5)
										  * dpb_output_delay_length_minus1          u(5)
										  */
					pbs->read_bit_int(15);
				}
			}

			for (i = 0; i <= max_sub_layers_minus1; i++) {
				unsigned int cpb_cnt_minus1 = 0;
				uint8_t low_delay_hrd_flag = 0;
				uint8_t fixed_pic_rate_within_cvs_flag = 0;
				uint8_t fixed_pic_rate_general_flag = (uint8_t)pbs->read_bit(1);

				if (!fixed_pic_rate_general_flag)
					fixed_pic_rate_within_cvs_flag = (uint8_t)pbs->read_bit(1);

				if (fixed_pic_rate_within_cvs_flag)
					pbs->read_ue(); // elemental_duration_in_tc_minus1
				else
					low_delay_hrd_flag = (uint8_t)pbs->read_bit(1);

				if (!low_delay_hrd_flag) {
					cpb_cnt_minus1 = (uint32_t)pbs->read_ue();
					if (cpb_cnt_minus1 > 31)
					{
						lberror("Invalid hevc data, parser hrd parameter failed, cpb_cnt_minus1:%d\n", cpb_cnt_minus1);
						return -1;
					}
				}

				if (nal_hrd_parameters_present_flag)
					skip_sub_layer_hrd_parameters(pbs, cpb_cnt_minus1, sub_pic_hrd_params_present_flag);

				if (vcl_hrd_parameters_present_flag)
					skip_sub_layer_hrd_parameters(pbs, cpb_cnt_minus1, sub_pic_hrd_params_present_flag);
			}

			return 0;
		}

		void skip_sub_layer_hrd_parameters(lazy_bitstream* pbs, unsigned int cpb_cnt_minus1, uint8_t sub_pic_hrd_params_present_flag)
		{
			unsigned int i;

			for (i = 0; i <= cpb_cnt_minus1; i++) {
				pbs->read_ue(); // bit_rate_value_minus1
				pbs->read_ue(); // cpb_size_value_minus1

				if (sub_pic_hrd_params_present_flag) {
					pbs->read_ue(); // cpb_size_du_value_minus1
					pbs->read_ue(); // bit_rate_du_value_minus1
				}

				pbs->read_bit(1); // cbr_flag
			}
		}

		int get_mux_hvcc_size()
		{
			int size = 23 + 3 * 3;
			size_t i = 0;
			for (i = 0; i < m_vps_list.size(); i++)
			{
				size += m_vps_list[i].size() + 2;
			}

			for (i = 0; i < m_sps_list.size(); i++)
			{
				size += m_sps_list[i].size() + 2;
			}

			for (i = 0; i < m_pps_list.size(); i++)
			{
				size += m_pps_list[i].size() + 2;
			}

			return size;
		}

		int add_xps(int nal_type, const char* xps, int xps_len)
		{
			CHECK_POINTER(xps, -1);
			vector<string>* pxps_list = NULL;
			if (m_unal_type_vps == nal_type)
			{
				pxps_list = &m_vps_list;
			}
			else if (m_unal_type_sps == nal_type)
			{
				pxps_list = &m_sps_list;
			}
			else if (m_unal_type_pps == nal_type)
			{
				pxps_list = &m_pps_list;
			}
			else
			{
				lberror("Invalid hevc nal type %d, add xps failed\n", nal_type);
				return -1;
			}

			for (size_t i = 0; i < pxps_list->size(); i++)
			{
				if (xps_len == (int)pxps_list->at(i).size() && 0 == memcmp(xps, pxps_list->at(i).data(), xps_len))
				{
					lberror("xps has already exist, return 0\n");
					return 0;
				}
			}

			string xps_str;
			xps_str.append(xps, xps_len);
			pxps_list->push_back(xps_str);
			return 0;
		}

	};

/**************************************************************************************************************************
1.Audio Specific Config
The Audio Specific Config is the global header for MPEG-4 Audio:

5 bits: object type
if (object type == 31)
    6 bits + 32: object type
4 bits: frequency index
if (frequency index == 15)
    24 bits: frequency
4 bits: channel configuration
var bits: AOT Specific Config
Audio Object Types
MPEG-4 Audio Object Types:

0: Null
1: AAC Main
2: AAC LC (Low Complexity)
3: AAC SSR (Scalable Sample Rate)
4: AAC LTP (Long Term Prediction)
5: SBR (Spectral Band Replication)
6: AAC Scalable
7: TwinVQ
8: CELP (Code Excited Linear Prediction)
9: HXVC (Harmonic Vector eXcitation Coding)
10: Reserved
11: Reserved
12: TTSI (Text-To-Speech Interface)
13: Main Synthesis
14: Wavetable Synthesis
15: General MIDI
16: Algorithmic Synthesis and Audio Effects
17: ER (Error Resilient) AAC LC
18: Reserved
19: ER AAC LTP
20: ER AAC Scalable
21: ER TwinVQ
22: ER BSAC (Bit-Sliced Arithmetic Coding)
23: ER AAC LD (Low Delay)
24: ER CELP
25: ER HVXC
26: ER HILN (Harmonic and Individual Lines plus Noise)
27: ER Parametric
28: SSC (SinuSoidal Coding)
29: PS (Parametric Stereo)
30: MPEG Surround
31: (Escape value)
32: Layer-1
33: Layer-2
34: Layer-3
35: DST (Direct Stream Transfer)
36: ALS (Audio Lossless)
37: SLS (Scalable LosslesS)
38: SLS non-core
39: ER AAC ELD (Enhanced Low Delay)
40: SMR (Symbolic Music Representation) Simple
41: SMR Main
42: USAC (Unified Speech and Audio Coding) (no SBR)
43: SAOC (Spatial Audio Object Coding)
44: LD MPEG Surround
45: USAC
Sampling Frequencies
There are 13 supported frequencies:

0: 96000 Hz
1: 88200 Hz
2: 64000 Hz
3: 48000 Hz
4: 44100 Hz
5: 32000 Hz
6: 24000 Hz
7: 22050 Hz
8: 16000 Hz
9: 12000 Hz
10: 11025 Hz
11: 8000 Hz
12: 7350 Hz
13: Reserved
14: Reserved
15: frequency is written explictly
Channel Configurations
These are the channel configurations:

0: Defined in AOT Specifc Config
1: 1 channel: front-center
2: 2 channels: front-left, front-right
3: 3 channels: front-center, front-left, front-right
4: 4 channels: front-center, front-left, front-right, back-center
5: 5 channels: front-center, front-left, front-right, back-left, back-right
6: 6 channels: front-center, front-left, front-right, back-left, back-right, LFE-channel
7: 8 channels: front-center, front-left, front-right, side-left, side-right, back-left, back-right, LFE-channel
8-15: Reserved

2.ADTS HEADER
adts fixed header
12 bit: syncword
1  bit: ID
2  bit: layer
1  bit: protection_absent
2  bit: profile
4  bit: sampling_frequency_index
1  bit: private_bit
3  bit: channel_configuration
1  bit: original_copy
1  bit: home

syncword: 					must be 0xfff
ID:							MPEG flag, 0 indicate MPEG-4, 1 indicate MPEG-2
layer:						always 00
protection_absent:			error codec check, 0: indicate there are crc check, 1 indicate no crc check
profile:					aac profile
sampling_frequency_index	audio samplerate index
private_bit					always be 0, ingore by decoder
channel_configuration		audio channel number
original_copy				always 0, ingore by decoder
home						always be 0, ingore decoder

adts variable header
1  bit: copyright_identification_bit
1  bit: copyright_identification_start
13 bit: aac_frame_length
11 bit: adts_buffer_fullness
2  bit: number_of_raw_data_blocks_in_frame

copyright_identification_bit		always be 0, ingore by decoder
copyright_identification_start		always be 0, ingore by decoder
aac_frame_length					include adts header and aac frame data bytes
adts_buffer_fullness 				0x7ff indicate aac bitstream is variable bitrate
number_of_raw_data_blocks_in_frame  indicate this packet has number_of_raw_data_blocks_in_frame + 1 raw frame, unually is 0

MPEG-2 AAC profile
0		Main profile
1		LowComplexity profile(LC)
2		Scalable Sampling Rate profile(SSR)
3		Reserved

MPEG-4 AAC Profile = Audo Object Type - 1(see audio object type define below)

***********************************************************************************************************************************************/
enum e_aac_object_type
{
	e_aac_object_type_reserved = 0,
	e_aac_object_type_main		= 1,
	e_aac_object_type_lc		= 2,
	e_aac_object_type_ssr		= 3,
    e_aac_object_type_ltp       = 4,
	e_aac_object_type_sbr		= 5,
    e_aac_object_type_scalable  = 6,
    e_aac_object_type_twinvq    = 7,
    e_aac_object_type_celp      = 8,
    e_aac_object_type_hvxc      = 9,
    e_aac_object_type_reserved1 = 10,
    e_aac_object_type_reserved2 = 11,
    e_aac_object_type_ttsi      = 12,
    e_aac_object_type_main_synthetic = 13,
    e_aac_object_type_wavetable_synthesis = 14,
    e_aac_object_type_general_midi = 15,
    e_aac_object_type_algorithmic_synthesis = 16,
	// AAC HEv2 = LC+SBR+PS
	e_aac_object_type_hev2		= 29
};
//0:AAC Main, 1: AAC LC(low complexity), 2:AAC SSR(Scalable Sample Rate), 3: AAC LTP(Long Term Prediction)
enum e_aac_profile
{
	e_aac_profile_main		= 0,
	e_aac_profile_lc		= 1,
	e_aac_profile_ssr		= 2,
	e_aac_profile_ltp		= 3
};

typedef struct adts_context
{
    uint16_t syncword;
    uint8_t id;
    uint8_t layer;
    uint8_t protection_absent;
    uint8_t profile;
    uint8_t sampleing_frequency_index;
    uint8_t private_bit;
    uint8_t channel_configuration;
    uint8_t original_copy;
    uint8_t home;
    uint32_t samplerate;

    // adts variable header
    uint8_t copyright_identification_bit;
    uint8_t copyright_identification_start;
    uint16_t aac_frame_length;
    uint16_t adts_buffer_fullness;
    uint16_t number_of_raw_data_blocks_in_frame;

    uint16_t crc;
    uint16_t adts_header_size;
} adts_ctx;

#define MIN_AUDIO_SPECIFIC_CONFIG_SIZE 2
#define MIN_ADTS_HEADER_SIZE	4
#define MAX_ADTS_HEADER_SIZE	7
class aac_parser
{
protected:
	adts_ctx*	m_padts_ctx;
	uint8_t*	m_paac_cfg;
	int			m_naac_cfg_len;
	
	e_aac_object_type	m_eobj_type;
	int					m_nsam_fre_idx;
	int					m_nchannel;
	int					m_nAOT;

public:
	aac_parser()
	{
		m_padts_ctx	= NULL;
		m_eobj_type 	= e_aac_object_type_reserved;
		m_nsam_fre_idx 	= -1;
		m_nchannel 		= 0;
		m_nAOT 			= 0;

	}
	~aac_parser()
	{
		if(m_padts_ctx)
		{
			delete[] m_padts_ctx;
			m_padts_ctx = NULL;
		}
	}
	
	int sample_rate()
	{
        static int sample_frequence_list[] = 
        {
            96000,
			88200,
			64000,
			48000,
			44100,
			32000,
			24000,
			22050,
			16000,
			12000,
			11025,
			8000,
			7350,
			0,
			0,
			0
        };
		if(m_nsam_fre_idx > 0 && m_nsam_fre_idx < 16)
		{
			return sample_frequence_list[m_nsam_fre_idx];
		}

		return 0;
	}
	
	int channel()
	{
		return m_nchannel;
	}
	
	int object_type()
	{
		return m_eobj_type;
	}

	int parser_audio_specific_config(uint8_t* paac_cfg, int aac_cfg_len)
	{
		if(NULL == paac_cfg || aac_cfg_len < MIN_AUDIO_SPECIFIC_CONFIG_SIZE)
		{
			lberror("Invalid parameter paac_cfg:%p, aac_cfg_len:%d\n", paac_cfg, aac_cfg_len);
			return -1;
		}
		lazy_bitstream bs(paac_cfg, aac_cfg_len);
		m_eobj_type =  (e_aac_object_type)bs.read_bit(5);
		m_nsam_fre_idx = bs.read_bit(4);
		m_nchannel = bs.read_bit(4);
		m_nAOT	 = bs.read_bit(3);
		
		return 0;
	}
	
	int parser_adts_header(uint8_t* padts, int len)
	{
		if(NULL == padts || len < MIN_ADTS_HEADER_SIZE)
		{
			lberror("Invalid parameter padts:%p, len:%d\n", padts, len);
			return -1;
		}
		lazy_bitstream bs(padts, len);
		
		if(NULL == m_padts_ctx)
		{
			m_padts_ctx = new adts_ctx();
		}
		memset(m_padts_ctx, 0, sizeof(adts_ctx));
		// read fixed header
		m_padts_ctx->syncword = (uint16_t)bs.read_bit_int(12);
		m_padts_ctx->id = bs.read_bit(1);
		m_padts_ctx->layer = bs.read_bit(2);
		m_padts_ctx->protection_absent = bs.read_bit(1);
		m_padts_ctx->profile = bs.read_bit(2);
		m_padts_ctx->sampleing_frequency_index = bs.read_bit(4);
		m_padts_ctx->private_bit = bs.read_bit(1);
		m_padts_ctx->channel_configuration = bs.read_bit(3);
		m_padts_ctx->original_copy = bs.read_bit(1);
		m_padts_ctx->home = bs.read_bit(1);
		//lbtrace("channel:%d, samidx:%d, profile:%d, m_padts_ctx->syncword:%0x\n", m_padts_ctx->channel_configuration, m_padts_ctx->sampleing_frequency_index, m_padts_ctx->profile, m_padts_ctx->syncword);
		if(0xfff != m_padts_ctx->syncword)
		{
			lberror("Invalid padts header data::%p, syncword:%d\n", padts, m_padts_ctx->syncword);
			lbmemory(padts, len);
			return -1;
		}
		
		// read variable header
		m_padts_ctx->copyright_identification_bit = bs.read_bit(1);
		m_padts_ctx->copyright_identification_start = bs.read_bit(1);
		m_padts_ctx->aac_frame_length = bs.read_bit(13);
		m_padts_ctx->adts_buffer_fullness = bs.read_bit(11);
		m_padts_ctx->number_of_raw_data_blocks_in_frame = bs.read_bit(2);
		
		int profile_offset = 0;
		if(0 == m_padts_ctx->id)
		{
			//mpeg-4
			profile_offset = 1;
		}
		
		m_eobj_type = (e_aac_object_type)(m_padts_ctx->profile + profile_offset);
		m_nsam_fre_idx = m_padts_ctx->sampleing_frequency_index;
		m_nchannel = m_padts_ctx->channel_configuration;
		//lbtrace("m_eobj_type:%d, m_nsam_fre_idx:%d, m_nchannel:%d", m_eobj_type, m_nsam_fre_idx, m_nchannel);
		return 0;
	}
	
	int mux_audio_specific_config(uint8_t* pcfg_buf, int len)
	{
		lazy_bitstream bs(pcfg_buf, len);
		if(!bs.require(MIN_AUDIO_SPECIFIC_CONFIG_SIZE))
		{
			lberror("not enought buffer len %d for muxer audio specific config\n", len);
			return -1;
		}
		bs.write_bit(m_eobj_type, 5);
		bs.write_bit(m_nsam_fre_idx, 4);
		bs.write_bit(m_nchannel, 4);
		bs.write_bit(m_nAOT, 3);
		//lbtrace("m_eobj_type:%d, m_nsam_fre_idx:%d, m_nchannel:%d, m_nAOT:%d\n", m_eobj_type, m_nsam_fre_idx, m_nchannel, m_nAOT);
		return bs.pos();
	}
	
	int mux_adts_frame(uint8_t* padts_buf, int len, int aac_data_len)
	{
		lazy_bitstream bs(padts_buf, len);
		if(!bs.require(MAX_ADTS_HEADER_SIZE))
		{
			lberror("not enought buffer len %d for muxer adts header\n", len);
			return -1;
		}
		// fixed adts header
		bs.write_bit(0xfff, 12); 			// syncword 0xfff
		bs.write_bit(0, 1);					// id mpeg-4
		bs.write_bit(0, 2);					// layer 00
		bs.write_bit(1, 1);					// protection_absent 1 no crc
		bs.write_bit(m_eobj_type-1, 2); 	// profile
		bs.write_bit(m_nsam_fre_idx, 4); 	// sampleing_frequency_index
		bs.write_bit(0, 1); 				// private_bit 0
		bs.write_bit(m_nchannel, 3); 		// channel_configuration channel
		bs.write_bit(0, 1); 				// original_copy 0
		bs.write_bit(0, 1); 				// home 0
		
		// variable adts header
		bs.write_bit(0, 1); 				// copyright_identification_bit 0
		bs.write_bit(0, 1); 				// copyright_identification_start 0
		bs.write_bit(aac_data_len + 7, 13); 	// aac_frame_length
		bs.write_bit(0x7ff, 11); 			// adts_buffer_fullness
		bs.write_bit(0, 2); 				// number_of_raw_data_blocks_in_frame
		//lbtrace("m_eobj_type:%d, m_nsam_fre_idx:%d, m_nchannel:%d, m_nAOT:%d, aac_data_len:%d\n", m_eobj_type, m_nsam_fre_idx, m_nchannel, m_nAOT, aac_data_len);
		return bs.pos();
	}
};
};
