#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <math.h>
#include <string>
#include <srs_kernel_log.hpp>
#ifndef lbtrace
#define lbtrace srs_trace
#endif
#ifndef lbmemory
#define lbmemory(ptr, len) srs_trace_memory((const char*)ptr, len)
#endif
#ifndef lberror
#define lberror srs_error
#endif
#define LBMAX(a,b) ((a) > (b) ? (a) : (b))
#define LBMIN(a,b) ((a) > (b) ? (b) : (a))
#ifndef CHECK_RESULT
#define CHECK_RESULT(ret) if(0 > ret) {lberror("%s:%d, %s check result failed, ret:%d\n", __FILE__, __LINE__, __FUNCTION__, ret); return ret;}
#endif
#ifndef CHECK_POINTER
#define CHECK_POINTER(ptr, ret) if(NULL == ptr) {lberror("%s:%d, %s NULL ptr error, ret:%d\n", __FILE__, __LINE__, __FUNCTION__, ret); return ret;}
#endif
namespace lbsp_util
{
using namespace std;
class lazy_bitstream
{
protected:
	uint8_t* 	m_pdata;		// bitstream data buffer ptr
	uint8_t*	m_pcur_ptr;		// current read/write bitstream ptr
	long	m_ndata_len;		// bitstream data length
	long	m_nbit_offset;		// bitstream bits offset
	bool	m_blittle_endian;	//little endian flag, 1:little endian, 0: big endian
	
public:
	lazy_bitstream(void* pdata = NULL, long len = 0)
	{
		
		m_pdata = NULL;
		m_pcur_ptr = NULL;
		m_ndata_len =  0;
		m_nbit_offset = 0;
		m_blittle_endian = is_litter_endian();
		if(pdata && len > 0)
		{
			initialize(pdata, len);
		}
	}
	
	virtual ~lazy_bitstream()
	{
	}

	/*
	* @descripe:current platform is litter endian
	*@return: litter endian return true, else return false
	*/
	bool is_litter_endian()
	{
		int num = 0x11223344;
		uint8_t* pval = (uint8_t*)&num;
		// big endian 0x11, 0x22, 0x33, 0x44
		// litter endian 0x44, 0x33, 0x22, 0x11
		return pval[0]== 0x44;
	}

	/*
	* @descripe:initialize the bitstream from bytes
	* @pamram: pdata: read write stream ptr
	* @pamram: len: pdata buffer length
	* @return: success return 0, else failed
	*/
	int initialize(void* pdata, long len)
	{
		if(NULL == pdata || len <= 0)
		{
			lberror("Invalid parameter, pdata:%p, len:%ld\n", pdata, len);
			return -1;
		}

		m_pdata = (uint8_t*)pdata;
		m_pcur_ptr = m_pdata;
		m_ndata_len = len;
		m_nbit_offset = 0;
		return 0;
	}

	/*
	* @descripe: get current read/write bitstream pos in bytes
	* @return: bitstream read/write pos
	*/
	long pos(long* pbit_pos = NULL)
	{
		if(pbit_pos)
		{
			*pbit_pos = m_nbit_offset;
		}
		return m_pcur_ptr - m_pdata;
	}

	/*
	* @descripe: get current bitstream read/write ptr
	* @return: data buffer ptr
	*/
	uint8_t* cur_ptr()
	{
		return m_pcur_ptr;
	}
	
	/*
	* @descripe: get bitstream data buffer ptr
	* @return: data buffer ptr
	*/
	uint8_t* data()
	{
		return m_pdata;
	}

	/*
	* @descripe: get current bitstream data buffer size
	* @return: data buffer size in bytes
	*/
	long size()
	{
		return m_ndata_len;
	}

	/*
	* @descripe: get bitstream data buffer not use length
	* @return: bitstream data buffer not use length in bytes
	*/
	long remain()
	{
		return m_ndata_len - pos() + (m_nbit_offset > 0 ? 1 : 0);
	}

	bool empty()
	{
		return remain() > 0 ? false : true;
	}

	void skip(int nbyte)
	{
		move(nbyte);
	}
	/*
	* @descripe: move bitstream read/write ptr
	* @pamram: nbytes: bitstream read/write ptr to move in bytes
	* @pamram: nbits: bitstream read/write ptr to move in bits
	* @return: current bitstream read/write pos
	*/
	long move(long nbytes, long nbits = 0)
	{
		long byte_off = nbytes;
		long bit_off = m_nbit_offset + nbits;
		byte_off += bit_off / 8;
		bit_off = bit_off % 8;
		if(m_ndata_len < byte_off + (bit_off + 7) /8)
		{
			lberror("move nbits:%ld out of range, m_ndata_len:%ld, pos:%ld, m_nbit_offset:%ld\n", nbits, m_ndata_len, pos(), m_nbit_offset);
			assert(0);
			exit(0);
			return -1;
		}
		m_pcur_ptr += byte_off;
		m_nbit_offset = bit_off;
		assert(m_pcur_ptr - m_pdata <= m_ndata_len);
		return pos();
	}
	
	/*
	* @descripe: move bitstream read/write ptr
	* @pamram: nbytes: bitstream read/write ptr to move in bytes
	* @pamram: nbits: bitstream read/write ptr to move in bits
	* @return: current bitstream read/write pos
	*/
	long seek_to(long npos, long nbits = 0)
	{
		if(npos >= m_ndata_len)
		{
			return -1;
		}

		long cur_pos = m_pcur_ptr - m_pdata;
		m_pcur_ptr = m_pdata + npos;
		m_nbit_offset = nbits;
		return cur_pos;
	}
	/*
	* @descripe: whether required read/write bitstream length is enough
	* @pamram: len: required read/write length in bytes
	* @return: read/write bitstream length enought return true, else return false
	*/
	bool require(long len)
	{
		return len <= remain();
	}
	
	/*
	* @descripe: whether required read/write bitstream bits is enough
	* @pamram: len: required read/write length in bits
	* @return: read/write bitstream bits enought return true, else return false
	*/
	bool require_bit(int nbits)
	{
		long bit_off = m_nbit_offset + nbits + 7;
		return pos() + bit_off / 8 <= m_ndata_len;
	}
	
	/*
	* @descripe: read some bytes from bitstream and convert to ingeter
	* @pamram: nbytes: reading bytes count
	* @return: ingeter convert from readed bytes
	*/
	int64_t read_byte(int nbytes)
	{
		if (m_pdata && require(nbytes))
		{
			int64_t value = 0;
			char* pp = (char*)&value;
			assert(0 == m_nbit_offset);
			for (int i = 0; i < nbytes; i++)
			{
				if (m_blittle_endian)
				{
					pp[nbytes - i - 1] = *m_pcur_ptr;
				}
				else
				{
					pp[i] = *m_pcur_ptr;
				}
				move(1, 0);
			}
			return value;
		}
		else
		{
			lberror("m_pdata:%p not init or bitstream have overflow, m_ndata_len:%ld, pos:%ld, m_nbit_offset:%ld\n", m_pdata, m_ndata_len, pos(), m_nbit_offset);
			assert(0);
			return -1;
		}
	}
	
	/*
	* @descripe: read some bits from bitstream and convert to ingeter
	* @pamram: nbits: reading bits count
	* @return: ingeter convert from readed bits
	*/
	int64_t read_bit_int64(int nbits)
	{
		if (m_pdata && require_bit(nbits))
		{
			int64_t readval = 0;
			while (nbits > 0)
			{
				int readbits = 8 - m_nbit_offset;
				readbits = readbits >= nbits ? nbits : readbits;
				for (int i = 0; i < readbits; i++)
				{
					readval = (readval << 1) | ((*m_pcur_ptr>> (7 - m_nbit_offset)) & 0x1);
					move(0, 1);
				}

				if (m_nbit_offset >= 8)
				{
					assert(8 == m_nbit_offset);
					m_nbit_offset++;
					m_nbit_offset = 0;
				}
				nbits -= readbits;
			}

			return readval;
		}
		else
		{
			lberror("m_pdata:%p not init or bitstream have overflow, m_ndata_len:%ld, pos:%ld, m_nbit_offset:%ld\n", m_pdata, m_ndata_len, pos(), m_nbit_offset);
			assert(0);
			return -1;
		}
	}

	int read_bit_int(int nbits)
	{
		return (int)read_bit_int64(nbits);
	}
	
	uint8_t read_bit(int nbits)
	{
		return (uint8_t)read_bit_int64(nbits);
	}
	/*
	* @descripe: reading bytes from bitstream with specify length
	* @pamram: pdata: reading bytes output ptr
	* @pamram: pdata: reading bytes output length
	* @return: acctualy read bytes, failed return < 0
	*/
	long read_bytes(void* pdata, long len)
	{
		if (m_pdata && require(len))
		{
			memcpy(pdata, m_pcur_ptr, len);
			move(len, 0);
			return len;
		}
		else
		{
			lberror("m_pdata:%p not init or bitstream have overflow, m_ndata_len:%ld, pos:%ld, m_nbit_offset:%ld\n", m_pdata, m_ndata_len, pos(), m_nbit_offset);
		}
		return -1;
	}
	
	string read_string(int len)
	{
		assert(require(len));
		
		std::string value;
		value.append((char*)m_pcur_ptr, len);
		
		move(len);
		
		return value;
	}

	long read_ue()
	{
		long i = 0;
		while (read_bit(1) == 0 && require_bit(1) && i < 32)
			i++;
		return ((1 << i) - 1 + read_bit(i));

	}

	long read_se()
	{
		long ueval = read_ue();
		double k = ueval;
		long nvalue = (long)ceil(k / 2);
		if (ueval % 2 == 0)
		{
			nvalue = -nvalue;
		}

		return nvalue;
	}
	
	/*
	* @descripe: write bits to bitstream
	* @pamram: nbits: write bits count
	* @return: actually write bit count
	*/
	int write_bit(int64_t val, int bits)
	{
		if(NULL == m_pdata || !require_bit(bits))
		{
			lberror("m_pdata:%p not init or bitstream have overflow, m_ndata_len:%ld, pos:%ld, m_nbit_offset:%ld\n", m_pdata, m_ndata_len, pos(), m_nbit_offset);
			assert(0);
			return -1;
		}
		
		while (bits > 0)
		{
			if(0 == m_nbit_offset)
			{
				*m_pcur_ptr = 0;
			}
			char cval = (char)(val >> (bits - 1));
			cval = (cval & 0x1) << (7 - m_nbit_offset);
			cval = (char)cval & 0xff;
			*m_pcur_ptr = cval | *m_pcur_ptr;
			move(0, 1);
			bits--;
		}

		return 0;
	}

	/*
	* @descripe: write nbytes to bitstream to stream from a ingeter value
	* @pamram: val: ingeter value to write to bitstream
	* @pamram: nbytes: write ingeter value to bitstream in nbytes
	* @return: success return 0, else return -1
	*/
	int write_byte(int64_t val, int nbytes)
	{
		char* pp = (char*)&val;
		int i;
		if(NULL == m_pdata || !require(nbytes))
		{
			lberror("m_pdata:%p not init or bitstream have overflow, m_ndata_len:%ld, pos:%ld, m_nbit_offset:%ld, write nbytes:%d\n", m_pdata, m_ndata_len, pos(), m_nbit_offset, nbytes);
			assert(0);
			return -1;
		}
		
		for(i = 0; i < nbytes; i++)
		{
			if (m_blittle_endian)
			{
				*m_pcur_ptr = pp[nbytes - i - 1];
			}
			else
			{
				*m_pcur_ptr = pp[i];
			}
			move(1);
		}
		
		return 0;
	}
	
	/*
	* @descripe: write bytes from bitstream with specify length
	* @pamram: pbuf: write bytes output ptr
	* @pamram: nbytes: write bytes output length
	* @return: acctualy read bytes, failed return < 0
	*/
	int write_bytes(const void* pbuf, int nbytes)
	{
		if (m_pdata && require(nbytes))
		{
			memcpy(m_pcur_ptr, pbuf, nbytes);
			move(nbytes, 0);
			return nbytes;
		}
		else
		{
			lberror("m_pdata:%p not init or bitstream have overflow, m_ndata_len:%ld, pos:%ld, m_nbit_offset:%ld\n", m_pdata, m_ndata_len, pos(), m_nbit_offset);
		}
		return -1;
	}

	int write_string(std::string str)
	{
		return write_bytes(str.c_str(), str.length());
	}
};

/*#define H264_CODEC_TYPE     4
#define HEVC_CODEC_TYPE     5
class annexb_stream:public lazy_bitstream
{
protected:
	int		m_nstream_type;
	uint8_t		m_unal_type_mask;
	uint8_t		m_unal_type_vps;
	uint8_t		m_unal_type_sps;
	uint8_t		m_unal_type_pps;

public:
	// 4: h.264, 5:h.265
	lazy_xvc_stream(int xvc_stream_type, void* pdata = NULL, int len = NULL):lazy_bit_steam(pdata, len)
	{
		m_nstream_type = xvc_stream_type;
		if (4 == m_nstream_type)
		{
			// h264 stream
			m_unal_type_vps = 0;
			m_unal_type_sps = 7;
			m_unal_type_pps = 8;
			m_unal_type_mask = 0x1f;
		}
		else if(5 == m_nstream_type)
		{
			// h265 stream
			m_unal_type_vps = 32;
			m_unal_type_sps = 33;
			m_unal_type_pps = 34;
			m_unal_type_mask = 0x7e;
		}
		else
		{
			assert(0);
		}
	}

	void reset()
	{
		m_pcur_ptr = m_pdata;
		m_nbit_offset = 0;
	}

	int parse_stream()
	{
		if (remain() <= 4)
		{
			lberror("Not enought stream for parser remain:%d\n", remain());
			return -1;
		}
		int ret = 0;
		int nal_len = 0;
		int nal_type = 0;
		const char* pnal_begin = NULL;
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
		return 0;
	}

	int read_nal_type()
	{
		uint8_t forbiden = read_bit(1);
		if (0 != forbiden)
		{
			lberror("Invalid nal data, forbiden bit is not zero\n");
			return -1;
		}
		uint8_t nal_type = -1;
		if (4 == m_nstream_type)
		{
			uint8_t nri = read_bit(2);
			nal_type = read_bit(5);
		}
		else if (5 == m_nstream_type)
		{
			uint8_t layer_id = 0, tid = 0;
			nal_type = read_bit(6);
			layer_id = read_bit(6);
			tid = read_bit(3);
		}
		else
		{
			return -1;
		}

		return nal_type;
	}

	const char* find_start_code(const char* pdata, int len, int* pstart_code_size = NULL, int* pnal_type = NULL)
	{
		int i = 0;
		int start_code_size = 3;
		while ((i < len - 3) && (0 != pdata[i] || 0 != pdata[i+1] || 1 != pdata[i+2])) i++;
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
				*pnal_type = (pdata[i + start_code_size] & m_unal_type_mask)>>1;
			}
		}

		return pdata + i;
	}
	const char* get_nal(const char* pdata, int len, int* pnal_len, int* pnal_type = NULL, bool has_start_code = false)
	{
		int offset = 0;
		int nal_len = 0;
		int start_code_size = 0;
		const char* pnal_begin = find_start_code(pdata + offset, len - offset, &start_code_size, pnal_type);
		if (NULL == pnal_begin)
		{
			lberror("can't find start code in stream data\n");
			return pnal_begin;
		}
		offset += pnal_begin - pdata + 4;
		const char* pnal_end = find_start_code(pdata + offset, len - offset, NULL, NULL);
		if (NULL == pnal_end)
		{
			pnal_end = pdata + len;
		}
		if(!has_start_code)
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
		while(offset < len)
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
		char* rbsp = new char[len];
		int rbsp_len;
		int i = 0, j = 0;
		while (i < len)
		{
			if (j >= 2 && pdata[i] == 0x3)
			{
				i++;
				j = 0;
				continue;
			}
			else if(0 == pdata[i])
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
			else if(zero_num >= 2 && 1 == pdata[i])
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
				if (*pnal_len)
				{
					*pnal_len = len;
				}
				return pdata;
			}
		}
		
		return NULL;
	}
};*/
};
