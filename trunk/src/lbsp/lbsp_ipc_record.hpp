#pragma once
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <memory.h>
#include <time.h>
#include <string>
#include <stdlib.h>
#include <openssl/aes.h>
#include <lbsp_media_parser.hpp>
#include <srs_kernel_log.hpp>

#define VAVA_AES_KEY				"vavalic2"
#define __STDC_FORMAT_MACROS
#ifndef lbtrace
#define lbtrace     srs_rtsp_debug
#endif
#ifndef lberror
#define lberror     srs_error
#endif
//#define lbmemory	srs_rtsp_debug_memory
using namespace std;
using namespace lbsp_util;
enum codec_id
{
    codec_id_none = -1,
    codec_id_h264 = 0,
    codec_id_h265 = 1,
    codec_id_mp3  = 2,
    codec_id_aac  = 8
};
#define FRAME_TAG_SYNC_NUM      0xEB0000AA
typedef struct _rechead{
  unsigned int tag;        		// sync 0xEB0000AA
  unsigned int size;        	// frame size
  unsigned int type;        	// frame type: 0, P frame, 1: I frame, 8: audio frame
  unsigned int fps;        		// frame rate
  unsigned int time_sec;      	// timestamp in second
  unsigned int time_usec;      // timestamp in microsecond
}VAVA_RecHead;

//video record head
typedef struct _recinfo{
  char tag;            		// 0:create record, 1.complete record
  char v_encode;          	// video codec, h264 0
  char a_encode;          	// audio codec, aac 3
  char res;            		// video resolution
  char fps;            		//֡ video frame rate
  char encrypt;          	// encrypt mode: 0, no encrypt, 1.aes encrypt
  unsigned short vframe;     // video frame count
  int size;            		// video record size
  int time;            		// video record duration
}VAVA_RecInfo;


//录像头
typedef struct _rechead_004{
  unsigned int tag;        //同步头 0xEB0000AA
  unsigned int size;        //帧大小
  unsigned int type;        //帧类型 0 P帧 1 I帧 8音频帧
  unsigned int fps;        //实时帧率
  unsigned int framnum;      //帧编号
  unsigned long long ntsamp;    //时间戳(毫秒)
  unsigned int reserv;      //保留
}VAVA_HS004_RecHead;

//录像文件信息
typedef struct _recinfo_004{
  char tag;            //0 录像创建  1录像完成
  char ver;            //版本号 初始为0
  char v_encode;          //视频编码格式 0 H264 1 H265
  char a_encode;          //音频编码格式
  char res;            //分辨率
  char fps;            //帧率
  char encrypt;          //加密方式 0 不加密 0x1A AES加密
  char alarmtype;          //触发类型
  char reserv_1[4];        //保留
  unsigned short vframe;      //视频帧数
  unsigned short sample;          //音频采样率 
  int size;            //录像大小
  int time;            //录像时长
  int reserv_2[2];        //保留
}VAVA_HS004_RecInfo;

enum ecamera_record_type
{
    ecamera_hs_unknown = -1,
    ecamera_hs_001 = 1,
    ecamera_hs_002 = 2,
    ecamera_hs_003 = 3,
    ecamera_hs_004 = 4,
    ecamera_hs_005 = 5,
};

typedef struct ipc_record_info
{
    char tag;
    char version;
    char vcodec_id;
    char acodec_id;
    char res;
    char fps;
    char encrypt;
    char alarm_type;
    int vframe_num;
    int sample_rate;
    int nrec_size;
    int nduration;
} IPC_REC_INFO;
typedef struct ipc_packet_header
{
    int mt;
    int codec_id;
    int keyflag;
    int64_t pts;
    int size;
    int frame_num;
} IPC_PKT_HDR;

class IRecodrDemux
{
public:
    virtual ~IRecodrDemux(){}

    virtual bool open(const char* purl, ipc_record_info* pri = NULL) = 0;

    virtual int read_packet(ipc_packet_header* pfhdr, char* pdata, int len, bool dec_flag = false) = 0;

    virtual void close() = 0;

    virtual int seek(int64_t pts) = 0;

    virtual int parser_sequence_header(string& vps, string& sps, string& pps, string& aac_cfg) = 0;
};
class HS003RecordDemux:public IRecodrDemux
{
protected:
    ecamera_record_type m_erec_type;
    FILE*               m_pfile;
    _recinfo            m_recordinfo;
    VAVA_RecHead        m_rechead;
    int                 m_vframe;
    int                 m_aframe;

public:
    HS003RecordDemux()
    {
        m_pfile = NULL;
        memset(&m_recordinfo, 0, sizeof(m_recordinfo));
        m_vframe = 0;
        m_aframe = 0;
    }

    virtual ~HS003RecordDemux()
    {
        close();
    }

    bool open(const char* purl, ipc_record_info* precinfo)
    {
        uint32_t sync_word = 0;
        lbtrace("HS003Record open(purl:%s)", purl);
        if(NULL == purl)
        {
            lberror("open record demux failed, null ptr!");
            return false;
        }

        m_pfile = fopen(purl, "rb");

        if(NULL == m_pfile)
        {
            lberror("open %s record failed", purl);
            return false;
        }

        size_t readlen = fread(&m_recordinfo, 1, sizeof(m_recordinfo), m_pfile);
        if(readlen < sizeof(m_recordinfo))
        {
            lberror("read hs003 record header failed, readlen:%d\n", readlen);
            return false;
        }
        readlen = fread(&sync_word, 1, sizeof(sync_word), m_pfile);
        if(readlen < sizeof(sync_word))
        {
            lberror("read hs003 sync_word failed, readlen:%d\n", readlen);
            return false;
        }
        if(FRAME_TAG_SYNC_NUM != sync_word)
        {
            return false;
        }
        else
        {
            fseek(m_pfile, sizeof(m_recordinfo), SEEK_SET);
        }
        
        if(precinfo)
        {
            memset(precinfo, 0, sizeof(ipc_record_info));
            precinfo->tag = m_recordinfo.tag;
            precinfo->vcodec_id = m_recordinfo.v_encode;
            m_recordinfo.a_encode = m_recordinfo.a_encode > 0 ? m_recordinfo.a_encode : 3;
            precinfo->acodec_id = m_recordinfo.a_encode;
            precinfo->res = m_recordinfo.res;
            precinfo->encrypt = m_recordinfo.encrypt;
            precinfo->alarm_type = 1;
            precinfo->vframe_num = m_recordinfo.vframe;
            precinfo->sample_rate = 8000;
            precinfo->nrec_size = m_recordinfo.size;
            precinfo->nduration = m_recordinfo.time;
        }
        m_vframe = 0;
        m_aframe = 0;

        lbtrace("HS003Record open(purl:%s) success m_recordinfo.v_encode:%d, m_recordinfo.a_encode:%d\n", purl, m_recordinfo.v_encode, m_recordinfo.a_encode);
        return true;
    }

    int read_packet(ipc_packet_header* pframehdr, char* pdata, int len, bool dec_flag = false)
    {
        if(NULL == pframehdr || NULL == pdata)
        {
            lberror("read record frame failed, null ptr!");
            return -1;
        }

        if(!m_pfile)
        {
            lberror("record not open, please open it first!");
            return -1;
        }

        size_t readlen = fread(&m_rechead, 1, sizeof(m_rechead), m_pfile);
        //lbtrace("m_rechead.type:%d, m_rechead.size:%d, pts:%u\n", m_rechead.type, m_rechead.size, m_rechead.time_sec *1000 + m_rechead.time_usec);
        if(readlen < readlen || m_rechead.tag != 0xEB0000AA)
        {
            lberror("readlen:%d < readlen:%d, read rechdr failed, tag:%0x", readlen, readlen, m_rechead.tag);
            return -1;
        }
        if(len < (int)m_rechead.size)
        {
            lberror("len:%d < prechdr->size:%d, data buffer not enough", len, m_rechead.size);
            return -1;
        }
        if(pdata)
        {
            readlen = fread(pdata, 1, m_rechead.size, m_pfile);
            //printf("before readlen:%d = fread(pdata, 1, prechdr->size:%p, pfile)", readlen, prechdr->size);
            if(readlen < m_rechead.size)
            {
                lberror("readlen:%d < precframe->size:%d, not enough memory", readlen, m_rechead.size);
                return -1; 
            }
        }
        else
        {
            fseek(m_pfile, m_rechead.size, SEEK_CUR);
        }

        if(pframehdr)
        {
            pframehdr->mt = m_rechead.type == 8 ? 1 : 0;
            if(0 ==  pframehdr->mt)
            {
                pframehdr->codec_id = m_recordinfo.v_encode;
                pframehdr->keyflag = m_rechead.type;
                pframehdr->frame_num = ++m_vframe;
            }
            else
            {
                pframehdr->codec_id = m_recordinfo.a_encode;
                pframehdr->keyflag = 1;
                pframehdr->frame_num = ++m_aframe;
            }
            pframehdr->size = m_rechead.size;
            pframehdr->pts = (int64_t)m_rechead.time_sec *1000 + m_rechead.time_usec;
            //lbtrace("pframehdr->mt:%d, pframehdr->codec_id:%d, pframehdr->keyflag:%d, pframehdr->size:%d, pframehdr->pts:%"PRId64", m_recordinfo.a_encode:%d\n", pframehdr->mt, pframehdr->codec_id, pframehdr->keyflag, pframehdr->size, pframehdr->pts, m_recordinfo.a_encode);
        }
        return readlen;
    }

    void close()
    {
        if(m_pfile)
        {
            fclose(m_pfile);
            m_pfile = NULL;
        }
        memset(&m_recordinfo, 0, sizeof(m_recordinfo));
    }

    int seek(int64_t pts)
    {
		if(m_pfile)
		{
			int64_t cur_pts = 0;
            int64_t start_pts = INT64_MIN;
			fseek(m_pfile, sizeof(_recinfo), SEEK_SET);
			if(pts <= 0)
			{
				return 0;
			}

			while(fread(&m_rechead, 1, sizeof(m_rechead), m_pfile) >= sizeof(m_rechead))
			{
				cur_pts = m_rechead.time_sec * 1000 + m_rechead.time_usec;
                if(INT64_MIN == start_pts)
                {
                    start_pts = cur_pts;
                }

                cur_pts -= start_pts;
                lbtrace("seek pts:" PRId64 ", cur_pts:%" PRId64 "", pts, cur_pts);
				if(cur_pts < pts)
				{
					fseek(m_pfile, -sizeof(m_rechead), SEEK_CUR);
					return 0;
				}
				else
				{
					fseek(m_pfile, m_rechead.size, SEEK_CUR);
				}
				
			};
		}
		
		return -1;
    }

	int parser_sequence_header(string& vps, string& sps, string& pps, string& aac_cfg)
	{
		return -1;
	}
};


class HS004RecordDemux:public IRecodrDemux
{
protected:
    FILE*                       m_pfile;
    VAVA_HS004_RecInfo          m_recordinfo;
    VAVA_HS004_RecHead          m_rechead;

public:
    HS004RecordDemux()
    {
        m_pfile = NULL;
        memset(&m_recordinfo, 0, sizeof(m_recordinfo));
        memset(&m_rechead, 0, sizeof(m_rechead));
    }
    virtual ~HS004RecordDemux()
    {
        close();
    }

    bool open(const char* purl, ipc_record_info* precinfo)
    {
        lbtrace("HS004RecordDemux open(purl:%s)", purl);
        if(NULL == purl)
        {
            lberror("open record demux failed, null ptr!");
            return false;
        }

        m_pfile = fopen(purl, "rb");

        if(NULL == m_pfile)
        {
            lberror("open %s record failed", purl);
            return false;
        }
        uint32_t sync_word = 0;
        size_t readlen = fread(&m_recordinfo, 1, sizeof(m_recordinfo), m_pfile);
        if(readlen < sizeof(m_recordinfo))
        {
            lberror("read hs004 record header failed, readlen:%d, sizeof(m_recordinfo):%ld\n", readlen, sizeof(m_recordinfo));
            return false;
        }
        readlen = fread(&sync_word, 1, sizeof(sync_word), m_pfile);
        if(readlen < sizeof(sync_word))
        {
            lberror("read hs003 sync_word failed, readlen:%d\n", readlen);
            return false;
        }
        if(FRAME_TAG_SYNC_NUM != sync_word)
        {
            return false;
        }
        else
        {
            fseek(m_pfile, sizeof(m_recordinfo), SEEK_SET);
        }
        if(precinfo)
        {
            memset(precinfo, 0, sizeof(ipc_record_info));
            precinfo->tag = m_recordinfo.tag;
            precinfo->version = m_recordinfo.ver;
            precinfo->vcodec_id = m_recordinfo.v_encode;
            //precinfo->acodec_id = m_recordinfo.a_encode;
            precinfo->res = m_recordinfo.res;
            precinfo->encrypt = m_recordinfo.encrypt;
            precinfo->alarm_type = m_recordinfo.alarmtype;
            precinfo->vframe_num = m_recordinfo.vframe;
            precinfo->sample_rate = m_recordinfo.sample;
            precinfo->nrec_size = m_recordinfo.size;
            precinfo->nduration = m_recordinfo.time;

            m_recordinfo.a_encode = m_recordinfo.a_encode > 0 ? m_recordinfo.a_encode : 3;
            precinfo->acodec_id = m_recordinfo.a_encode;
            lbtrace("m_recordinfo.v_encode:%d, m_recordinfo.a_encode:%d, m_recordinfo.res:%d, m_recordinfo.time:%d, pos:%ld\n", m_recordinfo.v_encode, m_recordinfo.a_encode, m_recordinfo.res, m_recordinfo.time, ftell(m_pfile));
        }
        /*uint32_t magic_num = 0;
        fread(&magic_num, sizeof(magic_num), 1, m_pfile);
        if(FRAME_TAG_SYNC_NUM == magic_num)
        {
            fseek(m_pfile,  sizeof(_recinfo), SEEK_SET);
        }
        else
        {
            fseek(m_pfile,  sizeof(m_recordinfo), SEEK_SET);
        }*/
        
        return true;
    }

    int read_packet(ipc_packet_header* pframehdr, char* pdata, int len, bool dec_flag = false)
    {
        if(NULL == pframehdr || NULL == pdata)
        {
            lberror("read record frame failed, null ptr!");
            return -1;
        }

        if(!m_pfile)
        {
            lberror("record not open, please open it first!");
            return -1;
        }
        //dec_flag = true;
        size_t readlen = fread(&m_rechead, 1, sizeof(VAVA_HS004_RecHead), m_pfile);
        //lbtrace("read pkt, size:%d type:%d, pts:% "PRId64"", readlen, m_rechead.type, m_rechead.ntsamp);
        if(readlen < sizeof(VAVA_HS004_RecHead) || m_rechead.tag != 0xEB0000AA)
        {
            lberror("readlen:%d < sizeof(VAVA_HS004_RecHead):%ld, read rechdr failed, tag:%0x, pos:%ld\n", readlen, sizeof(VAVA_HS004_RecHead), m_rechead.tag, ftell(m_pfile));
            return -1;
        }
        if(len < (int)m_rechead.size)
        {
            lberror("len:%d < prechdr->size:%d, data buffer not enough", len, m_rechead.size);
            return -1;
        }

        readlen = fread(pdata, 1, m_rechead.size, m_pfile);
        //lbtrace("before readlen:%d = fread(pdata, 1, prechdr->size:%p, pfile)", readlen, prechdr->size);
        if(readlen < m_rechead.size)
        {
            lberror("readlen:%d < precframe->size:%d, not enough memory", readlen, m_rechead.size);
            return -1; 
        }

        if(pframehdr)
        {
            pframehdr->mt = m_rechead.type == 8 ? 1 : 0;
            if(0 ==  pframehdr->mt)
            {
                pframehdr->codec_id = m_recordinfo.v_encode;
                pframehdr->keyflag = m_rechead.type;
            }
            else
            {
                pframehdr->codec_id = m_recordinfo.a_encode;
                pframehdr->keyflag = 1;
            }
            pframehdr->size = m_rechead.size;
            pframehdr->frame_num = m_rechead.framnum;
            pframehdr->pts = m_rechead.ntsamp;//m_recordinfo.time_sec *1000 + m_recordinfo.time_usec;
            //lbtrace("read packet pframehdr->mt:%d, codec_id:%d, pframehdr->size, pframehdr->pts:%"PRId64", pframehdr->keyflag:%d\n", pframehdr->mt, pframehdr->codec_id, pframehdr->size, pframehdr->pts, pframehdr->keyflag);
        }
        return readlen;
    }

    void close()
    {
        if(m_pfile)
        {
            fclose(m_pfile);
            m_pfile = NULL;
        }
        memset(&m_recordinfo, 0, sizeof(m_recordinfo));
    }

	int seek(int64_t pts)
    {
		if(m_pfile)
		{
			//int64_t cur_pts = 0;
            int64_t start_pts = INT64_MIN;
			fseek(m_pfile, sizeof(m_recordinfo), SEEK_SET);
			if(pts <= 0)
			{
                lbtrace("seek pts:%" PRId64 ", pos:%ld, success\n", pts, ftell(m_pfile));
				return 0;
			}

			while(fread(&m_rechead, 1, sizeof(m_rechead), m_pfile) >= (size_t)sizeof(m_rechead))
			{
                if(INT64_MIN == start_pts)
                {
                    start_pts = m_rechead.ntsamp;
                }

                m_rechead.ntsamp -= start_pts;
                lbtrace("seek pts:" PRId64 ", cur_pts:%" PRId64 "", pts, m_rechead.ntsamp);
				if((int64_t)m_rechead.ntsamp < pts)
				{
					fseek(m_pfile, m_rechead.size, SEEK_CUR);
				}
				else
				{
					fseek(m_pfile, -sizeof(m_rechead), SEEK_CUR);
                    lbtrace("Seek pts:%" PRId64 " success\n", m_rechead.ntsamp);
					return 0;
				}
			};
		}

		fseek(m_pfile, sizeof(m_recordinfo), SEEK_SET);
		return -1;
    }

	int parser_sequence_header(string& vps, string& sps, string& pps, string& aac_cfg)
	{
		return -1;
	}
};

class RecordDemux: public IRecodrDemux
{
protected:
    IRecodrDemux* m_precdemux;
	bool		  m_benc_flag;
    ipc_record_info m_record_info;
public:
    RecordDemux()
    {
        m_precdemux = NULL;
		m_benc_flag = false;
        memset(&m_record_info, 0, sizeof(ipc_record_info));
    }
    ~RecordDemux()
    {
    }

    bool open(const char* purl, ipc_record_info* pri = NULL)
    {
        IRecodrDemux* pdemux = new HS003RecordDemux();
        if(!pdemux->open(purl, &m_record_info))
        {
            delete pdemux;
            pdemux= NULL;
            lbtrace("hs003 record %s demux failed\n", purl);
        }
        if(NULL == pdemux)
        {
            pdemux = new HS004RecordDemux();
            if(!pdemux->open(purl, &m_record_info))
            {
                delete pdemux;
                pdemux= NULL;
                lbtrace("hs003 record %s demux failed\n", purl);
            }
        }
        m_precdemux = pdemux;
        if(m_precdemux)
        {
            lbtrace("open record %s success, vcodec_id:%d, acodec_id:%d, encrypt:%d, nduration:%d, vframe_num:%d, res:%d, fps:%d, sample_rate:%d", purl, m_record_info.vcodec_id, m_record_info.acodec_id, m_record_info.encrypt, m_record_info.nduration, m_record_info.vframe_num, m_record_info.res, m_record_info.fps, m_record_info.sample_rate);
        }
        if(pri)
        {
            *pri = m_record_info;
        }
        return m_precdemux ? true : false;
    }

    int read_packet(ipc_packet_header* pfhdr, char* pdata, int len, bool dec_flag = false)
    {
        //lbtrace("readframe(pfhdr:%p, pdata:%p, len:%d), m_precdemux:%p\n", pfhdr, pdata, len, m_precdemux);
		int ret = -1;
        if(m_precdemux && pfhdr)
        {
            ret = m_precdemux->read_packet(pfhdr, pdata, len);
			if(ret > 0 && dec_flag && pfhdr->keyflag && m_record_info.encrypt)
			{
				aes_decrypt(pdata, pdata, len);
			}
        }
        return ret;
    }

    void close()
    {
        if(m_precdemux)
        {
            m_precdemux->close();
            delete m_precdemux;
            m_precdemux = NULL;
        }
    }

	int seek(int64_t pts)
    {
		if(m_precdemux)
		{
			return m_precdemux->seek(pts);
		}
		
		return -1;
    }
    
    int parser_sequence_header(string& vps, string& sps, string& pps, string& aac_cfg)
    {
        int ret = -1;
        srs_rtsp_debug("parser_sequence_header begin\n");
		if(m_precdemux)
		{
			ipc_packet_header pkt;
			int len = 1024*512;
			char* pbuf = NULL;
			bool bvsh = false, bash = false;
			ret = m_precdemux->seek(0);
			if(ret != 0)
			{
				lberror("ret:%d = m_precdemux->seek(0) failed\n", ret);
				return ret;
			}
			pbuf = (char*)malloc(len);

			while(m_precdemux->read_packet(&pkt, pbuf, len, true) > 0)
			{
                lbtrace("read packet(pkt.codec_id:%d, pkt.keyflag:%d, pkt.pts:%" PRId64 ", pkt.size:%d)\n", pkt.codec_id, pkt.keyflag, pkt.pts, pkt.size);
				if((0 == pkt.codec_id/*m_record_info.vcodec_id*/ || 1 == pkt.codec_id/*m_record_info.vcodec_id*/) && pkt.keyflag)
				{
					lazy_xvc_stream xs(0 == m_record_info.vcodec_id ? 4 : 5);
					ret = xs.parse_stream(pbuf, pkt.size);
                    lbtrace("ret:%d = xs.parse_stream(pbuf:%p, pkt.size:%d)\n", ret, pbuf, pkt.size);
					vps = xs.get_vps();
					sps = xs.get_sps();
					pps = xs.get_pps();
                    //pps.append("\0", 1);
					bvsh = true;
					lbtrace("vcodec_id:%d, vps size:%ld, sps size:%ld, pps size:%ld\n", m_record_info.vcodec_id, vps.size(), sps.size(), pps.size());
					if(vps.size() > 0)
					{
						lbmemory(vps.data(), vps.size());
					}
					if(sps.size() > 0)
					{
						lbmemory(sps.data(), sps.size());
					}
					if(pps.size() > 0)
					{
						lbmemory(pps.data(), pps.size());
					}
				}
				else if(3 == pkt.codec_id/*m_record_info.acodec_id*/ && 0xff == (uint8_t)pbuf[0])
				{
                    uint8_t cfg[20] = {0};
                    aac_cfg.clear();
                    aac_parser aacparser;
                    aacparser.parser_adts_header((uint8_t*)pbuf, 7);
                    int cfg_len = aacparser.mux_audio_specific_config((uint8_t*)cfg, 20);
					aac_cfg.append((char*)cfg, cfg_len);
					bash = true;
					lbtrace("acodec_id:%d, cfg_len:%ld\n", pkt.codec_id, aac_cfg.size());
                    lbmemory((char*)pbuf, 9);
                    lbmemory((char*)aac_cfg.data(), aac_cfg.size());
				}

				if(pkt.pts > 1000 || (bvsh && bash))
				{
					lbtrace("pkt.pts:%" PRId64 ", bvsh:%d, bash:%d\n", pkt.pts, (int)bvsh, (int)bash);
					break;
				}
			};

			if(pbuf)
			{
				free(pbuf);
				pbuf = NULL;
			}
            
            ret = m_precdemux->seek(0);
		}

        return 0;
    }

protected:
	int aes_decrypt(char* in, char* out, int size)  
	{  
		AES_KEY aes;
		int en_size;
		char aeskey[AES_BLOCK_SIZE];
		char* porg_out = out;
		if(in == NULL || out == NULL)
		{
			return -1;
		}

		memset(aeskey, 0, AES_BLOCK_SIZE);
		strcpy(aeskey, VAVA_AES_KEY);
		
		if(AES_set_decrypt_key((unsigned char*)aeskey, 128, &aes) < 0)  
		{  
			return -1;  
		}  

		en_size = 0;

		//��������ַ���������������AES_BLOCK_SIZE������������Ҫ�ϸ�����
		while(en_size < size && size - en_size >= 16)  
		{  
			AES_decrypt((unsigned char*)in, (unsigned char*)out, &aes);  
			
			in += AES_BLOCK_SIZE;  
			out += AES_BLOCK_SIZE;  
			en_size += AES_BLOCK_SIZE;  
		}
		printf("VAVA_Aes_Decrypt aeskey:%s, porg_out[0]:%0x\n", aeskey, (uint8_t)porg_out[0]);
		return 0;  
	}
};

class RecordMuxer
{
public:
    RecordMuxer()
    {

    }

    ~RecordMuxer()
    {
        close();
    }
    int gen_url_by_pattrn(char* purl, int64_t mediatimestamp)
    {
        char url[1024] = {0};
        time_t t = mediatimestamp/1000;
        struct tm *p;
        p=gmtime(&t);
        char curdatatime[100] = {0};
        strftime(curdatatime, 100, "%Y-%m-%d %H:%M:%S", p);
        sprintf(url, purl, mediatimestamp);
        
        return 0;
    }

    int open(const char* purl, codec_id vcodecid, codec_id acodecid,  int encflag, int64_t mediatimestamp = -1)
    {
        lbtrace("purl:%s, vcodecid:%d, acodecid:%d, encflag:%d, mediatimestamp:%" PRId64 "", purl, vcodecid, acodecid, encflag, mediatimestamp);
        if(NULL == purl)
        {
            lberror("Invalid purl ptr, NULL == purl");
            return -1;
        }

        char url[1024] = {0};
        if(mediatimestamp > 0)
        {
            time_t t = mediatimestamp/1000;
            struct tm *p;
            p=localtime(&t);
            char curdatatime[100] = {0};
            strftime(curdatatime, 100, "%Y-%m-%d %H-%M-%S", p);
            sprintf(url, purl, curdatatime);
            //lbtrace("url:%s, purl:%s, curdatatime:%s", url, purl, curdatatime);
        }
        else
        {
            strcpy(url, purl);
        }
        
        memset(&m_recframe, 0, sizeof(m_recframe));
        memset(&m_recordinfo, 0, sizeof(m_recordinfo));
        m_pfile = fopen(url, "wb");
        if(NULL == m_pfile)
        {
            lberror("RecordMuxer open %s failed", url);
            return -1;
        }
        lbtrace(" m_pfile:%p = fopen(url:%s, wb)", m_pfile, url);
        m_recordinfo.v_encode = vcodecid;
        m_recordinfo.a_encode = acodecid == 2 ? 3 : acodecid;
        m_recordinfo.encrypt = encflag;
        m_recordinfo.fps = 15;
        m_recordinfo.res = 0;
        m_recordinfo.tag = 1;
        m_recordinfo.time = 0;
        fwrite(&m_recordinfo, 1, sizeof(m_recordinfo), m_pfile);
        return 0;
    }

    int writeframe(codec_id codecid, char* pdata, int len, int64_t pts)
    {
        if(!m_pfile)
        {
            lberror("record file not open");
            return -1;
        }

        if(!pdata)
        {
            lberror("Invalid data ptr");
            return -1;
        }
        m_recframe.tag = 0xEB0000AA;
        m_recframe.fps = 15;
        m_recframe.size = len;
        m_recframe.time_sec = pts/1000;
        m_recframe.time_usec = pts%1000;
        m_recframe.type = codecid;

        size_t wlen = fwrite(&m_recframe, 1, sizeof(m_recframe), m_pfile);
        
        wlen = fwrite(pdata, 1, len, m_pfile);
        //lbtrace("wlen:%d = fwrite(pdata, 1, len:%d, m_pfile:%p)", wlen, len, m_pfile);
        return wlen;
    }

    void close()
    {
        //lbtrace("close m_pfile:%p", m_pfile);
        if(m_pfile)
        {
            fclose(m_pfile);
            m_pfile = NULL;
        }
    }

protected:
    FILE*           m_pfile;
    _recinfo        m_recordinfo;
    VAVA_RecHead    m_recframe;
};