#pragma once
#include <stdio.h>
#include <stdint.h>
#include <memory.h>
#include <time.h>
#include <srs_kernel_log.hpp>
#define lbtrace printf
#define lberror srs_error

enum codec_id
{
    codec_id_none = -1,
    codec_id_h264 = 0,
    codec_id_h265 = 1,
    //codec_id_mp3  = 2,
    codec_id_aac  = 8
};
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

class RecordDemux
{
public:
    RecordDemux()
    {
        m_pfile = NULL;
        memset(&m_recordinfo, 0, sizeof(m_recordinfo));
    }

    ~RecordDemux()
    {
        close();
    }


    int open(const char* purl)
    {
        if(NULL == purl)
        {
            lberror("open record demux failed, null ptr!");
            return -1;
        }

        m_pfile = fopen(purl, "rb");

        if(NULL == m_pfile)
        {
            lberror("open %s record failed", purl);
            return -1;
        }

        fread(&m_recordinfo, 1, sizeof(m_recordinfo), m_pfile);
        m_lstart_pts = INT64_MIN;
        return 0;
    }

    int readframe(VAVA_RecHead* precframe, char* pdata, int len, int64_t* ppts = NULL)
    {
        if(NULL == precframe || NULL == pdata)
        {
            lberror("read record frame failed, null ptr!");
            return -1;
        }

        if(!m_pfile)
        {
            lberror("record not open, please open it first!");
            return -1;
        }

        size_t readlen = fread(precframe, 1, sizeof(VAVA_RecHead), m_pfile);
        //lbtrace("before readlen:%d = fread(prechdr", readlen);
        if(readlen < sizeof(VAVA_RecHead) || precframe->tag != 0xEB0000AA)
        {
            lberror("readlen:%"PRId64" < readlen:%"PRId64", read rechdr failed, tag:%0x", readlen, sizeof(VAVA_RecHead), precframe->tag);
            return -1;
        }
        if(len < (int)precframe->size)
        {
            lberror("len:%d < prechdr->size:%d, data buffer not enough", len, precframe->size);
            return -1;
        }
        if(INT64_MIN == m_lstart_pts)
        {
            m_lstart_pts = precframe->time_sec * 1000 + precframe->time_usec;
        }
        readlen = fread(pdata, 1, precframe->size, m_pfile);
        //lbtrace("before readlen:%d = fread(pdata, 1, prechdr->size:%p, pfile)", readlen, prechdr->size);
        if(readlen < precframe->size)
        {
            lberror("readlen:%"PRId64" < precframe->size:%d, not enough memory", readlen, precframe->size);
            return -1; 
        }
        if(ppts)
        {
            *ppts = precframe->time_sec * 1000 + precframe->time_usec - m_lstart_pts;
        }
        return readlen;
    }

    int seek(int64_t pts)
    {
        lbtrace("record seek begin, pts:%"PRId64"", pts);
        int64_t frame_pts = 0;
        int start_pts = INT32_MIN;
        VAVA_RecHead rechdr;
        fseek(m_pfile, sizeof(m_recordinfo), SEEK_SET);
        if(0 >= pts)
        {
            return 0;
        }
        do
        {
            
            int ret = fread(&rechdr, 1, sizeof(VAVA_RecHead), m_pfile);
            if(ret < sizeof(VAVA_RecHead))
            {
                lberror("read record failed, ret:%d\n", ret);
                return -1;
            }
            frame_pts = rechdr.time_sec * 1000 + rechdr.time_usec;
            lbtrace("read record frame pts:%"PRId64", size:%d\n", frame_pts, rechdr.size);
            if(INT64_MIN == m_lstart_pts)
            {
                m_lstart_pts = frame_pts;
            }
            frame_pts = frame_pts - m_lstart_pts;
            if(frame_pts < pts)
            {
                fseek(m_pfile, rechdr.size, SEEK_CUR);
            }
            else
            {
                fseek(m_pfile, -sizeof(VAVA_RecHead), SEEK_CUR);
                lbtrace("record seek success pts:%u, curpos:%ld", rechdr.time_sec * 1000 + rechdr.time_usec, ftell(m_pfile));
                break;
            }
            
        }while(frame_pts < pts);
        return 0;
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

protected:
    FILE*           m_pfile;
    _recinfo        m_recordinfo;
    int64_t         m_lstart_pts;
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
            strftime(curdatatime, 100, "%Y-%m-%d %H:%M:%S", p);
            sprintf(url, purl, curdatatime);
        }
        else
        {
            strcpy(url, purl);
        }
        
        memset(&m_recframe, 0, sizeof(m_recframe));
        memset(&m_recordinfo, 0, sizeof(m_recordinfo));
        m_pfile = fopen(url, "wb");
        if(m_pfile)
        {
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
       
        return -1;
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
        m_recframe.type = codecid == 2 ? 3 : codecid;

        int wlen = fwrite(&m_recframe, 1, sizeof(m_recframe), m_pfile);
        wlen = fwrite(pdata, 1, len, m_pfile);
        return wlen;
    }

    void close()
    {
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