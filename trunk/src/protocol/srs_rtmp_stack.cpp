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

#include <srs_rtmp_stack.hpp>

#include <srs_rtmp_amf0.hpp>
#include <srs_rtmp_io.hpp>
#include <srs_kernel_stream.hpp>
#include <srs_core_autofree.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_protocol_buffer.hpp>
#include <srs_rtmp_utility.hpp>
#include <srs_rtmp_handshake.hpp>
#include <srs_kernel_codec.hpp>
#include <lbsp_utility_common.hpp>
#include <lbsp_utility_string.hpp>
#include <lbsp_media_parser.hpp>
// for srs-librtmp, @see https://github.com/ossrs/srs/issues/213
#ifndef _WIN32
#include <unistd.h>
#endif
#include <stdint.h>
#include <stdlib.h>

// add by dawson for aes crt encryptiong
#ifdef USE_OPENSSL_AES_ENCRYPT
//#include <aes.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <openssl/md5.h>
#include <sys/time.h>

#ifdef ENABLE_STD_AES_ENCRYPT
#include "lbsp_aes_enc.hpp"
#endif
#endif
// add end

using namespace std;
using namespace lbsp_util;
// FMLE
#define RTMP_AMF0_COMMAND_ON_FC_PUBLISH         "onFCPublish"
#define RTMP_AMF0_COMMAND_ON_FC_UNPUBLISH       "onFCUnpublish"

// default stream id for response the createStream request.
#define SRS_DEFAULT_SID                         1

// when got a messae header, there must be some data,
// increase recv timeout to got an entire message.
#define SRS_MIN_RECV_TIMEOUT_US (int64_t)(60*1000*1000LL)

/****************************************************************************
*****************************************************************************
****************************************************************************/
/**
* 6.1.2. Chunk Message Header
* There are four different formats for the chunk message header,
* selected by the "fmt" field in the chunk basic header.
*/
// 6.1.2.1. Type 0
// Chunks of Type 0 are 11 bytes long. This type MUST be used at the
// start of a chunk stream, and whenever the stream timestamp goes
// backward (e.g., because of a backward seek).
#define RTMP_FMT_TYPE0                          0
// 6.1.2.2. Type 1
// Chunks of Type 1 are 7 bytes long. The message stream ID is not
// included; this chunk takes the same stream ID as the preceding chunk.
// Streams with variable-sized messages (for example, many video
// formats) SHOULD use this format for the first chunk of each new
// message after the first.
#define RTMP_FMT_TYPE1                          1
// 6.1.2.3. Type 2
// Chunks of Type 2 are 3 bytes long. Neither the stream ID nor the
// message length is included; this chunk has the same stream ID and
// message length as the preceding chunk. Streams with constant-sized
// messages (for example, some audio and data formats) SHOULD use this
// format for the first chunk of each message after the first.
#define RTMP_FMT_TYPE2                          2
// 6.1.2.4. Type 3
// Chunks of Type 3 have no header. Stream ID, message length and
// timestamp delta are not present; chunks of this type take values from
// the preceding chunk. When a single message is split into chunks, all
// chunks of a message except the first one, SHOULD use this type. Refer
// to example 2 in section 6.2.2. Stream consisting of messages of
// exactly the same size, stream ID and spacing in time SHOULD use this
// type for all chunks after chunk of Type 2. Refer to example 1 in
// section 6.2.1. If the delta between the first message and the second
// message is same as the time stamp of first message, then chunk of
// type 3 would immediately follow the chunk of type 0 as there is no
// need for a chunk of type 2 to register the delta. If Type 3 chunk
// follows a Type 0 chunk, then timestamp delta for this Type 3 chunk is
// the same as the timestamp of Type 0 chunk.
#define RTMP_FMT_TYPE3                          3

/****************************************************************************
*****************************************************************************
****************************************************************************/
/**
* band width check method name, which will be invoked by client.
* band width check mothods use SrsBandwidthPacket as its internal packet type,
* so ensure you set command name when you use it.
*/
// server play control
#define SRS_BW_CHECK_START_PLAY                 "onSrsBandCheckStartPlayBytes"
#define SRS_BW_CHECK_STARTING_PLAY              "onSrsBandCheckStartingPlayBytes"
#define SRS_BW_CHECK_STOP_PLAY                  "onSrsBandCheckStopPlayBytes"
#define SRS_BW_CHECK_STOPPED_PLAY               "onSrsBandCheckStoppedPlayBytes"

// server publish control
#define SRS_BW_CHECK_START_PUBLISH              "onSrsBandCheckStartPublishBytes"
#define SRS_BW_CHECK_STARTING_PUBLISH           "onSrsBandCheckStartingPublishBytes"
#define SRS_BW_CHECK_STOP_PUBLISH               "onSrsBandCheckStopPublishBytes"
// @remark, flash never send out this packet, for its queue is full.
#define SRS_BW_CHECK_STOPPED_PUBLISH            "onSrsBandCheckStoppedPublishBytes"

// EOF control.
// the report packet when check finished.
#define SRS_BW_CHECK_FINISHED                   "onSrsBandCheckFinished"
// @remark, flash never send out this packet, for its queue is full.
#define SRS_BW_CHECK_FINAL                      "finalClientPacket"

// data packets
#define SRS_BW_CHECK_PLAYING                    "onSrsBandCheckPlaying"
#define SRS_BW_CHECK_PUBLISHING                 "onSrsBandCheckPublishing"

/****************************************************************************
*****************************************************************************
****************************************************************************/
// add by dawson for aes encrypt

CAesEncrypt::CAesEncrypt()
{
    paesctx = NULL;
}

CAesEncrypt::~CAesEncrypt()
{
    AesDeinitContext();
}

int CAesEncrypt::AesInitContext(const uint8_t* key, const uint8_t* kiv, int len)
//int CAesEncrypt::AesInitContext(const unsigned char* key, const unsigned char* kiv, int len)
{
    srs_trace("%s(key:%s, kiv:%s, len:%d)", __FUNCTION__, key, kiv, len);
    if(NULL == key || NULL == kiv || len < AES_BLOCK_SIZE)
    {
        return -1;
    }
    AesDeinitContext();
    paesctx = (AES_CONTEXT*)malloc(sizeof(AES_CONTEXT));
    memset(paesctx, 0, sizeof(AES_CONTEXT));
    paesctx->paeskey = (aes_key_st*)malloc(sizeof(aes_key_st));
    memset(paesctx->paeskey, 0, sizeof(aes_key_st));
    memcpy(paesctx->key, key, AES_BLOCK_SIZE);
    memcpy(paesctx->kiv, kiv, AES_BLOCK_SIZE);
    //srs_trace("AesInitContext before paesctx->paeskey:%p, paesctx->key:%s, key:%s", paesctx->paeskey, paesctx->key, key);
    AES_set_encrypt_key(paesctx->key, 128, paesctx->paeskey);
    memcpy(paesctx->state.ivec, kiv, AES_BLOCK_SIZE);
    srs_trace("AesInitContext paesctx->paeskey:%p", paesctx->paeskey);
    return 0;
}

int CAesEncrypt::AesDecrypt(unsigned char* pin, unsigned char* pout, int len)
{
    //srs_trace("AesDecrypt begin, paesctx:%p", paesctx);
    //srs_trace("AesDecrypt begin paesctx->nlen:%d, paesctx->pbuf:%p", paesctx->nlen, paesctx->pbuf);
    int de_size = 0;
    if(NULL == paesctx)
    {
        srs_error("%s not init, paesctx:%p", __FUNCTION__, paesctx);
        return -1;
    }
    if(paesctx->nlen < len)
    {
        if(paesctx->pbuf)
        {
            srs_trace("before free");
            free(paesctx->pbuf);
            paesctx->pbuf = NULL;
        }
        srs_trace("after free");
        paesctx->nlen = len * 2;
        paesctx->pbuf = (unsigned char*)malloc(paesctx->nlen);
        memset(paesctx->pbuf, 0, paesctx->nlen);
    }
#if 1
    //srs_trace("before AES_ctr128_encrypt, len:%d, paesctx->paeskey:%p, paesctx->nlen, paesctx->pbuf:%p",len, paesctx->paeskey, paesctx->nlen, paesctx->pbuf);
    //AES_ctr128_encrypt((const unsigned char *)pin, (unsigned char *)paesctx->pbuf, len, paesctx->paeskey, paesctx->state.ivec, paesctx->state.ecount, &paesctx->state.num);
    CRYPTO_ctr128_encrypt((const unsigned char *)pin, (unsigned char *)paesctx->pbuf, len, paesctx->paeskey, paesctx->state.ivec, paesctx->state.ecount, &paesctx->state.num, (block128_f) AES_encrypt);
    //srs_trace("AES_ctr128_encrypt end");
    memcpy(pout, paesctx->pbuf, len);
    de_size = len;
#else
    while(de_size < len && len - de_size >= 16)
    {
        unsigned char *pdst = paesctx->pbuf;
        AES_ctr128_encrypt((const unsigned char *)pin, (unsigned char *)pdst, len, key, pcrt_state->ivec, pcrt_state->ecount, &pcrt_state->num);
        pin += AES_BLOCK_SIZE;
        pdst += AES_BLOCK_SIZE;
        de_size += AES_BLOCK_SIZE;
    }
#endif

    return de_size;
}

void CAesEncrypt::AesDeinitContext()
{
    if(paesctx)
    {
        if(paesctx->pbuf)
        {
            free(paesctx->pbuf);
            paesctx->pbuf = NULL;
            paesctx->nlen = 0;
        }

        if(paesctx->paeskey)
        {
            free(paesctx->paeskey);
            paesctx->paeskey = NULL;
        }

        free(paesctx);
        paesctx = NULL;
    }
}

int CAesEncrypt::AesInitByStringMd5(const uint8_t* pkeystring, int len)
{
    if(!pkeystring)
    {
        AesDeinitContext();
        srs_trace("%s pkeystring:%p == NULL, len:%d, AesDeinitContext", __FUNCTION__, pkeystring, len);
        return -1;
    }
    srs_trace("%s(pkeystring:%s, len:%d)", __FUNCTION__, pkeystring, len);
    unsigned char md5[100] = {0};
    MD5_CTX md5ctx;
    MD5_Init(&md5ctx);
    MD5_Update(&md5ctx, pkeystring, len);
    unsigned char tmp[16];
    MD5_Final(tmp, &md5ctx);
    for(int i = 0; i < 16; i++)
    {
        sprintf((char*)md5 + i*2, "%02X", tmp[i]);
    }

    return AesInitContext(md5, md5+16, 16);
}

CStreamInfo::CStreamInfo()
{
    interval = 2000;
    max_sample_size = 6000;
    duration    = 0;
    sumbytes    = 0;
    bitrate     = 0;
    framerate   = 0;
}

CStreamInfo::~CStreamInfo()
{

}

int CStreamInfo::SetInterval(int millsecond)
{
    if(millsecond > 0)
    {
        interval = millsecond;
        return ERROR_SUCCESS;
    }
    else
    {
        srs_error("%s invalid stream info interval:%d", __FUNCTION__, millsecond);
        return -1;
    }
}

int CStreamInfo::Push(int64_t pts, int64_t size)
{
    if(pts < 0 || size <= 0 || max_sample_size < (int64_t)sample_list.size())
    {
        srs_error("%s invalid sample pts:%"PRId64" < 0 && size:%"PRId64" <= 0 || max_sample_size:%"PRId64" < sample_list.size():%d", __FUNCTION__, pts, size, max_sample_size, (int)sample_list.size());
        return -1;
    }
    sampleitem item;
    item.llpts = pts;
    item.pktsize = size;
    //srs_trace("CStreamInfo::Push(pts:%"PRId64", size:%"PRId64, pts, size);
    int ret = Push(item);
    //srs_trace("CStreamInfo::Push ret:%d = Push(item)", ret);
    return ret;
}

int CStreamInfo::Push(sampleitem& itme)
{
    if(sample_list.size() <= 0)
    {
        sample_list.push_back(itme);
        return ERROR_SUCCESS;
    }
    int64_t minpts = itme.llpts;
    int64_t sum_bytes = 0;
    std::vector<sampleitem>::iterator it = sample_list.begin();
    //srs_trace("CStreamInfo::Push llpts:%"PRId64", pktsize:%"PRId64, itme.llpts, itme.pktsize);
    for(; it != sample_list.end(); it++)
    {
        if(itme.llpts - it->llpts > interval)
        {
            //srs_trace("itme.llpts:%"PRId64" - it->llpts:%"PRId64" > interval%"PRId64, itme.llpts, it->llpts, interval);
            sample_list.erase(it);
            //srs_trace("after erase it%p", it);
            it = sample_list.begin();
            if(it != sample_list.end())
            {
                //srs_trace("llpts:%"PRId64" size:%"PRId64, it->llpts, it->pktsize);
            }
            else
            {
                break;
            }
            continue;
        }
        else if(minpts > it->llpts)
        {
            minpts = it->llpts;
        }
        sum_bytes += it->pktsize;
    }
    //srs_trace("CStreamInfo::Push after for sum_bytes:%"PRId64, sum_bytes);
    duration = itme.llpts - minpts;
    if(duration > 0)
    {
        bitrate = sum_bytes*8*1000/duration;
        framerate = sample_list.size()*1000 / duration;
    }
   
    sumbytes = sum_bytes;
     sample_list.push_back(itme);
    //srs_trace("%s duration:%"PRId64" sum_bytes:%"PRId64" bitrate:%"PRId64" framerate:%lf, pts:%"PRId64" minpts:%"PRId64" sample_list.size:%d", __FUNCTION__, duration, sum_bytes, bitrate, framerate, itme.llpts, minpts, (int)sample_list.size());
    return ERROR_SUCCESS;
}

int CStreamInfo::GetBitrate()
{
    return bitrate;
}

double CStreamInfo::GetFramerate()
{
    return framerate;
}

int CStreamInfo::GetDuration()
{
    return duration;
}

int CStreamInfo::Reset()
{
    interval = 2000;
    max_sample_size = 6000;
    duration    = 0;
    sumbytes    = 0;
    bitrate     = 0;
    framerate   = 0;
    sample_list.clear();
    return 0;
}
// add end

SrsPacket::SrsPacket()
{
}

SrsPacket::~SrsPacket()
{
}

int SrsPacket::encode(int& psize, char*& ppayload)
{
    int ret = ERROR_SUCCESS;
    
    int size = get_size();
    char* payload = NULL;
    
    SrsStream stream;
    
    if (size > 0) {
        payload = new char[size];
        LB_ADD_MEM(payload, size);
        if ((ret = stream.initialize(payload, size)) != ERROR_SUCCESS) {
            srs_error("initialize the stream failed. ret=%d", ret);
            srs_freepa(payload);
            return ret;
        }
    }
    
    if ((ret = encode_packet(&stream)) != ERROR_SUCCESS) {
        srs_error("encode the packet failed. ret=%d", ret);
        srs_freepa(payload);
        return ret;
    }
    
    psize = size;
    ppayload = payload;
    srs_verbose("encode the packet success. size=%d", size);
    
    return ret;
}

int SrsPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(stream != NULL);
    
    ret = ERROR_SYSTEM_PACKET_INVALID;
    srs_error("current packet is not support to decode. ret=%d", ret);
    
    return ret;
}

int SrsPacket::get_prefer_cid()
{
    return 0;
}

int SrsPacket::get_message_type()
{
    return 0;
}

int SrsPacket::get_size()
{
    return 0;
}

int SrsPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(stream != NULL);
    
    ret = ERROR_SYSTEM_PACKET_INVALID;
    srs_error("current packet is not support to encode. ret=%d", ret);
    
    return ret;
}

SrsProtocol::AckWindowSize::AckWindowSize()
{
    window = 0;
    sequence_number = nb_recv_bytes = 0;
}

SrsProtocol::SrsProtocol(ISrsProtocolReaderWriter* io)
{
    in_buffer = new SrsFastBuffer();
    LB_ADD_MEM(in_buffer, sizeof(SrsFastBuffer));
    skt = io;
    
    in_chunk_size = SRS_CONSTS_RTMP_PROTOCOL_CHUNK_SIZE;
    out_chunk_size = SRS_CONSTS_RTMP_PROTOCOL_CHUNK_SIZE;
    
    nb_out_iovs = SRS_CONSTS_IOVS_MAX;
    out_iovs = (iovec*)malloc(sizeof(iovec) * nb_out_iovs);
    // each chunk consumers atleast 2 iovs
    srs_assert(nb_out_iovs >= 2);
    
    warned_c0c3_cache_dry = false;
    auto_response_when_recv = true;
    show_debug_info = true;
    in_buffer_length = 0;
    
    cs_cache = NULL;
    if (SRS_PERF_CHUNK_STREAM_CACHE > 0) {
        cs_cache = new SrsChunkStream*[SRS_PERF_CHUNK_STREAM_CACHE];
        LB_ADD_MEM(cs_cache, sizeof(SrsChunkStream*)*SRS_PERF_CHUNK_STREAM_CACHE);
    }
    for (int cid = 0; cid < SRS_PERF_CHUNK_STREAM_CACHE; cid++) {
        SrsChunkStream* cs = new SrsChunkStream(cid);
        LB_ADD_MEM(cs, sizeof(SrsChunkStream));
        // set the perfer cid of chunk,
        // which will copy to the message received.
        cs->header.perfer_cid = cid;
        
        cs_cache[cid] = cs;
    }
#ifdef USE_OPENSSL_AES_ENCRYPT
    // add by dawson for aes crt encryption
    //unsigned char* paaes_key = (unsigned char*)"sunvalley secret";
    //unsigned char* pvaes_key =  (unsigned char*)"sunvalley secret";
    //unsigned char kiv[16] = {0};
    //paenc           = NULL;
    
    bvfirst         = true;
    llvlastpts       = 0;
    llalastpts       = 0;
    llvlastrecvtime   = 0;
    llalastrecvtime   = 0;
    pencrecmuxer     = NULL;
    pdecrecmuxer     = NULL;
    m_paudiobuf      = NULL;
    m_nauidio_buf_len = 0;
#ifdef ENABLE_WRITE_VIDEO_STREAM
    pvfile          = NULL;
    pvencfile       = NULL;
#endif
#ifdef ENABLE_WRITE_AUDIO_STREAM
    pafile          = NULL;
    paencfile       = NULL;
#endif
#ifdef ENABLE_STD_AES_ENCRYPT
    pvaesdec    = NULL;
    paaesdec    = NULL;

#else
    padec           = NULL;
    //pvenc           = NULL;
    pvdec           = NULL;
#endif
    //add end
#endif
#ifdef ENABLE_CHECK_XVC_DATA
    m_pbuf_data     = NULL;
    m_nbuf_size     = 0;
#endif
    m_nhearbeat_count = 0;

    m_pavcfile = NULL;
    m_paacfile = NULL;
    nvskipbytes = 5;
    naskipbytes = 2;
}

SrsProtocol::~SrsProtocol()
{
    if (true) {
        std::map<int, SrsChunkStream*>::iterator it;
        
        for (it = chunk_streams.begin(); it != chunk_streams.end(); ++it) {
            SrsChunkStream* stream = it->second;
            srs_freep(stream);
        }
    
        chunk_streams.clear();
    }
    
    if (true) {
        std::vector<SrsPacket*>::iterator it;
        for (it = manual_response_queue.begin(); it != manual_response_queue.end(); ++it) {
            SrsPacket* pkt = *it;
            srs_freep(pkt);
        }
        manual_response_queue.clear();
    }
    
    srs_freep(in_buffer);
    
    // alloc by malloc, use free directly.
    if (out_iovs) {
        free(out_iovs);
        out_iovs = NULL;
    }
    
    // free all chunk stream cache.
    for (int i = 0; i < SRS_PERF_CHUNK_STREAM_CACHE; i++) {
        SrsChunkStream* cs = cs_cache[i];
        srs_freep(cs);
    }
    srs_freepa(cs_cache);

    if(m_pavcfile)
    {
        fclose(m_pavcfile);
        m_pavcfile = NULL;
    }
    if(m_paacfile)
    {
        fclose(m_paacfile);
        m_paacfile = NULL;
    }
#ifdef ENABLE_CHECK_XVC_DATA
    srs_freepa(m_pbuf_data);
#endif
#ifdef USE_OPENSSL_AES_ENCRYPT
    // add by dawson for aes crt encryption
#ifdef ENABLE_AES_ENC_CLASS
    LB_DEL(paenc);
    LB_DEL(padec);
    LB_DEL([pvenc]);
    LB_DEL([pvdec]);
    /*if(paenc)
    {
        delete paenc;
        paenc = NULL;
    }

    if(padec)
    {
        delete padec;
        padec = NULL;
    }

    if(pvenc)
    {
        delete pvenc;
        pvenc = NULL;
    }

    if(pvdec)
    {
        delete pvdec;
        pvdec = NULL;
    }*/
#else
    /*if(video_enc_key)
    {
        free(video_enc_key);
        video_enc_key = NULL;
    }

    if(audio_enc_key)
    {
        free(audio_enc_key);
        audio_enc_key = NULL;
    }

    if(video_kiv)
    {
        free(video_kiv);
        video_kiv = NULL;
    }

    if(audio_kiv)
    {
        free(audio_kiv);
        audio_kiv = NULL;
    }

    if(video_key)
    {
        free(video_key);
        video_key = NULL;
    }

    if(audio_key)
    {
        free(audio_key);
        audio_key = NULL;
    }

    if(video_buf)
    {
        free(video_buf);
        video_buf = NULL;
    }

    if(audio_buf)
    {
        free(audio_buf);
        audio_buf = NULL;
    }*/
#endif
#ifdef ENABLE_WRITE_VIDEO_STREAM
    if(pvencfile)
    {
        close_write_data_file(pvencfile, avcencpath.c_str(), 1024);
        pvencfile = NULL;
        avcencpath.clear();
    }

    if(pvfile)
    {
        close_write_data_file(pvfile, avcpath.c_str(), 1024);
        pvfile = NULL;
        avcpath.clear();
    }
#endif
#ifdef ENABLE_WRITE_AUDIO_STREAM
    if(paencfile)
    {
        close_write_data_file(paencfile, aacencpath.c_str(), 1024);
        paencfile = NULL;
        aacencpath.clear();
    }

    if(pafile)
    {
        close_write_data_file(pafile, aacpath.c_str(), 1024);
        pafile = NULL;
        aacpath.clear();
    }
#endif
#ifdef ENABLE_STD_AES_ENCRYPT
    LB_DEL(pvaesdec);
    LB_DEL(paaesdec);

    /*if(pvaesdec)
    {
        delete pvaesdec;
        pvaesdec = NULL;
    }

    if(paaesdec)
    {
        delete paaesdec;
        paaesdec = NULL;
    }*/
#endif
    //add end
#endif
    LB_DEL(pencrecmuxer);
    LB_DEL(pdecrecmuxer);
    LB_DEL_ARR(m_paudiobuf);

    /*if(pencrecmuxer)
    {
        delete pencrecmuxer;
        pencrecmuxer = NULL;
    }

    if(pdecrecmuxer)
    {
        delete pdecrecmuxer;
        pdecrecmuxer = NULL;
    }

    if(m_paudiobuf)
    {
        delete[] m_paudiobuf;
        m_paudiobuf = NULL;
        m_nauidio_buf_len = 0;
    }*/
}

void SrsProtocol::set_auto_response(bool v)
{
    auto_response_when_recv = v;
}

int SrsProtocol::manual_response_flush()
{
    int ret = ERROR_SUCCESS;
    
    if (manual_response_queue.empty()) {
        return ret;
    }
    
    std::vector<SrsPacket*>::iterator it;
    for (it = manual_response_queue.begin(); it != manual_response_queue.end();) {
        SrsPacket* pkt = *it;
        
        // erase this packet, the send api always free it.
        it = manual_response_queue.erase(it);
        
        // use underlayer api to send, donot flush again.
        if ((ret = do_send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            return ret;
        }
    }
    
    return ret;
}

#ifdef SRS_PERF_MERGED_READ
void SrsProtocol::set_merge_read(bool v, IMergeReadHandler* handler)
{
    in_buffer->set_merge_read(v, handler);
}

void SrsProtocol::set_recv_buffer(int buffer_size)
{
    in_buffer->set_buffer(buffer_size);
}
#endif

void SrsProtocol::set_recv_timeout(int64_t timeout_us)
{
    return skt->set_recv_timeout(timeout_us);
}

int64_t SrsProtocol::get_recv_timeout()
{
    return skt->get_recv_timeout();
}

void SrsProtocol::set_send_timeout(int64_t timeout_us)
{
    return skt->set_send_timeout(timeout_us);
}

int64_t SrsProtocol::get_send_timeout()
{
    return skt->get_send_timeout();
}

int64_t SrsProtocol::get_recv_bytes()
{
    return skt->get_recv_bytes();
}

int64_t SrsProtocol::get_send_bytes()
{
    return skt->get_send_bytes();
}

int SrsProtocol::recv_message(SrsCommonMessage** pmsg)
{
    *pmsg = NULL;
    
    int ret = ERROR_SUCCESS;
    
    while (true) {
        SrsCommonMessage* msg = NULL;
        
        if ((ret = recv_interlaced_message(&msg)) != ERROR_SUCCESS) {
            if (ret != ERROR_SOCKET_TIMEOUT && !srs_is_client_gracefully_close(ret)) {
                tag_error(get_device_sn(), "recv interlaced message failed. ret=%d", ret);
            }
            tag_error(get_device_sn(), "SrsProtocol::recv_message recv interlaced message failed, ret:%d", ret);
            srs_freep(msg);
            return ret;
        }
        //srs_verbose("entire msg received");
        
        if (!msg) {
            srs_info("got empty message without error.");
            continue;
        }
        srs_verbose("entire msg received, msg->payload:%p, msg->size:%d, message_type:%d", msg->payload, msg->size, msg->header.message_type);
        if (msg->size <= 0 || msg->header.payload_length <= 0) {
            srs_trace("ignore empty message(type=%d, size=%d, time=%"PRId64", sid=%d).",
                msg->header.message_type, msg->header.payload_length,
                msg->header.timestamp, msg->header.stream_id);
            srs_freep(msg);
            continue;
        }
/*#ifdef ENABLE_WRITE_VIDEO_STREAM
        if(RTMP_MSG_VideoMessage == msg->header.message_type)
        {
            //static FILE* pfile = fopen("./objs/nginx/html/vrecv.h264", "wb");
            if(pvencfile)
            {
                int writed = fwrite(msg->payload, 1, msg->size, pvencfile);
                srs_verbose("video writed:%d = fwrite(msg->payload, 1, msg->size:%d, pvencfile:%p)",writed, msg->size, pvencfile);
            }
        }
#endif
#ifdef ENABLE_WRITE_AUDIO_STREAM
        if(RTMP_MSG_AudioMessage == msg->header.message_type)
        {
            //static FILE* pfile = fopen("./objs/nginx/html/arecv.aac", "wb");
            if(paencfile)
            {
                int writed = fwrite(msg->payload, 1, msg->size, paencfile);
                srs_verbose("audio writed:%d = fwrite(msg->payload, 1, msg->size:%d, paencfile:%p)", writed, msg->size, paencfile);
            }
        }
#endif*/
        if ((ret = on_recv_message(msg)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(), "hook the received msg failed. ret=%d", ret);
            srs_freep(msg);
            return ret;
        }
        
        srs_verbose("got a msg, cid=%d, type=%d, size=%d, time=%"PRId64, 
            msg->header.perfer_cid, msg->header.message_type, msg->header.payload_length, 
            msg->header.timestamp);
        *pmsg = msg;
        break;
    }
    
    return ret;
}

int SrsProtocol::decode_message(SrsCommonMessage* msg, SrsPacket** ppacket)
{
    *ppacket = NULL;
    
    int ret = ERROR_SUCCESS;
    
    srs_assert(msg != NULL);
    srs_assert(msg->payload != NULL);
    srs_assert(msg->size > 0);
    
    SrsStream stream;

    // initialize the decode stream for all message,
    // it's ok for the initialize if fast and without memory copy.
    if ((ret = stream.initialize(msg->payload, msg->size)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(), "initialize stream failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("decode stream initialized success");
    
    // decode the packet.
    SrsPacket* packet = NULL;
    if ((ret = do_decode_message(msg->header, &stream, &packet)) != ERROR_SUCCESS) {
        srs_freep(packet);
#ifdef WRITE_RTMP_DATA_ENABLE
        /*if(in_buffer)
        {
            srs_trace("ret:%d = do_decode_message(msg->header, &stream, &packet)failed, curpos:%d", ret, in_buffer->get_cur_write_pos());
            in_buffer->print_cur_buff(0, 16);
        }*/
#endif
        return ret;
    }
    
    // set to output ppacket only when success.
    *ppacket = packet;
    
    return ret;
}

int SrsProtocol::do_send_messages(SrsSharedPtrMessage** msgs, int nb_msgs)
{
    int ret = ERROR_SUCCESS;
    
#ifdef SRS_PERF_COMPLEX_SEND
    int iov_index = 0;
    iovec* iovs = out_iovs + iov_index;
    
    int c0c3_cache_index = 0;
    char* c0c3_cache = out_c0c3_caches + c0c3_cache_index;

    // try to send use the c0c3 header cache,
    // if cache is consumed, try another loop.
    for (int i = 0; i < nb_msgs; i++) {
        SrsSharedPtrMessage* msg = msgs[i];
        
        if (!msg) {
            continue;
        }
    
        // ignore empty message.
        if (!msg->payload || msg->size <= 0) {
            srs_info("ignore empty message.");
            continue;
        }
    
        // p set to current write position,
        // it's ok when payload is NULL and size is 0.
        char* p = msg->payload;
        char* pend = msg->payload + msg->size;
        
        // always write the header event payload is empty.
        while (p < pend) {
            // always has header
            int nb_cache = SRS_CONSTS_C0C3_HEADERS_MAX - c0c3_cache_index;
            int nbh = msg->chunk_header(c0c3_cache, nb_cache, p == msg->payload);
            srs_assert(nbh > 0);
            
            // header iov
            iovs[0].iov_base = c0c3_cache;
            iovs[0].iov_len = nbh;
            
            // payload iov
            int payload_size = srs_min(out_chunk_size, (int)(pend - p));
            iovs[1].iov_base = p;
            iovs[1].iov_len = payload_size;
            
            // consume sendout bytes.
            p += payload_size;
            
            // realloc the iovs if exceed,
            // for we donot know how many messges maybe to send entirely,
            // we just alloc the iovs, it's ok.
            if (iov_index >= nb_out_iovs - 2) {
                srs_warn("resize iovs %d => %d, max_msgs=%d", 
                    nb_out_iovs, nb_out_iovs + SRS_CONSTS_IOVS_MAX, 
                    SRS_PERF_MW_MSGS);
                    
                nb_out_iovs += SRS_CONSTS_IOVS_MAX;
                int realloc_size = sizeof(iovec) * nb_out_iovs;
                out_iovs = (iovec*)realloc(out_iovs, realloc_size);
            }
            
            // to next pair of iovs
            iov_index += 2;
            iovs = out_iovs + iov_index;

            // to next c0c3 header cache
            c0c3_cache_index += nbh;
            c0c3_cache = out_c0c3_caches + c0c3_cache_index;
            
            // the cache header should never be realloc again,
            // for the ptr is set to iovs, so we just warn user to set larger
            // and use another loop to send again.
            int c0c3_left = SRS_CONSTS_C0C3_HEADERS_MAX - c0c3_cache_index;
            if (c0c3_left < SRS_CONSTS_RTMP_MAX_FMT0_HEADER_SIZE) {
                // only warn once for a connection.
                if (!warned_c0c3_cache_dry) {
                    srs_warn("c0c3 cache header too small, recoment to %d", 
                        SRS_CONSTS_C0C3_HEADERS_MAX + SRS_CONSTS_RTMP_MAX_FMT0_HEADER_SIZE);
                    warned_c0c3_cache_dry = true;
                }
                
                // when c0c3 cache dry,
                // sendout all messages and reset the cache, then send again.
                if ((ret = do_iovs_send(out_iovs, iov_index)) != ERROR_SUCCESS) {
                    return ret;
                }
    
                // reset caches, while these cache ensure 
                // atleast we can sendout a chunk.
                iov_index = 0;
                iovs = out_iovs + iov_index;
                
                c0c3_cache_index = 0;
                c0c3_cache = out_c0c3_caches + c0c3_cache_index;
            }
        }
    }
    
    // maybe the iovs already sendout when c0c3 cache dry,
    // so just ignore when no iovs to send.
    if (iov_index <= 0) {
        return ret;
    }
    srs_info("mw %d msgs in %d iovs, max_msgs=%d, nb_out_iovs=%d",
        nb_msgs, iov_index, SRS_PERF_MW_MSGS, nb_out_iovs);

    return do_iovs_send(out_iovs, iov_index);
#else
    // try to send use the c0c3 header cache,
    // if cache is consumed, try another loop.
    for (int i = 0; i < nb_msgs; i++) {
        SrsSharedPtrMessage* msg = msgs[i];
        
        if (!msg) {
            continue;
        }
    
        // ignore empty message.
        if (!msg->payload || msg->size <= 0) {
            srs_info("ignore empty message.");
            continue;
        }
    
        // p set to current write position,
        // it's ok when payload is NULL and size is 0.
        char* p = msg->payload;
        char* pend = msg->payload + msg->size;
        
        // always write the header event payload is empty.
        while (p < pend) {
            // for simple send, send each chunk one by one
            iovec* iovs = out_iovs;
            char* c0c3_cache = out_c0c3_caches;
            int nb_cache = SRS_CONSTS_C0C3_HEADERS_MAX;
            
            // always has header
            int nbh = msg->chunk_header(c0c3_cache, nb_cache, p == msg->payload);
            srs_assert(nbh > 0);
            
            // header iov
            iovs[0].iov_base = c0c3_cache;
            iovs[0].iov_len = nbh;
            
            // payload iov
            int payload_size = srs_min(out_chunk_size, pend - p);
            iovs[1].iov_base = p;
            iovs[1].iov_len = payload_size;
            
            // consume sendout bytes.
            p += payload_size;

            if ((ret = skt->writev(iovs, 2, NULL)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    tag_error(get_device_sn(), "send packet with writev failed. ret=%d", ret);
                }
                return ret;
            }
        }
    }
    
    return ret;
#endif   
}

int SrsProtocol::do_iovs_send(iovec* iovs, int size)
{
    return srs_write_large_iovs(skt, iovs, size);
}

int SrsProtocol::do_send_and_free_packet(SrsPacket* packet, int stream_id)
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(packet);
    SrsAutoFree(SrsPacket, packet);
    
    int size = 0;
    char* payload = NULL;
    if ((ret = packet->encode(size, payload)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(), "encode RTMP packet to bytes oriented RTMP message failed. ret=%d", ret);
        return ret;
    }
    
    // encode packet to payload and size.
    if (size <= 0 || payload == NULL) {
        srs_warn("packet is empty, ignore empty message.");
        return ret;
    }
    
    // to message
    SrsMessageHeader header;
    header.payload_length = size;
    header.message_type = packet->get_message_type();
    header.stream_id = stream_id;
    header.perfer_cid = packet->get_prefer_cid();
    
    ret = do_simple_send(&header, payload, size);
    srs_freepa(payload);
    if (ret == ERROR_SUCCESS) {
        ret = on_send_packet(&header, packet);
    }
    
    return ret;
}

int SrsProtocol::do_simple_send(SrsMessageHeader* mh, char* payload, int size)
{
    int ret = ERROR_SUCCESS;
    
    // we directly send out the packet,
    // use very simple algorithm, not very fast,
    // but it's ok.
    char* p = payload;
    char* end = p + size;
    char c0c3[SRS_CONSTS_RTMP_MAX_FMT0_HEADER_SIZE];
    while (p < end) {
        int nbh = 0;
        if (p == payload) {
            nbh = srs_chunk_header_c0(
                mh->perfer_cid, mh->timestamp, mh->payload_length,
                mh->message_type, mh->stream_id,
                c0c3, sizeof(c0c3));
        } else {
            nbh = srs_chunk_header_c3(
                mh->perfer_cid, mh->timestamp,
                c0c3, sizeof(c0c3));
        }
        srs_assert(nbh > 0);;
        
        iovec iovs[2];
        iovs[0].iov_base = c0c3;
        iovs[0].iov_len = nbh;
        
        int payload_size = srs_min(end - p, out_chunk_size);
        iovs[1].iov_base = p;
        iovs[1].iov_len = payload_size;
        p += payload_size;
        
        if ((ret = skt->writev(iovs, 2, NULL)) != ERROR_SUCCESS) {
            if (!srs_is_client_gracefully_close(ret)) {
                tag_error(get_device_sn(), "send packet with writev failed. ret=%d", ret);
            }
            return ret;
        }
    }
    
    return ret;
}

int SrsProtocol::do_decode_message(SrsMessageHeader& header, SrsStream* stream, SrsPacket** ppacket)
{
    int ret = ERROR_SUCCESS;
    
    SrsPacket* packet = NULL;
    
    // decode specified packet type
    if (header.is_amf0_command() || header.is_amf3_command() || header.is_amf0_data() || header.is_amf3_data()) {
        srs_verbose("start to decode AMF0/AMF3 command message.");
        
        // skip 1bytes to decode the amf3 command.
        if (header.is_amf3_command() && stream->require(1)) {
            srs_verbose("skip 1bytes to decode AMF3 command");
            stream->skip(1);
        }
        
        // amf0 command message.
        // need to read the command name.
        std::string command;
        if ((ret = srs_amf0_read_string(stream, command)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(), "decode AMF0/AMF3 command name failed. ret=%d", ret);
            return ret;
        }
        srs_verbose("AMF0/AMF3 command message, command_name=%s", command.c_str());
        
        // result/error packet
        if (command == RTMP_AMF0_COMMAND_RESULT || command == RTMP_AMF0_COMMAND_ERROR) {
            double transactionId = 0.0;
            if ((ret = srs_amf0_read_number(stream, transactionId)) != ERROR_SUCCESS) {
                tag_error(get_device_sn(), "decode AMF0/AMF3 transcationId failed. ret=%d", ret);
                return ret;
            }
            srs_verbose("AMF0/AMF3 command id, transcationId=%.2f", transactionId);
            
            // reset stream, for header read completed.
            stream->skip(-1 * stream->pos());
            if (header.is_amf3_command()) {
                stream->skip(1);
            }
            
            // find the call name
            if (requests.find(transactionId) == requests.end()) {
                ret = ERROR_RTMP_NO_REQUEST;
                tag_error(get_device_sn(), "decode AMF0/AMF3 request failed. ret=%d", ret);
                return ret;
            }
            
            std::string request_name = requests[transactionId];
            srs_verbose("AMF0/AMF3 request parsed. request_name=%s", request_name.c_str());

            if (request_name == RTMP_AMF0_COMMAND_CONNECT) {
                srs_info("decode the AMF0/AMF3 response command(%s message).", request_name.c_str());
                *ppacket = packet = new SrsConnectAppResPacket();
                LB_ADD_MEM(packet, sizeof(SrsConnectAppResPacket));
                return packet->decode(stream);
            } else if (request_name == RTMP_AMF0_COMMAND_CREATE_STREAM) {
                srs_info("decode the AMF0/AMF3 response command(%s message).", request_name.c_str());
                *ppacket = packet = new SrsCreateStreamResPacket(0, 0);
                LB_ADD_MEM(packet, sizeof(SrsCreateStreamResPacket));
                return packet->decode(stream);
            } else if (request_name == RTMP_AMF0_COMMAND_RELEASE_STREAM
                || request_name == RTMP_AMF0_COMMAND_FC_PUBLISH
                || request_name == RTMP_AMF0_COMMAND_UNPUBLISH) {
                srs_info("decode the AMF0/AMF3 response command(%s message).", request_name.c_str());
                *ppacket = packet = new SrsFMLEStartResPacket(0);
                LB_ADD_MEM(packet, sizeof(SrsFMLEStartResPacket));
                return packet->decode(stream);
            } else {
                ret = ERROR_RTMP_NO_REQUEST;
                tag_error(get_device_sn(), "decode AMF0/AMF3 request failed. "
                    "request_name=%s, transactionId=%.2f, ret=%d", 
                    request_name.c_str(), transactionId, ret);
                return ret;
            }
        }
        
        // reset to zero(amf3 to 1) to restart decode.
        stream->skip(-1 * stream->pos());
        if (header.is_amf3_command()) {
            stream->skip(1);
        }
        
        // decode command object.
        if (command == RTMP_AMF0_COMMAND_CONNECT) {
            srs_info("decode the AMF0/AMF3 command(connect vhost/app message).");
            *ppacket = packet = new SrsConnectAppPacket();
            LB_ADD_MEM(packet, sizeof(SrsConnectAppPacket));
            return packet->decode(stream);
        } else if(command == RTMP_AMF0_COMMAND_CREATE_STREAM) {
            srs_info("decode the AMF0/AMF3 command(createStream message).");
            *ppacket = packet = new SrsCreateStreamPacket();
            LB_ADD_MEM(packet, sizeof(SrsCreateStreamPacket));
            return packet->decode(stream);
        } else if(command == RTMP_AMF0_COMMAND_PLAY) {
            srs_info("decode the AMF0/AMF3 command(paly message).");
            *ppacket = packet = new SrsPlayPacket();
            LB_ADD_MEM(packet, sizeof(SrsPlayPacket));
            return packet->decode(stream);
        } else if(command == RTMP_AMF0_COMMAND_PAUSE) {
            srs_info("decode the AMF0/AMF3 command(pause message).");
            *ppacket = packet = new SrsPausePacket();
            LB_ADD_MEM(packet, sizeof(SrsPausePacket));
            return packet->decode(stream);
        } else if(command == RTMP_AMF0_COMMAND_RELEASE_STREAM) {
            srs_info("decode the AMF0/AMF3 command(FMLE releaseStream message).");
            *ppacket = packet = new SrsFMLEStartPacket();
            LB_ADD_MEM(packet, sizeof(SrsFMLEStartPacket));
            return packet->decode(stream);
        } else if(command == RTMP_AMF0_COMMAND_FC_PUBLISH) {
            srs_info("decode the AMF0/AMF3 command(FMLE FCPublish message).");
            *ppacket = packet = new SrsFMLEStartPacket();
            LB_ADD_MEM(packet, sizeof(SrsFMLEStartPacket));
            return packet->decode(stream);
        } else if(command == RTMP_AMF0_COMMAND_PUBLISH) {
            srs_info("decode the AMF0/AMF3 command(publish message).");
            *ppacket = packet = new SrsPublishPacket();
            LB_ADD_MEM(packet, sizeof(SrsPublishPacket));
            return packet->decode(stream);
        } else if(command == RTMP_AMF0_COMMAND_UNPUBLISH) {
            srs_info("decode the AMF0/AMF3 command(unpublish message).");
            *ppacket = packet = new SrsFMLEStartPacket();
            LB_ADD_MEM(packet, sizeof(SrsFMLEStartPacket));
            return packet->decode(stream);
        } else if(command == SRS_CONSTS_RTMP_SET_DATAFRAME || command == SRS_CONSTS_RTMP_ON_METADATA) {
            srs_info("decode the AMF0/AMF3 data(onMetaData message).");
            *ppacket = packet = new SrsOnMetaDataPacket();
            LB_ADD_MEM(packet, sizeof(SrsOnMetaDataPacket));
            return packet->decode(stream);
        } else if(command == SRS_BW_CHECK_FINISHED
            || command == SRS_BW_CHECK_PLAYING
            || command == SRS_BW_CHECK_PUBLISHING
            || command == SRS_BW_CHECK_STARTING_PLAY
            || command == SRS_BW_CHECK_STARTING_PUBLISH
            || command == SRS_BW_CHECK_START_PLAY
            || command == SRS_BW_CHECK_START_PUBLISH
            || command == SRS_BW_CHECK_STOPPED_PLAY
            || command == SRS_BW_CHECK_STOP_PLAY
            || command == SRS_BW_CHECK_STOP_PUBLISH
            || command == SRS_BW_CHECK_STOPPED_PUBLISH
            || command == SRS_BW_CHECK_FINAL)
        {
            srs_info("decode the AMF0/AMF3 band width check message.");
            *ppacket = packet = new SrsBandwidthPacket();
            LB_ADD_MEM(packet, sizeof(SrsBandwidthPacket));
            return packet->decode(stream);
        } else if (command == RTMP_AMF0_COMMAND_CLOSE_STREAM) {
            srs_info("decode the AMF0/AMF3 closeStream message.");
            *ppacket = packet = new SrsCloseStreamPacket();
            LB_ADD_MEM(packet, sizeof(SrsCloseStreamPacket));
            return packet->decode(stream);
        } else if (header.is_amf0_command() || header.is_amf3_command()) {
            srs_info("decode the AMF0/AMF3 call message.");
            *ppacket = packet = new SrsCallPacket();
            LB_ADD_MEM(packet, sizeof(SrsCallPacket));
            return packet->decode(stream);
        }
        
        // default packet to drop message.
        srs_info("drop the AMF0/AMF3 command message, command_name=%s", command.c_str());
        *ppacket = packet = new SrsPacket();
        LB_ADD_MEM(packet, sizeof(SrsPacket));
        return ret;
    } else if(header.is_user_control_message()) {
        srs_verbose("start to decode user control message.");
        *ppacket = packet = new SrsUserControlPacket();
        LB_ADD_MEM(packet, sizeof(SrsUserControlPacket));
        return packet->decode(stream);
    } else if(header.is_window_ackledgement_size()) {
        srs_verbose("start to decode set ack window size message.");
        *ppacket = packet = new SrsSetWindowAckSizePacket();
        LB_ADD_MEM(packet, sizeof(SrsSetWindowAckSizePacket));
        return packet->decode(stream);
    } else if(header.is_set_chunk_size()) {
        srs_verbose("start to decode set chunk size message.");
        *ppacket = packet = new SrsSetChunkSizePacket();
        LB_ADD_MEM(packet, sizeof(SrsSetChunkSizePacket));
        return packet->decode(stream);
    } else {
        if (!header.is_set_peer_bandwidth() && !header.is_ackledgement()) {
            srs_trace("drop unknown message, type=%d", header.message_type);
        }
    }
    
    return ret;
}

int SrsProtocol::send_and_free_message(SrsSharedPtrMessage* msg, int stream_id)
{
    return send_and_free_messages(&msg, 1, stream_id);
}

int SrsProtocol::send_and_free_messages(SrsSharedPtrMessage** msgs, int nb_msgs, int stream_id)
{
    // always not NULL msg.
    srs_assert(msgs);
    srs_assert(nb_msgs > 0);
    
    // update the stream id in header.
    for (int i = 0; i < nb_msgs; i++) {
        SrsSharedPtrMessage* msg = msgs[i];
        
        if (!msg) {
            continue;
        }
        
        // check perfer cid and stream,
        // when one msg stream id is ok, ignore left.
        if (msg->check(stream_id)) {
            break;
        }
    }
    
    // donot use the auto free to free the msg,
    // for performance issue.
    int ret = do_send_messages(msgs, nb_msgs);
    
    for (int i = 0; i < nb_msgs; i++) {
        SrsSharedPtrMessage* msg = msgs[i];
        srs_freep(msg);
    }
    
    // donot flush when send failed
    if (ret != ERROR_SUCCESS) {
        return ret;
    }
    
    // flush messages in manual queue
    if ((ret = manual_response_flush()) != ERROR_SUCCESS) {
        return ret;
    }
    
    //print_debug_info();
    
    return ret;
}

int SrsProtocol::send_and_free_packet(SrsPacket* packet, int stream_id)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = do_send_and_free_packet(packet, stream_id)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // flush messages in manual queue
    if ((ret = manual_response_flush()) != ERROR_SUCCESS) {
        return ret;
    }
    
    return ret;
}

int SrsProtocol::recv_interlaced_message(SrsCommonMessage** pmsg)
{
    int ret = ERROR_SUCCESS;
    
    // chunk stream basic header.
    char fmt = 0;
    int cid = 0;
    if ((ret = read_basic_header(fmt, cid)) != ERROR_SUCCESS) {
        if (ret != ERROR_SOCKET_TIMEOUT && !srs_is_client_gracefully_close(ret)) {
            tag_error(get_device_sn(), "read basic header failed. ret=%d", ret);
        }
        else
        {
            tag_error(get_device_sn(), "ret:%d = read_basic_header(fmt:%d, cid:%d)", ret, fmt, cid);
        }

        return ret;
    }
    srs_verbose("read basic header success. fmt=%d, cid=%d", fmt, cid);
    
    // the cid must not negative.
    srs_assert(cid >= 0);
    
    // get the cached chunk stream.
    SrsChunkStream* chunk = NULL;
    
    // use chunk stream cache to get the chunk info.
    // @see https://github.com/ossrs/srs/issues/249
    if (cid < SRS_PERF_CHUNK_STREAM_CACHE) {
        // chunk stream cache hit.
        srs_verbose("cs-cache hit, cid=%d", cid);
        // already init, use it direclty
        chunk = cs_cache[cid];
        srs_verbose("cached chunk stream: fmt=%d, cid=%d, size=%d, message(type=%d, size=%d, time=%"PRId64", sid=%d)",
            chunk->fmt, chunk->cid, (chunk->msg? chunk->msg->size : 0), chunk->header.message_type, chunk->header.payload_length,
            chunk->header.timestamp, chunk->header.stream_id);
    } else {
        // chunk stream cache miss, use map.
        if (chunk_streams.find(cid) == chunk_streams.end()) {
            chunk = chunk_streams[cid] = new SrsChunkStream(cid);
            LB_ADD_MEM(chunk, sizeof(SrsChunkStream));
            // set the perfer cid of chunk,
            // which will copy to the message received.
            chunk->header.perfer_cid = cid;
            srs_info("cache new chunk stream: fmt=%d, cid=%d", fmt, cid);
        } else {
            chunk = chunk_streams[cid];
            srs_verbose("cached chunk stream: fmt=%d, cid=%d, size=%d, message(type=%d, size=%d, time=%"PRId64", sid=%d)",
                chunk->fmt, chunk->cid, (chunk->msg? chunk->msg->size : 0), chunk->header.message_type, chunk->header.payload_length,
                chunk->header.timestamp, chunk->header.stream_id);
        }
    }

    // chunk stream message header
    if ((ret = read_message_header(chunk, fmt)) != ERROR_SUCCESS) {
        if (ret != ERROR_SOCKET_TIMEOUT && !srs_is_client_gracefully_close(ret)) {
            tag_error(get_device_sn(), "read message header failed. ret=%d", ret);
        }
        else
        {
            tag_error(get_device_sn(), "ret:%d = read_message_header(chunk:%p, fmt:%d)", ret, chunk, (int)fmt);
        }
        return ret;
    }
    srs_verbose("read message header success. "
            "fmt=%d, ext_time=%d, size=%d, message(type=%d, size=%d, time=%"PRId64", sid=%d)", 
            fmt, chunk->extended_timestamp, (chunk->msg? chunk->msg->size : 0), chunk->header.message_type, 
            chunk->header.payload_length, chunk->header.timestamp, chunk->header.stream_id);
    
    // read msg payload from chunk stream.
    SrsCommonMessage* msg = NULL;
    if ((ret = read_message_payload(chunk, &msg)) != ERROR_SUCCESS) {
        if (ret != ERROR_SOCKET_TIMEOUT && !srs_is_client_gracefully_close(ret)) {
            tag_error(get_device_sn(), "read message payload failed. ret=%d", ret);
        }
        else
        {
            tag_error(get_device_sn(), "ret:%d = read_message_payload(chunk:%p, &msg:%p)", ret, chunk, msg);
        }
        return ret;
    }
    
    // not got an entire RTMP message, try next chunk.
    if (!msg) {
        srs_verbose("get partial message success. size=%d, message(type=%d, size=%d, time=%"PRId64", sid=%d)",
                (msg? msg->size : (chunk->msg? chunk->msg->size : 0)), chunk->header.message_type, chunk->header.payload_length,
                chunk->header.timestamp, chunk->header.stream_id);
        return ret;
    }
    
    *pmsg = msg;
    srs_info("get entire message success. size=%d, message(type=%d, size=%d, time=%"PRId64", sid=%d)",
            (msg? msg->size : (chunk->msg? chunk->msg->size : 0)), chunk->header.message_type, chunk->header.payload_length,
            chunk->header.timestamp, chunk->header.stream_id);
            
    return ret;
}

/**
* 6.1.1. Chunk Basic Header
* The Chunk Basic Header encodes the chunk stream ID and the chunk
* type(represented by fmt field in the figure below). Chunk type
* determines the format of the encoded message header. Chunk Basic
* Header field may be 1, 2, or 3 bytes, depending on the chunk stream
* ID.
* 
* The bits 0-5 (least significant) in the chunk basic header represent
* the chunk stream ID.
*
* Chunk stream IDs 2-63 can be encoded in the 1-byte version of this
* field.
*    0 1 2 3 4 5 6 7
*   +-+-+-+-+-+-+-+-+
*   |fmt|   cs id   |
*   +-+-+-+-+-+-+-+-+
*   Figure 6 Chunk basic header 1
*
* Chunk stream IDs 64-319 can be encoded in the 2-byte version of this
* field. ID is computed as (the second byte + 64).
*   0                   1
*   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   |fmt|    0      | cs id - 64    |
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   Figure 7 Chunk basic header 2
*
* Chunk stream IDs 64-65599 can be encoded in the 3-byte version of
* this field. ID is computed as ((the third byte)*256 + the second byte
* + 64).
*    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   |fmt|     1     |         cs id - 64            |
*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   Figure 8 Chunk basic header 3
*
* cs id: 6 bits
* fmt: 2 bits
* cs id - 64: 8 or 16 bits
* 
* Chunk stream IDs with values 64-319 could be represented by both 2-
* byte version and 3-byte version of this field.
*/
int SrsProtocol::read_basic_header(char& fmt, int& cid)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = in_buffer->grow(skt, 1)) != ERROR_SUCCESS) {
        if (ret != ERROR_SOCKET_TIMEOUT && !srs_is_client_gracefully_close(ret)) {
            tag_error(get_device_sn(), "read 1bytes basic header failed. required_size=%d, ret=%d", 1, ret);
        }
        else
        {
            tag_error(get_device_sn(), "read 1bytes basic header failed, ret:%d = in_buffer->grow(skt:%p, 1)", ret, skt);
        }
        return ret;
    }
    
    lastfmt = in_buffer->read_1byte();
    cid = lastfmt & 0x3f;
    fmt = (lastfmt >> 6) & 0x03;
    //if(fmt_byte)
    //srs_trace("fmt_byte:%0x, cid:%d, fmt:%d, curpos:%0x", fmt_byte, cid, fmt, (int)in_buffer->get_cur_write_pos());
#ifdef WRITE_RTMP_DATA_ENABLE
    /*llastfmtpos = in_buffer->get_cur_write_pos()-1;
    if(2 == fmt || fmt == 1)
    {
        tag_error(get_device_sn(), "read error fmt_byte:%0x fmt:%d, cid:%d, pos:%0x", (int)lastfmt, (int)fmt, (int)cid, (int)in_buffer->get_cur_write_pos());
        in_buffer->print_cur_buff(-130, 130);
        in_buffer->print_cur_buff(0, 130);
        in_buffer->closefile();
    }
    else if(in_buffer->get_cur_write_pos() >= 0x24c0cb)
    {
        srs_trace("read fmt_byte:%0x fmt:%d, cid:%d, pos:%0x", fmt_byte, (int)fmt, (int)cid, (int)in_buffer->get_cur_write_pos());
        in_buffer->print_cur_buff(16);
    }*/
    //srs_trace("read fmt_byte:%0x fmt:%d, cid:%d, pos:%0x", (int)fmt_byte, (int)fmt, (int)cid, (int)in_buffer->get_cur_write_pos());
#endif
    // 2-63, 1B chunk header
    if (cid > 1) {
        srs_verbose("basic header parsed. fmt=%d, cid=%d", fmt, cid);
        return ret;
    }

    // 64-319, 2B chunk header
    if (cid == 0) {
        if ((ret = in_buffer->grow(skt, 1)) != ERROR_SUCCESS) {
            if (ret != ERROR_SOCKET_TIMEOUT && !srs_is_client_gracefully_close(ret)) {
                tag_error(get_device_sn(), "read 2bytes basic header failed. required_size=%d, ret=%d", 1, ret);
            }
            else
            {
                tag_error(get_device_sn(), "read 2bytes basic header failed, ret:%d = in_buffer->grow(skt, 1), ", ret, skt);
            }
            return ret;
        }
        
        cid = 64;
        cid += (u_int8_t)in_buffer->read_1byte();
        srs_verbose("2bytes basic header parsed. fmt=%d, cid=%d", fmt, cid);
    // 64-65599, 3B chunk header
    } else if (cid == 1) {
        if ((ret = in_buffer->grow(skt, 2)) != ERROR_SUCCESS) {
            if (ret != ERROR_SOCKET_TIMEOUT && !srs_is_client_gracefully_close(ret)) {
                tag_error(get_device_sn(), "read 3bytes basic header failed. required_size=%d, ret=%d", 2, ret);
            }
            else
            {
                tag_error(get_device_sn(), "read 3bytes basic header failed, ret:%d = in_buffer->grow(skt, 2)", ret, skt);
            }
            return ret;
        }
        
        cid = 64;
        cid += (u_int8_t)in_buffer->read_1byte();
        cid += ((u_int8_t)in_buffer->read_1byte()) * 256;
        srs_verbose("3bytes basic header parsed. fmt=%d, cid=%d", fmt, cid);
    } else {
        tag_error(get_device_sn(), "invalid path, impossible basic header.");
        srs_assert(false);
    }
    
    return ret;
}

/**
* parse the message header.
*   3bytes: timestamp delta,    fmt=0,1,2
*   3bytes: payload length,     fmt=0,1
*   1bytes: message type,       fmt=0,1
*   4bytes: stream id,          fmt=0
* where:
*   fmt=0, 0x0X
*   fmt=1, 0x4X
*   fmt=2, 0x8X
*   fmt=3, 0xCX
*/
int SrsProtocol::read_message_header(SrsChunkStream* chunk, char fmt)
{
    int ret = ERROR_SUCCESS;
    
    /**
    * we should not assert anything about fmt, for the first packet.
    * (when first packet, the chunk->msg is NULL).
    * the fmt maybe 0/1/2/3, the FMLE will send a 0xC4 for some audio packet.
    * the previous packet is:
    *     04                // fmt=0, cid=4
    *     00 00 1a          // timestamp=26
    *     00 00 9d          // payload_length=157
    *     08                // message_type=8(audio)
    *     01 00 00 00       // stream_id=1
    * the current packet maybe:
    *     c4             // fmt=3, cid=4
    * it's ok, for the packet is audio, and timestamp delta is 26.
    * the current packet must be parsed as:
    *     fmt=0, cid=4
    *     timestamp=26+26=52
    *     payload_length=157
    *     message_type=8(audio)
    *     stream_id=1
    * so we must update the timestamp even fmt=3 for first packet.
    */
    // fresh packet used to update the timestamp even fmt=3 for first packet.
    // fresh packet always means the chunk is the first one of message.
    bool is_first_chunk_of_msg = !chunk->msg;
    
    // but, we can ensure that when a chunk stream is fresh, 
    // the fmt must be 0, a new stream.
    if (chunk->msg_count == 0 && fmt != RTMP_FMT_TYPE0) {
        // for librtmp, if ping, it will send a fresh stream with fmt=1,
        // 0x42             where: fmt=1, cid=2, protocol contorl user-control message
        // 0x00 0x00 0x00   where: timestamp=0
        // 0x00 0x00 0x06   where: payload_length=6
        // 0x04             where: message_type=4(protocol control user-control message)
        // 0x00 0x06            where: event Ping(0x06)
        // 0x00 0x00 0x0d 0x0f  where: event data 4bytes ping timestamp.
        // @see: https://github.com/ossrs/srs/issues/98
        if (chunk->cid == RTMP_CID_ProtocolControl && fmt == RTMP_FMT_TYPE1) {
            srs_warn("accept cid=2, fmt=1 to make librtmp happy.");
        } else {
            // must be a RTMP protocol level error.
            //ret = ERROR_RTMP_CHUNK_START;
#ifdef WRITE_RTMP_DATA_ENABLE
            /*tag_error(get_device_sn(), "chunk stream is fresh, fmt must be %d, actual is %d. cid=%d, type:%d, stream_id:%d, curpos:%0x, is_first:%d, lastfmt:%0x, %"PRId64, 
                RTMP_FMT_TYPE0, (int)fmt, chunk->cid, (int)chunk->header.message_type, chunk->header.stream_id, (int)in_buffer->get_cur_write_pos(), (int)is_first_chunk_of_msg, lastfmt, llastfmtpos);
                in_buffer->print_cur_buff(-130, 130);
                in_buffer->print_cur_buff(0, 130);*/
#else
            tag_error(get_device_sn(), "chunk stream is fresh, fmt must be %d, actual is %d. cid=%d, type:%d, stream_id:%d, is_first_chunk_of_msg:%d", 
                RTMP_FMT_TYPE0, (int)fmt, chunk->cid, (int)chunk->header.message_type, chunk->header.stream_id, (int)is_first_chunk_of_msg);
#endif
            // remove by dawson for srs server interrupt
            fmt = RTMP_FMT_TYPE0;
            //return ret;
        }
    }

    // when exists cache msg, means got an partial message,
    // the fmt must not be type0 which means new message.
    if (chunk->msg && fmt == RTMP_FMT_TYPE0) {
        ret = ERROR_RTMP_CHUNK_START;
        tag_error(get_device_sn(), "chunk stream exists, "
            "fmt must not be %d, actual is %d. ret=%d", RTMP_FMT_TYPE0, fmt, ret);
        return ret;
    }
    
    // create msg when new chunk stream start
    if (!chunk->msg) {
        chunk->msg = new SrsCommonMessage();
        LB_ADD_MEM(chunk->msg, sizeof(SrsCommonMessage));
        srs_verbose("create message for new chunk, fmt=%d, cid=%d", fmt, chunk->cid);
    }

    // read message header from socket to buffer.
    static char mh_sizes[] = {11, 7, 3, 0};
    int mh_size = mh_sizes[(int)fmt];
    srs_verbose("calc chunk message header size. fmt=%d, mh_size=%d", fmt, mh_size);
    
    if (mh_size > 0 && (ret = in_buffer->grow(skt, mh_size)) != ERROR_SUCCESS) {
        if (ret != ERROR_SOCKET_TIMEOUT && !srs_is_client_gracefully_close(ret)) {
            tag_error(get_device_sn(), "read %dbytes message header failed. ret=%d", mh_size, ret);
        }
        return ret;
    }
    
    /**
    * parse the message header.
    *   3bytes: timestamp delta,    fmt=0,1,2
    *   3bytes: payload length,     fmt=0,1
    *   1bytes: message type,       fmt=0,1
    *   4bytes: stream id,          fmt=0
    * where:
    *   fmt=0, 0x0X
    *   fmt=1, 0x4X
    *   fmt=2, 0x8X
    *   fmt=3, 0xCX
    */
    // see also: ngx_rtmp_recv
    if (fmt <= RTMP_FMT_TYPE2) {
        char* p = in_buffer->read_slice(mh_size);
    
        char* pp = (char*)&chunk->header.timestamp_delta;
        pp[2] = *p++;
        pp[1] = *p++;
        pp[0] = *p++;
        pp[3] = 0;
        
        // fmt: 0
        // timestamp: 3 bytes
        // If the timestamp is greater than or equal to 16777215
        // (hexadecimal 0x00ffffff), this value MUST be 16777215, and the
        // 'extended timestamp header' MUST be present. Otherwise, this value
        // SHOULD be the entire timestamp.
        //
        // fmt: 1 or 2
        // timestamp delta: 3 bytes
        // If the delta is greater than or equal to 16777215 (hexadecimal
        // 0x00ffffff), this value MUST be 16777215, and the 'extended
        // timestamp header' MUST be present. Otherwise, this value SHOULD be
        // the entire delta.
        chunk->extended_timestamp = (chunk->header.timestamp_delta >= RTMP_EXTENDED_TIMESTAMP);
        if (!chunk->extended_timestamp) {
            // Extended timestamp: 0 or 4 bytes
            // This field MUST be sent when the normal timsestamp is set to
            // 0xffffff, it MUST NOT be sent if the normal timestamp is set to
            // anything else. So for values less than 0xffffff the normal
            // timestamp field SHOULD be used in which case the extended timestamp
            // MUST NOT be present. For values greater than or equal to 0xffffff
            // the normal timestamp field MUST NOT be used and MUST be set to
            // 0xffffff and the extended timestamp MUST be sent.
            if (fmt == RTMP_FMT_TYPE0) {
                // 6.1.2.1. Type 0
                // For a type-0 chunk, the absolute timestamp of the message is sent
                // here.
                chunk->header.timestamp = chunk->header.timestamp_delta;
            } else {
                // 6.1.2.2. Type 1
                // 6.1.2.3. Type 2
                // For a type-1 or type-2 chunk, the difference between the previous
                // chunk's timestamp and the current chunk's timestamp is sent here.
                chunk->header.timestamp += chunk->header.timestamp_delta;
            }
        }
        
        if (fmt <= RTMP_FMT_TYPE1) {
            int32_t payload_length = 0;
            uint8_t* plen = (uint8_t*)p;
            pp = (char*)&payload_length;
            pp[2] = *p++;
            pp[1] = *p++;
            pp[0] = *p++;
            pp[3] = 0;
            
            // for a message, if msg exists in cache, the size must not changed.
            // always use the actual msg size to compare, for the cache payload length can changed,
            // for the fmt type1(stream_id not changed), user can change the payload 
            // length(it's not allowed in the continue chunks).
            if (!is_first_chunk_of_msg && chunk->header.payload_length != payload_length) {
                ret = ERROR_RTMP_PACKET_SIZE;
#ifdef WRITE_RTMP_DATA_ENABLE
                /*tag_error(get_device_sn(), "msg exists in chunk cache, "
                    "size=%d cannot change to %d, ret=%d, fmt:%d, curpos:%0x, pp%0x%0x%0x", 
                    chunk->header.payload_length, payload_length, ret, (int)fmt, (int)in_buffer->get_cur_write_pos(), (int)*(plen + 2), (int)*(plen+1), (int)*plen);
                    in_buffer->print_cur_buff(0, 16);*/
#else
                tag_error(get_device_sn(), "msg exists in chunk cache, "
                    "size=%d cannot change to %d, ret=%d, fmt:%d, pp%0x%0x%0x", 
                    chunk->header.payload_length, payload_length, ret, (int)fmt, (int)*(plen + 2), (int)*(plen+1), (int)*plen);
#endif
                return ret;
            }
            
            chunk->header.payload_length = payload_length;
            chunk->header.message_type = *p++;
            
            if (fmt == RTMP_FMT_TYPE0) {
                pp = (char*)&chunk->header.stream_id;
                pp[0] = *p++;
                pp[1] = *p++;
                pp[2] = *p++;
                pp[3] = *p++;
                srs_verbose("header read completed. fmt=%d, mh_size=%d, ext_time=%d, time=%"PRId64", payload=%d, type=%d, sid=%d", 
                    fmt, mh_size, chunk->extended_timestamp, chunk->header.timestamp, chunk->header.payload_length, 
                    chunk->header.message_type, chunk->header.stream_id);
            } else {
                srs_verbose("header read completed. fmt=%d, mh_size=%d, ext_time=%d, time=%"PRId64", payload=%d, type=%d", 
                    fmt, mh_size, chunk->extended_timestamp, chunk->header.timestamp, chunk->header.payload_length, 
                    chunk->header.message_type);
            }
        } else {
            srs_verbose("header read completed. fmt=%d, mh_size=%d, ext_time=%d, time=%"PRId64"", 
                fmt, mh_size, chunk->extended_timestamp, chunk->header.timestamp);
        }
    } else {
        // update the timestamp even fmt=3 for first chunk packet
        if (is_first_chunk_of_msg && !chunk->extended_timestamp) {
            chunk->header.timestamp += chunk->header.timestamp_delta;
        }
        srs_verbose("header read completed. fmt=%d, size=%d, ext_time=%d", 
            fmt, mh_size, chunk->extended_timestamp);
    }
    
    // read extended-timestamp
    if (chunk->extended_timestamp) {
        mh_size += 4;
        srs_verbose("read header ext time. fmt=%d, ext_time=%d, mh_size=%d", fmt, chunk->extended_timestamp, mh_size);
        if ((ret = in_buffer->grow(skt, 4)) != ERROR_SUCCESS) {
            if (ret != ERROR_SOCKET_TIMEOUT && !srs_is_client_gracefully_close(ret)) {
                tag_error(get_device_sn(), "read %dbytes message header failed. required_size=%d, ret=%d", mh_size, 4, ret);
            }
            return ret;
        }
        // the ptr to the slice maybe invalid when grow()
        // reset the p to get 4bytes slice.
        char* p = in_buffer->read_slice(4);

        u_int32_t timestamp = 0x00;
        char* pp = (char*)&timestamp;
        pp[3] = *p++;
        pp[2] = *p++;
        pp[1] = *p++;
        pp[0] = *p++;

        // always use 31bits timestamp, for some server may use 32bits extended timestamp.
        // @see https://github.com/ossrs/srs/issues/111
        timestamp &= 0x7fffffff;
        
        /**
        * RTMP specification and ffmpeg/librtmp is false,
        * but, adobe changed the specification, so flash/FMLE/FMS always true.
        * default to true to support flash/FMLE/FMS.
        * 
        * ffmpeg/librtmp may donot send this filed, need to detect the value.
        * @see also: http://blog.csdn.net/win_lin/article/details/13363699
        * compare to the chunk timestamp, which is set by chunk message header
        * type 0,1 or 2.
        *
        * @remark, nginx send the extended-timestamp in sequence-header,
        * and timestamp delta in continue C1 chunks, and so compatible with ffmpeg,
        * that is, there is no continue chunks and extended-timestamp in nginx-rtmp.
        *
        * @remark, srs always send the extended-timestamp, to keep simple,
        * and compatible with adobe products.
        */
        u_int32_t chunk_timestamp = (u_int32_t)chunk->header.timestamp;
        
        /**
        * if chunk_timestamp<=0, the chunk previous packet has no extended-timestamp,
        * always use the extended timestamp.
        */
        /**
        * about the is_first_chunk_of_msg.
        * @remark, for the first chunk of message, always use the extended timestamp.
        */
        if (!is_first_chunk_of_msg && chunk_timestamp > 0 && chunk_timestamp != timestamp) {
            mh_size -= 4;
            in_buffer->skip(-4);
            srs_info("no 4bytes extended timestamp in the continued chunk");
        } else {
            chunk->header.timestamp = timestamp;
        }
        srs_verbose("header read ext_time completed. time=%"PRId64"", chunk->header.timestamp);
    }
    
    // the extended-timestamp must be unsigned-int,
    //         24bits timestamp: 0xffffff = 16777215ms = 16777.215s = 4.66h
    //         32bits timestamp: 0xffffffff = 4294967295ms = 4294967.295s = 1193.046h = 49.71d
    // because the rtmp protocol says the 32bits timestamp is about "50 days":
    //         3. Byte Order, Alignment, and Time Format
    //                Because timestamps are generally only 32 bits long, they will roll
    //                over after fewer than 50 days.
    // 
    // but, its sample says the timestamp is 31bits:
    //         An application could assume, for example, that all 
    //        adjacent timestamps are within 2^31 milliseconds of each other, so
    //        10000 comes after 4000000000, while 3000000000 comes before
    //        4000000000.
    // and flv specification says timestamp is 31bits:
    //        Extension of the Timestamp field to form a SI32 value. This
    //        field represents the upper 8 bits, while the previous
    //        Timestamp field represents the lower 24 bits of the time in
    //        milliseconds.
    // in a word, 31bits timestamp is ok.
    // convert extended timestamp to 31bits.
    chunk->header.timestamp &= 0x7fffffff;
    
    // valid message, the payload_length is 24bits,
    // so it should never be negative.
    srs_assert(chunk->header.payload_length >= 0);
    
    // copy header to msg
    chunk->msg->header = chunk->header;
    
    // increase the msg count, the chunk stream can accept fmt=1/2/3 message now.
    chunk->msg_count++;
//#ifdef WRITE_RTMP_DATA_ENABLE
    //if(is_first_chunk_of_msg)
    //{
        //srs_trace("fmt:%d, ts:%"PRId64", plen:%d, curpos:%0x, isfirst:%d, remain:%d", (int)fmt, chunk->header.timestamp, chunk->header.payload_length, (int)in_buffer->get_cur_write_pos(), (int)is_first_chunk_of_msg, chunk->header.payload_length - chunk->msg->size);
    //}
//#endif
    return ret;
}


// add by dawson for h264 key frame encryption
int SrsProtocol::get_nalu_type(unsigned char* pdata, int size, int& nalutype)
{
    unsigned char* tmp = pdata;
    nalutype = 0;
    if(size < 4)
    {
        tag_error(get_device_sn(), "%s invalid h264 data size:%d", __FUNCTION__, size);
        return -1;
    }
    if(*tmp++ == 0x0 && *tmp++ == 0x0)
    {
        if(*tmp++ == 0x1 || (*tmp == 0x0 && *(++tmp) == 0x1))
        {
            nalutype = (int)(*(++tmp) & 0x1f);
            return tmp - pdata;
        }
    }
    tag_error(get_device_sn(), "%s invalid h264 data, start with:%0x%0x%0x%0x%0x", __FUNCTION__, *pdata, *(pdata+1), *(pdata+2), *(pdata+3), *(pdata+4));
    return -1;
}
// add end

int SrsProtocol::read_message_payload(SrsChunkStream* chunk, SrsCommonMessage** pmsg)
{
    int ret = ERROR_SUCCESS;
    
    // empty message
    if (chunk->header.payload_length <= 0) {
        srs_trace("get an empty RTMP "
                "message(type=%d, size=%d, time=%"PRId64", sid=%d)", chunk->header.message_type, 
                chunk->header.payload_length, chunk->header.timestamp, chunk->header.stream_id);
        
        *pmsg = chunk->msg;
        chunk->msg = NULL;
                
        return ret;
    }
    srs_assert(chunk->header.payload_length > 0);
    
    // the chunk payload size.
    int payload_size = chunk->header.payload_length - chunk->msg->size;
    payload_size = srs_min(payload_size, in_chunk_size);
    srs_verbose("chunk payload size is %d, message_size=%d, received_size=%d, in_chunk_size=%d", 
        payload_size, chunk->header.payload_length, chunk->msg->size, in_chunk_size);

    // create msg payload if not initialized
    if (!chunk->msg->payload) {
        chunk->msg->create_payload(chunk->header.payload_length);
    }
    
    // read payload to buffer
    if ((ret = in_buffer->grow(skt, payload_size)) != ERROR_SUCCESS) {
        if (ret != ERROR_SOCKET_TIMEOUT && !srs_is_client_gracefully_close(ret)) {
            tag_error(get_device_sn(), "read payload failed. required_size=%d, ret=%d", payload_size, ret);
        }
        return ret;
    }
    memcpy(chunk->msg->payload + chunk->msg->size, in_buffer->read_slice(payload_size), payload_size);
    chunk->msg->size += payload_size;
    
    srs_verbose("chunk payload read completed. payload_size=%d", payload_size);
    
    // got entire RTMP message?
    if (chunk->header.payload_length == chunk->msg->size) {
        *pmsg = chunk->msg;
        chunk->msg = NULL;
        srs_verbose("get entire RTMP message(type=%d, size=%d, time=%"PRId64", sid=%d)", 
                chunk->header.message_type, chunk->header.payload_length, 
                chunk->header.timestamp, chunk->header.stream_id);
        return ret;
    }
    
    srs_verbose("get partial RTMP message(type=%d, size=%d, time=%"PRId64", sid=%d), partial size=%d", 
            chunk->header.message_type, chunk->header.payload_length, 
            chunk->header.timestamp, chunk->header.stream_id,
            chunk->msg->size);
            
    return ret;
}

int SrsProtocol::decrypt(unsigned char* pin, unsigned char* pout, int len, aes_key_st* key, ctr_state* pcrt_state)
{
#ifdef ENABLE_STD_AES_ENCRYPT
    return 0;
#else
    int de_size = 0;
    while(de_size < len && len - de_size >= 16)
    {
        AES_ctr128_encrypt((const unsigned char *)pin, (unsigned char *)pout, len, key, pcrt_state->ivec, pcrt_state->ecount, &pcrt_state->num);
        pin += AES_BLOCK_SIZE;
        pout += AES_BLOCK_SIZE;
        de_size += AES_BLOCK_SIZE;
    }

    return de_size;
#endif
}
bool SrsProtocol::is_video_need_encrypt(char* payload, int len, int& isseqheader)
{
    //int nualtype = 0;
    if(!payload || len < nvskipbytes)
    {
        return false;
    }

    if(AVC_AES_ENC_ALL_FRAME == nvideo_enc_type)
    {
        return true;
    }
    int frametype = payload[0] & 0xf0;
    frametype = frametype >> 4;
    int av_packet_type = payload[1];
    isseqheader = av_packet_type == SrsCodecVideoAVCTypeSequenceHeader ? 1 : 0;
    if(isseqheader)
    {
        return payload[5] != 1;
    }
    //srs_trace("nvideo_enc_type:%d, frametype:%d\n", nvideo_enc_type, frametype);
    if(AVC_AES_ENC_KEY_FRAME == nvideo_enc_type && 1 == frametype)
    {
        return true;
    }
    /*nualtype = payload[AVC_AES_ENC_SKIP_BYTES - 1] & 0x1f;
    srs_verbose("nualtype:%d, nvideo_enc_type:%d", nualtype, nvideo_enc_type);
    if(5 == nualtype && AVC_AES_ENC_KEY_FRAME == nvideo_enc_type)
    {
        return true;
    }*/

    return false;
}

int SrsProtocol::InitEncrypt(int type, int enctype,  const char* pkey, int skipbytes)
{
    //srs_trace("(type:%d, enctype:%d, pkey:%s, skipbytes:%d)", type, enctype,  pkey, skipbytes);
#ifdef ENABLE_STD_AES_ENCRYPT
    if(2 == type)
    {
        if(pvaesdec)
        {
            pvaesdec->deinit();
            //delete pvaesdec;
            //pvaesdec = NULL;
        }
        else
        {
            pvaesdec = new CAesEnc();
            LB_ADD_MEM(pvaesdec, sizeof(CAesEnc));
        }
        nvideo_enc_type = enctype;
        int ret = pvaesdec->init((uint8_t*)pkey, strlen(pkey), AES_DECRYPT);
        nvskipbytes = skipbytes;
        //srs_trace("ret:%d = pvaesdec->init(pkey:%s, strlen(pkey), AES_DECRYPT), nvskipbytes:%d", ret, pkey, nvskipbytes);
        return ret;
    }
    else if(3 == type)
    {
        if(paaesdec)
        {
            paaesdec->deinit();
        }
        else
        {
            paaesdec = new CAesEnc();
            LB_ADD_MEM(paaesdec, sizeof(CAesEnc));
        }
        naudio_enc_type = enctype;
        int ret = paaesdec->init((uint8_t*)pkey, strlen(pkey), AES_DECRYPT);
        naskipbytes = skipbytes;
        //srs_trace("ret:%d = paaesdec->init(pkey:%s, strlen(pkey), AES_DECRYPT), naskipbytes:%d", ret, pkey, naskipbytes);
        return ret;
    }
    else
    {
        tag_error(get_device_sn(), "%s error_type:%d", __FUNCTION__, type);
    }
    return -1;
#else
    if(2 == type)
    {
        if(!pvdec)
        {
            pvdec = new CAesEncrypt();
            LB_ADD_MEM(pvdec, sizeof(CAesEncrypt));
        } 
        else if(!pkey)
        {
            LB_DEL(pvdec);
            //delete pvdec;
            //pvdec = NULL;
            srs_trace("%s(type:%d, enctype:%d,  pkey:%s), delete pvdec", __FUNCTION__, type, enctype,  pkey);
            return 0;
        }
        nvideo_enc_type = enctype;
        //srs_trace("pvdec:%p->AesInitByStringMd5((const unsigned char*)pkey:%s, strlen(pkey):%d)", pvdec, pkey, strlen(pkey));
        return pvdec->AesInitByStringMd5((const unsigned char*)pkey, strlen(pkey));
    }
    else if(3 == type)
    {
        if(!padec)
        {
            padec = new CAesEncrypt();
            LB_ADD_MEM(padec, sizeof(CAesEncrypt));
        } 
        else if(!pkey)
        {
            LB_DEL(padec);
            //delete padec;
            //padec = NULL;
            //srs_trace("%s(type:%d, enctype:%d,  pkey:%s), delete paenc", __FUNCTION__, type, enctype,  pkey);
            return 0;
        }
        naudio_enc_type = enctype;
        //srs_trace("paenc:%p->AesInitByStringMd5((const unsigned char*)pkey:%s, strlen(pkey):%d)", padec, pkey, strlen(pkey));
        return padec->AesInitByStringMd5((const unsigned char*)pkey, strlen(pkey));
    }
    else
    {
        tag_error(get_device_sn(), "%s error_type:%d", __FUNCTION__, type);
    }
#endif
    return -1;
}

void SrsProtocol::on_stream_start(write_data_cfg* pwdc)
{
    //srs_trace("stream start");
    llvlastpts          = 0;
    llalastpts          = 0;
    llvlastrecvtime     = 0;
    llalastrecvtime     = 0;
    bvfirst             = 1;
    if(pencrecmuxer)
    {
        LB_DEL(pencrecmuxer);
        //delete pencrecmuxer;
        //pencrecmuxer = NULL;
    }

    if(pdecrecmuxer)
    {
        LB_DEL(pdecrecmuxer);
        //delete pdecrecmuxer;
        //pdecrecmuxer = NULL;
    }
    //srs_trace("SrsProtocol::on_stream_start(pwdc:%p)\n", pwdc);
    begin_write_rtmp_stream(pwdc);
    /*if(pwdc)
    {
        if(!enc_log_path.empty())
        {
            pencrecmuxer = new RecordMuxer();
            LB_ADD_MEM(pencrecmuxer, sizeof(RecordMuxer));
            int ret = pencrecmuxer->open(enc_log_path.c_str(), codec_id_h264, codec_id_aac, 1);
            srs_trace("ret:%d = pencrecmuxer->open(enc_log_path.c_str():%s, codec_id_h264, codec_id_aac, 1)", ret, enc_log_path.c_str());
            if(ret < 0)
            {
                tag_error(get_device_sn(), "ret:%d = pencrecmuxer->open(enc_rec_path:%s, codec_id_h264, codec_id_aac, 1)", ret, enc_log_path.c_str());
                LB_DEL(pencrecmuxer);
                //delete pencrecmuxer;
                //pencrecmuxer = NULL;
            }
        }

        if(!dec_log_path.empty())
        {
            pdecrecmuxer = new RecordMuxer();
            LB_ADD_MEM(pdecrecmuxer, sizeof(RecordMuxer));
            int ret = pdecrecmuxer->open(dec_log_path.c_str(), codec_id_h264, codec_id_aac, 1);
            srs_trace("ret:%d = pdecrecmuxer->open(enc_log_path.c_str():%s, codec_id_h264, codec_id_aac, 1)", ret, dec_log_path.c_str());
            if(ret < 0)
            {
                tag_error(get_device_sn(), "ret:%d = pdecrecmuxer->open(dec_rec_path:%s, codec_id_h264, codec_id_aac, 1)", ret, dec_log_path.c_str());
                LB_DEL(pdecrecmuxer);
                //delete pdecrecmuxer;
                //pdecrecmuxer = NULL;
            }
        }
    }*/
    
    //srs_trace("enc_rec_path:%s, dec_rec_path:%s, datetime:%s", enc_log_path.c_str(), dec_log_path.c_str(), _req->datetime.c_str());
    vstreaminfo.Reset();
    astreaminfo.Reset();
}

void SrsProtocol::on_stream_stop()
{
    end_write_rtmp_stream();
}

 void SrsProtocol::begin_write_rtmp_stream(write_data_cfg* pwdc)
 {
     if(pwdc)
    {
        if(!pwdc->enc_record_data_path.empty())
        {
            pencrecmuxer = new RecordMuxer();
            LB_ADD_MEM(pencrecmuxer, sizeof(RecordMuxer));
            srs_trace("pdecrecmuxer->open(pwdc->enc_record_data_path.c_str():%s, codec_id_h264, codec_id_aac, 1)\n", pwdc->enc_record_data_path.c_str());
            int ret = pencrecmuxer->open(pwdc->enc_record_data_path.c_str(), codec_id_h264, codec_id_aac, 1);
            srs_trace("ret:%d = pencrecmuxer->open(enc_log_path.c_str():%s, codec_id_h264, codec_id_aac, 1)", ret, pwdc->enc_record_data_path.c_str());
            if(ret < 0)
            {
                tag_error(get_device_sn(), "ret:%d = pencrecmuxer->open(enc_rec_path:%s, codec_id_h264, codec_id_aac, 1)", ret, pwdc->enc_record_data_path.c_str());
                LB_DEL(pencrecmuxer);
                //delete pencrecmuxer;
                //pencrecmuxer = NULL;
            }
        }

        if(!pwdc->dec_record_data_path.empty())
        {
            pdecrecmuxer = new RecordMuxer();
            LB_ADD_MEM(pdecrecmuxer, sizeof(RecordMuxer));
            srs_trace("pdecrecmuxer->open(pwdc->dec_record_data_path.c_str():%s, codec_id_h264, codec_id_aac, 1)\n", pwdc->dec_record_data_path.c_str());
            int ret = pdecrecmuxer->open(pwdc->dec_record_data_path.c_str(), codec_id_h264, codec_id_aac, 1);
            srs_trace("ret:%d = pdecrecmuxer->open(enc_log_path.c_str():%s, codec_id_h264, codec_id_aac, 1)", ret, pwdc->dec_record_data_path.c_str());
            if(ret < 0)
            {
                tag_error(get_device_sn(), "ret:%d = pdecrecmuxer->open(dec_rec_path:%s, codec_id_h264, codec_id_aac, 1)", ret, pwdc->dec_record_data_path.c_str());
                LB_DEL(pdecrecmuxer);
            }
        }

        if(!pwdc->write_h264_data_path.empty())
        {
            m_pavcfile = fopen(pwdc->write_h264_data_path.c_str(), "wb");
            srs_trace("m_pavcfile:%p = fopen(pwdc->write_h264_data_path.c_str():%s, wb)\n", m_pavcfile, pwdc->write_h264_data_path.c_str());
        }

        if(!pwdc->write_aac_data_path.empty())
        {
            m_paacfile = fopen(pwdc->write_aac_data_path.c_str(), "wb");
        }
    }
 }

void SrsProtocol::end_write_rtmp_stream()
{
    if(pencrecmuxer)
    {
        pencrecmuxer->close();
        LB_DEL(pencrecmuxer);
    }

    if(pdecrecmuxer)
    {
        pdecrecmuxer->close();
        LB_DEL(pdecrecmuxer);
    }

    if(m_pavcfile)
    {
        fclose(m_pavcfile);
        m_pavcfile = NULL;
    }

    if(m_paacfile)
    {
       fclose(m_paacfile);
       m_paacfile = NULL;
    }
}
//million second
int64_t SrsProtocol::get_cur_time()
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    int64_t curtime = tv.tv_sec*1000 + tv.tv_usec/1000;
    return curtime;
}

int SrsProtocol::get_fd()
{
    return skt->get_fd();
}

#ifdef ENABLE_WRITE_VIDEO_STREAM
int SrsProtocol::SetVideoWriteDataPath(const std::string& vencpath, const std::string& vdatapath)
{
    srs_trace("(vencpath:%s, vdatapath:%s)", vencpath.c_str(), vdatapath.c_str());
    avcencpath = vencpath;
    avcpath = vdatapath;
    if(!avcencpath.empty())
    {
        if(pvencfile)
        {
            fclose(pvencfile);
            //close_write_data_file(paencfile, aacencpath.c_str(), 1024);
            pvencfile = NULL;
        }
        pvencfile = fopen(avcencpath.c_str(), "wb");
        srs_trace("pvencfile:%p = fopen(avcencpath.c_str():%s, wb)", pvencfile, avcencpath.c_str());
    }
    if(!avcpath.empty())
    {
        if(pvfile)
        {
            fclose(pvfile);
            //close_write_data_file(paencfile, aacencpath.c_str(), 1024);
            pvfile = NULL;
        }
        pvfile = fopen(avcpath.c_str(), "wb");
        srs_trace("pvfile:%p = fopen(avcpath.c_str():%s, wb)", pvfile, avcpath.c_str());
    }

    return 0;
}
#endif

#ifdef ENABLE_WRITE_AUDIO_STREAM
int SrsProtocol::SetAudioWriteDataPath(const std::string& aencpath, const std::string& adatapath)
{
    srs_trace("begin");
    srs_trace("(aencpath:%s, adatapath:%s)", aencpath.c_str(), adatapath.c_str());
    aacencpath = aencpath;
    aacpath = adatapath;
    srs_trace("aacencpath:%s", aacencpath.c_str());
    if(!aacencpath.empty())
    {
        if(paencfile)
        {
            fclose(paencfile);
            //close_write_data_file(paencfile, aacencpath.c_str(), 1024);
            paencfile = NULL;
        }
        paencfile = fopen(aacencpath.c_str(), "wb");
        srs_trace("paencfile:%p = fopen(aacencpath.c_str():%s, wb)", paencfile, aacencpath.c_str());
    }
    srs_trace("aacpath:%s", aacpath.c_str());
    if(!aacpath.empty())
    {
        if(pafile)
        {
            fclose(pafile);
            //close_write_data_file(paencfile, aacencpath.c_str(), 1024);
            pafile = NULL;
        }
        pafile = fopen(aacpath.c_str(), "wb");
        srs_trace("pafile:%p = fopen(aacpath.c_str():%s, wb)", pafile, aacpath.c_str());
    }
     srs_trace("end");
    return 0;
}
#endif
int SrsProtocol::on_recv_message(SrsCommonMessage* msg)
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(msg != NULL);
        
    // try to response acknowledgement
    if ((ret = response_acknowledgement_message()) != ERROR_SUCCESS) {
        return ret;
    }
    
    SrsPacket* packet = NULL;
    switch (msg->header.message_type) {
        case RTMP_MSG_SetChunkSize:
        case RTMP_MSG_UserControlMessage:
        case RTMP_MSG_WindowAcknowledgementSize:
            if ((ret = decode_message(msg, &packet)) != ERROR_SUCCESS) {
                tag_error(get_device_sn(), "decode packet from message payload failed. ret=%d", ret);
                return ret;
            }
            srs_verbose("decode packet from message payload success.");
            break;
        case RTMP_MSG_VideoMessage:
        case RTMP_MSG_AudioMessage:
            //print_debug_info();
            if(RTMP_MSG_VideoMessage == msg->header.message_type)
            {
                int64_t curtime = get_cur_time();
                int64_t recvdur = curtime - llvlastrecvtime;
                int64_t ptsdur = msg->header.timestamp - llvlastpts;
                vstreaminfo.Push(msg->header.timestamp, msg->size);
                if(ptsdur > 150)
                {
                    srs_trace("pts:%"PRId64" - lastvpts:%"PRId64" = ptsdur:%"PRId64" > 150, recv duration:%"PRId64", some video frames maybe drop!", msg->header.timestamp, llvlastpts, ptsdur, recvdur);
                }
                llvlastpts = msg->header.timestamp;
                llvlastrecvtime = curtime;
            }
            else
            {
                int64_t curtime = get_cur_time();
                int64_t recvdur = curtime - llalastrecvtime;
                int64_t ptsdur = msg->header.timestamp - llalastpts;
                astreaminfo.Push(msg->header.timestamp, msg->size);
                if(ptsdur > 200)
                {
                    srs_trace("pts:%"PRId64" - lastapts:%"PRId64" = ptsdur:%"PRId64" > 150, recv duration:%"PRId64", some audio frames maybe drop!", msg->header.timestamp, llalastpts, ptsdur, recvdur);
                }
                llalastpts = msg->header.timestamp;
                llalastrecvtime = curtime;
            }
            //srs_trace("%s media enc begin msgtype:%d, msg size:%d, sid:%d, pts:%"PRId64", pvdec:%p, padec:%p", __FUNCTION__, msg->header.message_type, msg->size,  msg->header.stream_id, msg->header.timestamp, pvdec, padec);
#ifdef ENABLE_WRITE_VIDEO_STREAM
            if(RTMP_MSG_VideoMessage == msg->header.message_type)
            {
                /*if(NULL == pvencfile)
                {
                    pvencryptfile = fopen("./objs/nginx/html/svenc.h264", "wb");
                }*/
                
                srs_info("write audio adts data after pvencryptfile:%p = fopen", pvencryptfile);
                if(pvencfile)
                {
                    int writed = fwrite(&msg->size, 1, 4, pvencfile);
                    writed = fwrite(msg->payload, 1, msg->size, pvencfile);
                    srs_info("write video data msgtype:%d, msg size:%d, writed:%d", msg->header.message_type, msg->size, writed);
                }
            }
#endif
#ifdef ENABLE_WRITE_AUDIO_STREAM
            if(RTMP_MSG_AudioMessage == msg->header.message_type)
            {
                /*if(NULL == paencfile)
                {
                    paencfile = fopen("./objs/nginx/html/saenc.aac", "wb");
                }*/
                
                char adtshdr[7] = {0xff, 0xf9, 0x50, 0x40, 0x01, 0x7f, 0xfc};
                //srs_trace("%s write audio adts data after paencfile:%p = fopen", __FUNCTION__, paencfile);
                if(paencfile)
                {
                    //int writed = fwrite(adtshdr, 1, 7, paencfile);
                    int writed = fwrite(&msg->size, 1, 4, paencfile);
                    writed = fwrite(msg->payload, 1, msg->size, paencfile);
                    srs_info("%s write audio adts data, msgtype:%d, msg size:%d, writed:%d", __FUNCTION__, msg->header.message_type, msg->size, writed);
                }
            }
#endif
// add by zwu for aes crt encrypt
#ifdef USE_OPENSSL_AES_ENCRYPT
#ifdef ENABLE_STD_AES_ENCRYPT
            //srs_trace("pvaesdec:%p, paaesdec:%p, msg->header.message_type:%d, naskipbytes:%d", pvaesdec, paaesdec, msg->header.message_type, naskipbytes);
            if(RTMP_MSG_AudioMessage == msg->header.message_type && paaesdec && msg->size > naskipbytes)
            {
#ifdef ENABLE_WRITE_MEDIA_TEST
                static FILE* pencfile = fopen("srsencaac.data", "wb");
                if(pencfile)
                {
                    fwrite(msg->payload, 1, msg->size, pencfile);
                }
#endif
                int skipbytes = naskipbytes;
                if(pencrecmuxer)
                {
                    pencrecmuxer->writeframe(codec_id_aac, msg->payload, msg->size, msg->header.timestamp);
                }
                char* pout = msg->payload + skipbytes;
                if(msg->payload[skipbytes] == (char)0xbb)
                {
                    //srs_trace("msg->payload[skipbytes] = (char)0xff");
                    msg->payload[skipbytes] = (char)0xff;
                    skipbytes++;
                    if(NULL == m_paudiobuf)
                    {
                        m_paudiobuf = new char[44100*4];
                        LB_ADD_MEM(m_paudiobuf, 44100*4);
                        m_nauidio_buf_len = 44100*4;
                    }
                    pout = m_paudiobuf;
                }

                paaesdec->encrypt((unsigned char*)msg->payload + skipbytes, (unsigned char*)pout, msg->size - skipbytes);
                //srs_trace("recv audio msg, skipbytes:%d, pts:%" PRId64 ", msg->size:%d\n", skipbytes, msg->header.timestamp, msg->size);
                //srs_trace_memory(msg->payload, msg->size);
                if(pout != msg->payload + skipbytes)
                {
                    int copylen = msg->size - skipbytes - 6;
                    msg->size = copylen + naskipbytes;
                    memcpy(msg->payload + naskipbytes, pout + 6, copylen);
                }

                if(pdecrecmuxer)
                {
                    pdecrecmuxer->writeframe(codec_id_aac, msg->payload + naskipbytes, msg->size - naskipbytes, msg->header.timestamp);
                }
                if(m_paacfile)
                {
                    fwrite(msg->payload + naskipbytes, 1, msg->size - naskipbytes, m_paacfile);
                }
                //srs_trace("on audio pkt pts:%u msg->payload:%p, msg->size:%d, skipbytes:%d\n", msg->header.timestamp, msg->payload, msg->size, skipbytes);
                //srs_trace_memory(msg->payload + naskipbytes, msg->size - naskipbytes > 32 ? 32 : msg->size - naskipbytes);
#ifdef ENABLE_WRITE_MEDIA_TEST
                static FILE* pdecfile = fopen("srsdecaac.data", "wb");
                if(pdecfile)
                {
                    fwrite(msg->payload, 1, msg->size, pdecfile);
                }
#endif
                //padec->AesDecrypt((unsigned char*)msg->payload + AAC_AES_ENC_SKIP_BYTES, (unsigned char*)msg->payload + AAC_AES_ENC_SKIP_BYTES, msg->size - AAC_AES_ENC_SKIP_BYTES);
#else
            if(RTMP_MSG_AudioMessage == msg->header.message_type && padec && msg->size > AAC_AES_ENC_SKIP_BYTES)
            {
                padec->AesDecrypt((unsigned char*)msg->payload + AAC_AES_ENC_SKIP_BYTES, (unsigned char*)msg->payload + AAC_AES_ENC_SKIP_BYTES, msg->size - AAC_AES_ENC_SKIP_BYTES);
#endif
                //srs_trace("after padec:%p->AesDecrypt", padec);
            }
            
            if(RTMP_MSG_VideoMessage == msg->header.message_type)
            {
#ifdef ENABLE_WRITE_MEDIA_TEST
                static FILE* pencfile = fopen("encavc.data", "wb");
                if(pencfile)
                {
                    int writelen = fwrite(msg->payload, 1, msg->size, pencfile);
                    srs_trace("write enc data, writelen:%d", writelen);
                }
                else
                {
                    srs_trace("open encavc.data file, pencfile:%p", pencfile);
                }
#endif
                int issequence = 0;
                int skipbytes = nvskipbytes;
                //srs_rtsp_debug("video pakcets, is_video_need_encrypt(msg->payload, msg->size:%d):%d && pvaesdec:%p, , msg->payload[skipbytes+1]:%0x, [2]:%0x, [3]:%0x", msg->size, (int)is_video_need_encrypt(msg->payload, msg->size, issequence), pvaesdec, (uint32_t)msg->payload[skipbytes+1], (uint32_t)msg->payload[skipbytes+2], (uint32_t)msg->payload[skipbytes+3]);
                //srs_trace_memory(msg->payload, msg->size);
                if(pencrecmuxer)
                {
                    pencrecmuxer->writeframe(codec_id_h264, msg->payload, msg->size, msg->header.timestamp);
                }
                uint8_t codec_id = msg->payload[0]&0xf;
                uint8_t frame_type = (msg->payload[0] >> 4)& 0x0F;
                /*if(SrsCodecVideoAVCTypeSequenceHeader == msg->payload[1] && SrsCodecVideoAVCFrameKeyFrame == frame_type)
                {
                    // sequence header comeing
                    srs_debug("sequence header timestamp:%" PRId64 "", msg->header.timestamp);
                    dump_memory("avcc", msg->payload, msg->size);
                }*/
                int dec_flag = 0;
#ifdef ENABLE_CHECK_XVC_DATA
                if(m_nbuf_size < msg->size)
                {
                    srs_freepa(m_pbuf_data);
                    m_nbuf_size = msg->size > 1024 * 256 ? msg->size : 1024 * 256;
                    m_pbuf_data = new char[m_nbuf_size];
                }
                if(m_pbuf_data && m_nbuf_size >= msg->size)
                {
                    memcpy(m_pbuf_data, msg->payload, msg->size);
                }
                if(m_nbuf_size < msg->size)
#endif
                if(bvfirst && SrsFlvCodec::video_is_sequence_header(msg->payload, msg->size))
                {
                    bvfirst = false;
                    //srs_trace("first frame, no decrypt, msg->size:%d\n", msg->size);
                }
#ifdef ENABLE_STD_AES_ENCRYPT
                else if(is_video_need_encrypt(msg->payload, msg->size, issequence) && pvaesdec)
                {
                    skipbytes = issequence ? 5 : nvskipbytes;
                    pvaesdec->encrypt((unsigned char*)msg->payload + skipbytes, (unsigned char*)msg->payload + skipbytes, msg->size - skipbytes);
                    dec_flag = 1;
                }
#else
                else if(is_video_need_encrypt(msg->payload, msg->size) && pvdec)
                {
                    pvdec->AesDecrypt((unsigned char*)msg->payload + AVC_AES_ENC_SKIP_BYTES, (unsigned char*)msg->payload + AVC_AES_ENC_SKIP_BYTES, msg->size - AVC_AES_ENC_SKIP_BYTES);
                    dec_flag = 1;
                }
#endif
#ifdef ENABLE_CHECK_XVC_DATA
                if(!SrsFlvDecoder::check_xvc_data(msg->payload, msg->size))
                {
                    srs_error("org data:");
                    srs_err_memory(m_pbuf_data, msg->size);
                    srs_error("Invalid xvc data, size:%d, pts:%" PRId64 ", dec_flag:%d, pvaesdec:%p", msg->size, msg->header.timestamp, dec_flag, pvaesdec);
                    srs_err_memory(msg->payload, msg->size);
                    char str[100];
                    sprintf(str, "%" PRId64 "_org.h264", msg->header.timestamp);
                    FILE* pfile = fopen(str, "wb");
                    if(pfile)
                    {
                        fwrite(m_pbuf_data, 1, msg->size, pfile);
                        fclose(pfile);
                    }
                    sprintf(str, "%" PRId64 "_dec_%d.h264", msg->header.timestamp, dec_flag);
                    pfile = fopen(str, "wb");
                    if(pfile)
                    {
                        fwrite(msg->payload, 1, msg->size, pfile);
                        fclose(pfile);
                    }
                }
#endif
                if(pdecrecmuxer)
                {
                    pdecrecmuxer->writeframe(codec_id_h264, msg->payload + nvskipbytes, msg->size - nvskipbytes, msg->header.timestamp);
                }

                if(m_pavcfile)
                {
                    std::string sh;
                    if(SrsCodecVideoAVCTypeSequenceHeader == msg->payload[1] && SrsCodecVideoAVCFrameKeyFrame == frame_type)
                    {
                        char* pextradata = msg->payload + skipbytes;
                        int extradata_size = msg->size - skipbytes;
                        srs_rtsp_debug("pextradata:%p, extradata_size:%d\n", pextradata, extradata_size);
                        //srs_rtsp_debug_memory(pextradata, extradata_size);
                        if(SrsCodecVideoAVC == codec_id)
                        {
                            lazy_avc_parser avc_parser;
                            int ret = avc_parser.demux_extradata(pextradata, extradata_size);
                            //srs_rtsp_debug("ret:%d = avc_parser.demux_extradata(msg->payload:%p, msg->size:%d)\n", ret, pextradata, extradata_size);
                            if(0 == ret)
                            {
                                sh = avc_parser.get_sequence_header();
                                //srs_rtsp_debug("ret:%d = avc_parser.get_sequence_header(), sh.size():%ld\n", ret, sh.size());
                                //srs_rtsp_debug_memory(sh.data(), sh.size());
                                int write_len = fwrite(sh.data(), 1, sh.size(), m_pavcfile);
                                srs_rtsp_debug("write_len:%d = fwrite(sh.data(), 1, sh.size():%d, m_pavcfile), ftell(m_pavcfile):%ld\n",  write_len, sh.size(), ftell(m_pavcfile));
                            }
                        }
                        else if(SrsCodecVideoHEVC == codec_id)
                        {
                            lazy_hevc_parser hevc_parser;
                            int ret = hevc_parser.demux_extradata(pextradata, extradata_size);
                            //srs_rtsp_debug("ret:%d = hevc_parser.demux_extradata(msg->payload:%p, msg->size:%d)\n", ret, pextradata, extradata_size);
                            //srs_rtsp_debug_memory(pextradata, extradata_size);
                            if(0 == ret)
                            {
                                sh = hevc_parser.get_sequence_header();
                                //srs_rtsp_debug("ret:%d = hevc_parser.get_sequence_header(), sh.size():%ld, ftell(m_pavcfile):%ld\n", ret, sh.size(), ftell(m_pavcfile));
                                //srs_rtsp_debug_memory(sh.data(), sh.size());
                                int write_len = fwrite(sh.data(), 1, sh.size(), m_pavcfile);
                                srs_rtsp_debug("write_len:%d = fwrite(sh.data(), 1, sh.size():%d, m_pavcfile), ftell(m_pavcfile):%ld\n",  write_len, sh.size(), ftell(m_pavcfile));
                            }
                        }
                        else
                        {
                            srs_error("Invalid codec data\n");
                        }
                    }
                    else
                    {
                        char start_code[4] = {0, 0, 0, 1};
                        fwrite(start_code, 1, sizeof(start_code), m_pavcfile);
                        fwrite(msg->payload + skipbytes + 4, 1, msg->size - skipbytes - 4, m_pavcfile);
                        //srs_rtsp_debug("writelen:%d = fwrite(msg->payload:%p + skipbytes:%d, 1, msg->size:%d - skipbytes, m_pavcfile:%p), ftell(m_pavcfile):%ld\n", writelen, msg->payload,  skipbytes + 4, msg->size - 4, m_pavcfile, ftell(m_pavcfile));
                        //srs_rtsp_debug_memory(msg->payload, 48);
                    }
                }
                //srs_rtsp_debug("on video pkt org pts:%u msg->payload:%p, msg->size:%d, skipbytes:%d, pvaesdec:%p\n", msg->header.timestamp, msg->payload, msg->size, skipbytes, pvaesdec);
                //srs_rtsp_debug_memory(msg->payload + skipbytes, msg->size - skipbytes > 32 ? 32 : msg->size - skipbytes);
#if 1
                uint8_t flv_codec_id = msg->payload[0]&0xf;
                int stream_type = 4;
                if(SrsCodecVideoHEVC == flv_codec_id)
                {
                    stream_type = 5;
                }
                lazy_xvc_stream xs(stream_type);
                int start_code = 0;
                int is_sc = (int)xs.is_start_code(msg->payload + skipbytes, msg->size - skipbytes, &start_code);
                //srs_trace("is_sc:%d = xs.is_start_code, flv_codec_id:%d, stream_type:%d\n", is_sc, (int)flv_codec_id, stream_type);
                if(is_sc)
                {
                    int frame_size = 0;
                    const char* pframe = xs.get_nalu_frame(msg->payload + skipbytes, msg->size - skipbytes, &frame_size);
                    //srs_trace("pframe:%p, msg->payload + skipbytes:%p, msg->size - skipbytes:%d, frame_size:%d\n", pframe, msg->payload + skipbytes, msg->size - skipbytes, frame_size);
                    if(pframe && frame_size > 0)
                    {
                        xs.initialize(msg->payload + skipbytes, frame_size);
                        xs.write_byte(frame_size, 4);
                        int offset = pframe - msg->payload;
                        //srs_rtsp_debug("xs.write_byte(frame_size:%d, 4), offset:%d\n", frame_size, offset);
                        if(frame_size != msg->size - offset)
                        {
                            srs_rtsp_debug("frame_size:%d != msg->size:%d - offset:%d\n", frame_size, msg->size, offset);
                            //assert(frame_size == msg->size - offset);
                        }
                        //srs_trace("on video pkt write framesize pts:%u msg->payload:%p, msg->size:%d, skipbytes:%d\n", msg->header.timestamp, msg->payload, msg->size, skipbytes);
                        //srs_trace_memory(msg->payload, 16);
                        if(pframe  != msg->payload + skipbytes + 4)
                        {
                            memmove(msg->payload + skipbytes + 4, pframe, frame_size);
                        }

                        //memmove(msg->payload + skipbytes + 4, pframe, frame_size);
                        frame_size += skipbytes + 4;
                        msg->size = frame_size;
                    }
                }
#endif
                //srs_trace("on video pkt mod pts:%u msg->payload:%p, msg->size:%d, skipbytes:%d\n", msg->header.timestamp, msg->payload, msg->size, skipbytes);
                //srs_trace_memory(msg->payload + nvskipbytes, msg->size - nvskipbytes > 32 ? 32 : msg->size - nvskipbytes);
#ifdef ENABLE_WRITE_MEDIA_TEST
                static FILE* pdecfile = fopen("decavc.data", "wb");
                if(pdecfile)
                {
                    int writelen = fwrite(msg->payload, 1, msg->size, pdecfile);
                    srs_trace("write dec data, writelen:%d", writelen);
                }
#endif
            }
#endif



            // add by dawson for media data write test
#ifdef ENABLE_WRITE_VIDEO_STREAM
            if(RTMP_MSG_VideoMessage == msg->header.message_type && pvdec)
            {
                /*if(NULL == pvfile)
                {
                    pvfile = fopen("./objs/nginx/html/svdec.h264", "wb");
                }*/
                    
                char adtshdr = {};
                if(pvfile)
                {
                    int writed = fwrite(&msg->size, 1, 4, pvfile);
                    writed = fwrite(msg->payload, 1, msg->size, pvfile);
                    srs_info("write video data msgtype:%d, msg size:%d, writed:%d", msg->header.message_type, msg->size, writed);
                }
            }
#endif
#ifdef ENABLE_WRITE_AUDIO_STREAM
            if(RTMP_MSG_AudioMessage == msg->header.message_type && padec)
            {
                /*if(NULL == pafile)
                {
                    pafile = fopen("./objs/nginx/html/sadec.aac", "wb");
                }*/
                    
                char adtshdr[7] = {0xff, 0xf9, 0x50, 0x40, 0x01, 0x7f, 0xfc};
                if(pafile)
                {
                    //int writed = fwrite(adtshdr, 1, 7, pafile);
                    int writed = fwrite(&msg->size, 1, 4, pafile);
                    writed = fwrite(msg->payload, 1, msg->size, pafile);
                    srs_info("write audio adts data, msgtype:%d, msg size:%d, writed:%d", msg->header.message_type, msg->size, writed);
                }
            }
#endif
           // srs_trace("%s media enc end msgtype:%d, msg size:%d, pts:%"PRId64, __FUNCTION__, msg->header.message_type, msg->size, msg->header.timestamp);

            // add end
        default:
            return ret;
    }
    
    srs_assert(packet);
    
    // always free the packet.
    SrsAutoFree(SrsPacket, packet);
    
    switch (msg->header.message_type) {
        case RTMP_MSG_WindowAcknowledgementSize: {
            SrsSetWindowAckSizePacket* pkt = dynamic_cast<SrsSetWindowAckSizePacket*>(packet);
            srs_assert(pkt != NULL);
            
            if (pkt->ackowledgement_window_size > 0) {
                in_ack_size.window = (uint32_t)pkt->ackowledgement_window_size;
                // @remark, we ignore this message, for user noneed to care.
                // but it's important for dev, for client/server will block if required 
                // ack msg not arrived.
                srs_info("set ack window size to %d", pkt->ackowledgement_window_size);
            } else {
                srs_warn("ignored. set ack window size is %d", pkt->ackowledgement_window_size);
            }
            break;
        }
        case RTMP_MSG_SetChunkSize: {
            SrsSetChunkSizePacket* pkt = dynamic_cast<SrsSetChunkSizePacket*>(packet);
            srs_assert(pkt != NULL);

            // for some server, the actual chunk size can greater than the max value(65536),
            // so we just warning the invalid chunk size, and actually use it is ok,
            // @see: https://github.com/ossrs/srs/issues/160
            if (pkt->chunk_size < SRS_CONSTS_RTMP_MIN_CHUNK_SIZE 
                || pkt->chunk_size > SRS_CONSTS_RTMP_MAX_CHUNK_SIZE) 
            {
                srs_warn("accept chunk=%d, should in [%d, %d], please see #160",
                    pkt->chunk_size, SRS_CONSTS_RTMP_MIN_CHUNK_SIZE,  SRS_CONSTS_RTMP_MAX_CHUNK_SIZE);
            }

            // @see: https://github.com/ossrs/srs/issues/541
            if (pkt->chunk_size < SRS_CONSTS_RTMP_MIN_CHUNK_SIZE) {
                ret = ERROR_RTMP_CHUNK_SIZE;
                tag_error(get_device_sn(), "chunk size should be %d+, value=%d. ret=%d",
                    SRS_CONSTS_RTMP_MIN_CHUNK_SIZE, pkt->chunk_size, ret);
                return ret;
            }
            
            in_chunk_size = pkt->chunk_size;
            srs_info("in.chunk=%d", pkt->chunk_size);

            break;
        }
        case RTMP_MSG_UserControlMessage: {
            SrsUserControlPacket* pkt = dynamic_cast<SrsUserControlPacket*>(packet);
            srs_assert(pkt != NULL);
            
            if (pkt->event_type == SrcPCUCSetBufferLength) {
                in_buffer_length = pkt->extra_data;
                srs_info("buffer=%d, in.ack=%d, out.ack=%d, in.chunk=%d, out.chunk=%d", pkt->extra_data,
                    in_ack_size.window, out_ack_size.window, in_chunk_size, out_chunk_size);
            }
            if (pkt->event_type == SrcPCUCPingRequest) {
                if ((ret = response_ping_message(pkt->event_data)) != ERROR_SUCCESS) {
                    return ret;
                }
            }
            break;
        }
        default:
            break;
    }
    
    return ret;
}

int SrsProtocol::on_send_packet(SrsMessageHeader* mh, SrsPacket* packet)
{
    int ret = ERROR_SUCCESS;
    
    // ignore raw bytes oriented RTMP message.
    if (packet == NULL) {
        return ret;
    }
    
    switch (mh->message_type) {
        case RTMP_MSG_SetChunkSize: {
            SrsSetChunkSizePacket* pkt = dynamic_cast<SrsSetChunkSizePacket*>(packet);
            out_chunk_size = pkt->chunk_size;
            srs_info("out.chunk=%d", pkt->chunk_size);
            break;
        }
        case RTMP_MSG_WindowAcknowledgementSize: {
            SrsSetWindowAckSizePacket* pkt = dynamic_cast<SrsSetWindowAckSizePacket*>(packet);
            out_ack_size.window = (uint32_t)pkt->ackowledgement_window_size;
            break;
        }
        case RTMP_MSG_AMF0CommandMessage:
        case RTMP_MSG_AMF3CommandMessage: {
            if (true) {
                SrsConnectAppPacket* pkt = dynamic_cast<SrsConnectAppPacket*>(packet);
                if (pkt) {
                    requests[pkt->transaction_id] = pkt->command_name;
                    break;
                }
            }
            if (true) {
                SrsCreateStreamPacket* pkt = dynamic_cast<SrsCreateStreamPacket*>(packet);
                if (pkt) {
                    requests[pkt->transaction_id] = pkt->command_name;
                    break;
                }
            }
            if (true) {
                SrsFMLEStartPacket* pkt = dynamic_cast<SrsFMLEStartPacket*>(packet);
                if (pkt) {
                    requests[pkt->transaction_id] = pkt->command_name;
                    break;
                }
            }
            break;
        }
        case RTMP_MSG_VideoMessage:
        case RTMP_MSG_AudioMessage:
            //print_debug_info();
        default:
            break;
    }
    
    return ret;
}

int SrsProtocol::response_acknowledgement_message()
{
    int ret = ERROR_SUCCESS;
    
    if (in_ack_size.window <= 0) {
        return ret;
    }
    
    // ignore when delta bytes not exceed half of window(ack size).
    uint32_t delta = (uint32_t)(skt->get_recv_bytes() - in_ack_size.nb_recv_bytes);
    if (delta < in_ack_size.window / 2) {
        return ret;
    }
    in_ack_size.nb_recv_bytes = skt->get_recv_bytes();
    
    // when the sequence number overflow, reset it.
    uint32_t sequence_number = in_ack_size.sequence_number + delta;
    if (sequence_number > 0xf0000000) {
        sequence_number = delta;
    }
    in_ack_size.sequence_number = sequence_number;
    
    SrsAcknowledgementPacket* pkt = new SrsAcknowledgementPacket();
    LB_ADD_MEM(pkt, sizeof(SrsAcknowledgementPacket));
    pkt->sequence_number = sequence_number;
    
    // cache the message and use flush to send.
    if (!auto_response_when_recv) {
        manual_response_queue.push_back(pkt);
        return ret;
    }
    
    // use underlayer api to send, donot flush again.
    if ((ret = do_send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(), "send acknowledgement failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("send acknowledgement success.");
    
    return ret;
}

int SrsProtocol::response_ping_message(int32_t timestamp)
{
    int ret = ERROR_SUCCESS;
    /*if(m_nhearbeat_count++%20 == 0)
    {
        srs_trace("devicesn:%s, get a ping request, response it. m_nhearbeat_count=%d", device_sn.c_str(), m_nhearbeat_count);
    }*/
    
    
    SrsUserControlPacket* pkt = new SrsUserControlPacket();
    LB_ADD_MEM(pkt, sizeof(SrsUserControlPacket));
    pkt->event_type = SrcPCUCPingResponse;
    pkt->event_data = timestamp;
    
    // cache the message and use flush to send.
    if (!auto_response_when_recv) {
        manual_response_queue.push_back(pkt);
        return ret;
    }
    
    // use underlayer api to send, donot flush again.
    if ((ret = do_send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(), "send ping response failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("send ping response success.");
    
    return ret;
}

void SrsProtocol::print_debug_info()
{
    if (show_debug_info) {
        show_debug_info = false;
        srs_trace("protocol in.buffer=%d, in.ack=%d, out.ack=%d, in.chunk=%d, out.chunk=%d", in_buffer_length,
            in_ack_size.window, out_ack_size.window, in_chunk_size, out_chunk_size);
    }
}

SrsChunkStream::SrsChunkStream(int _cid)
{
    fmt = 0;
    cid = _cid;
    extended_timestamp = false;
    msg = NULL;
    msg_count = 0;
}

SrsChunkStream::~SrsChunkStream()
{
    srs_freep(msg);
}

SrsRequest::SrsRequest()
{
    objectEncoding = RTMP_SIG_AMF0_VER;
    //duration = -1;
    args = NULL;
    llstart_timestamp = -1;
    llstop_timestamp  = -1;
    disconnect_type   = RTMP_DISCONNECT_BY_CLIENT;
    eipc_tigger_type  = e_tigger_type_unknow;
    eauth_type        = e_auth_type_unknow;
    timezone          = -1;
    dalarm_time       = 0;
    duration          = 0;
    dmajorImgTimestamp = 0;
    dminorImgTimestamp = 0;
    streamType        = e_push_stream_type_unkonwn;
}

SrsRequest::~SrsRequest()
{
    srs_freep(args);
}

SrsRequest* SrsRequest::copy()
{
    SrsRequest* cp = new SrsRequest();
    LB_ADD_MEM(cp, sizeof(SrsRequest));
    cp->ip = ip;
    cp->app = app;
    cp->objectEncoding = objectEncoding;
    cp->pageUrl = pageUrl;
    cp->host = host;
    cp->port = port;
    cp->param = param;
    cp->schema = schema;
    cp->stream = stream;
    cp->swfUrl = swfUrl;
    cp->tcUrl = tcUrl;
    cp->vhost = vhost;
    cp->duration = duration;
    // add by dawson for change hls m3u8 and ts slice
    cp->token = token;
    cp->appkey = appkey;
    cp->devicesn = devicesn;
    cp->datetime = datetime;
	cp->eipc_tigger_type = eipc_tigger_type;
    cp->eauth_type = eauth_type;
    cp->timezone = timezone;
    cp->llstart_timestamp = llstart_timestamp;
    cp->llstop_timestamp = llstop_timestamp;
    cp->disconnect_type = disconnect_type;
    cp->dalarm_time = dalarm_time;
    cp->sdkVersion = sdkVersion;
    cp->srsForwardHostName = srsForwardHostName;
    cp->naesKeyEncType = naesKeyEncType;
    cp->userid = userid;
    cp->streamType = streamType;
    cp->dmajorImgTimestamp = dmajorImgTimestamp;
    cp->dminorImgTimestamp = dminorImgTimestamp;
    // add end
    if (args) {
        cp->args = args->copy()->to_object();
    }
    
    return cp;
}

void SrsRequest::update_auth(SrsRequest* req)
{
    pageUrl = req->pageUrl;
    swfUrl = req->swfUrl;
    tcUrl = req->tcUrl;
    param = req->param;
    
    if (args) {
        srs_freep(args);
    }
    if (req->args) {
        args = req->args->copy()->to_object();
    }
    
    srs_info("update req of soruce for auth ok");
}

string SrsRequest::get_stream_url()
{
    return srs_generate_stream_url(vhost, app, stream);
}

void SrsRequest::strip()
{
    // remove the unsupported chars in names.
    host = srs_string_remove(host, "/ \n\r\t");
    vhost = srs_string_remove(vhost, "/ \n\r\t");
    app = srs_string_remove(app, " \n\r\t");
    stream = srs_string_remove(stream, " \n\r\t");
    
    // remove end slash of app/stream
    app = srs_string_trim_end(app, "/");
    stream = srs_string_trim_end(stream, "/");
    
    // remove start slash of app/stream
    app = srs_string_trim_start(app, "/");
    stream = srs_string_trim_start(stream, "/");
}

SrsRequest* SrsRequest::as_http()
{
    schema = "http";
    return this;
}

const char* get_device_sn(SrsRequest* req, int nbytes)
{
    if(req)
    {
        int pos = 0;
        int snlen = req->devicesn.length();
        if(snlen <= 0)
        {
            return NULL;
        }

        if(nbytes <= snlen && nbytes > 0)
        {
            pos = snlen - nbytes;
        }
        
        return req->devicesn.c_str() + pos;
    }
    
    return NULL;
}

SrsResponse::SrsResponse()
{
    stream_id = SRS_DEFAULT_SID;
}

SrsResponse::~SrsResponse()
{
}

string srs_client_type_string(SrsRtmpConnType type)
{
    switch (type) {
        case SrsRtmpConnPlay: return "Play";
        case SrsRtmpConnFlashPublish: return "flash-publish";
        case SrsRtmpConnFMLEPublish: return "fmle-publish";
        case SrsRtmpConnHaivisionPublish: return "haivision-publish";
        default: return "Unknown";
    }
}

bool srs_client_type_is_publish(SrsRtmpConnType type)
{
    return type != SrsRtmpConnPlay;
}

SrsHandshakeBytes::SrsHandshakeBytes()
{
    c0c1 = s0s1s2 = c2 = NULL;
}

SrsHandshakeBytes::~SrsHandshakeBytes()
{
    srs_freepa(c0c1);
    srs_freepa(s0s1s2);
    srs_freepa(c2);
}

int SrsHandshakeBytes::read_c0c1(ISrsProtocolReaderWriter* io)
{
    int ret = ERROR_SUCCESS;
    
    if (c0c1) {
        return ret;
    }
    
    ssize_t nsize;
    
    c0c1 = new char[1537];
    LB_ADD_MEM(c0c1, sizeof(char)*1537);
    if ((ret = io->read_fully(c0c1, 1537, &nsize)) != ERROR_SUCCESS) {
        //srs_warn("read c0c1 failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("read c0c1 success.");
    
    return ret;
}

int SrsHandshakeBytes::read_s0s1s2(ISrsProtocolReaderWriter* io)
{
    int ret = ERROR_SUCCESS;
    
    if (s0s1s2) {
        return ret;
    }
    
    ssize_t nsize;
    
    s0s1s2 = new char[3073];
    LB_ADD_MEM(s0s1s2, sizeof(char)*3073);
    if ((ret = io->read_fully(s0s1s2, 3073, &nsize)) != ERROR_SUCCESS) {
        srs_warn("read s0s1s2 failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("read s0s1s2 success.");
    
    return ret;
}

int SrsHandshakeBytes::read_c2(ISrsProtocolReaderWriter* io)
{
    int ret = ERROR_SUCCESS;
    
    if (c2) {
        return ret;
    }
    
    ssize_t nsize;
    
    c2 = new char[1536];
    LB_ADD_MEM(c2, sizeof(char)*1536);
    if ((ret = io->read_fully(c2, 1536, &nsize)) != ERROR_SUCCESS) {
        srs_warn("read c2 failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("read c2 success.");
    
    return ret;
}

int SrsHandshakeBytes::create_c0c1()
{
    int ret = ERROR_SUCCESS;
    
    if (c0c1) {
        return ret;
    }
    
    c0c1 = new char[1537];
    LB_ADD_MEM(c0c1, sizeof(char)*1537);
    srs_random_generate(c0c1, 1537);
    
    // plain text required.
    SrsStream stream;
    if ((ret = stream.initialize(c0c1, 9)) != ERROR_SUCCESS) {
        return ret;
    }
    stream.write_1bytes(0x03);
    stream.write_4bytes((int32_t)::time(NULL));
    stream.write_4bytes(0x00);
    
    return ret;
}

int SrsHandshakeBytes::create_s0s1s2(const char* c1)
{
    int ret = ERROR_SUCCESS;
    
    if (s0s1s2) {
        return ret;
    }
    
    s0s1s2 = new char[3073];
    LB_ADD_MEM(s0s1s2, sizeof(char)*3073);
    srs_random_generate(s0s1s2, 3073);
    
    // plain text required.
    SrsStream stream;
    if ((ret = stream.initialize(s0s1s2, 9)) != ERROR_SUCCESS) {
        return ret;
    }
    stream.write_1bytes(0x03);
    stream.write_4bytes((int32_t)::time(NULL));
    // s1 time2 copy from c1
    if (c0c1) {
        stream.write_bytes(c0c1 + 1, 4);
    }
    
    // if c1 specified, copy c1 to s2.
    // @see: https://github.com/ossrs/srs/issues/46
    if (c1) {
        memcpy(s0s1s2 + 1537, c1, 1536);
    }
    
    return ret;
}

int SrsHandshakeBytes::create_c2()
{
    int ret = ERROR_SUCCESS;
    
    if (c2) {
        return ret;
    }
    
    c2 = new char[1536];
    LB_ADD_MEM(c2, sizeof(char)*1536);
    srs_random_generate(c2, 1536);
    
    // time
    SrsStream stream;
    if ((ret = stream.initialize(c2, 8)) != ERROR_SUCCESS) {
        return ret;
    }
    stream.write_4bytes((int32_t)::time(NULL));
    // c2 time2 copy from s1
    if (s0s1s2) {
        stream.write_bytes(s0s1s2 + 1, 4);
    }
    
    return ret;
}

SrsRtmpClient::SrsRtmpClient(ISrsProtocolReaderWriter* skt)
{
    io = skt;
    protocol = new SrsProtocol(skt);
    LB_ADD_MEM(protocol, sizeof(SrsProtocol));
    hs_bytes = new SrsHandshakeBytes();
    LB_ADD_MEM(hs_bytes, sizeof(SrsHandshakeBytes));
}

SrsRtmpClient::~SrsRtmpClient()
{
    srs_freep(protocol);
    srs_freep(hs_bytes);
}

void SrsRtmpClient::set_recv_timeout(int64_t timeout_us)
{
    protocol->set_recv_timeout(timeout_us);
}

void SrsRtmpClient::set_send_timeout(int64_t timeout_us)
{
    protocol->set_send_timeout(timeout_us);
}

int64_t SrsRtmpClient::get_recv_bytes()
{
    return protocol->get_recv_bytes();
}

int64_t SrsRtmpClient::get_send_bytes()
{
    return protocol->get_send_bytes();
}

int SrsRtmpClient::recv_message(SrsCommonMessage** pmsg)
{
    return protocol->recv_message(pmsg);
}

int SrsRtmpClient::decode_message(SrsCommonMessage* msg, SrsPacket** ppacket)
{
    return protocol->decode_message(msg, ppacket);
}

int SrsRtmpClient::send_and_free_message(SrsSharedPtrMessage* msg, int stream_id)
{
    return protocol->send_and_free_message(msg, stream_id);
}

int SrsRtmpClient::send_and_free_messages(SrsSharedPtrMessage** msgs, int nb_msgs, int stream_id)
{
    return protocol->send_and_free_messages(msgs, nb_msgs, stream_id);
}

int SrsRtmpClient::send_and_free_packet(SrsPacket* packet, int stream_id)
{
    return protocol->send_and_free_packet(packet, stream_id);
}

bool SrsRtmpClient::is_readable()
{
    return io ? io->is_readable() : false;
}

int SrsRtmpClient::handshake()
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(hs_bytes);
    
    // maybe st has problem when alloc object on stack, always alloc object at heap.
    // @see https://github.com/ossrs/srs/issues/509
    SrsComplexHandshake* complex_hs = new SrsComplexHandshake();
    LB_ADD_MEM(complex_hs, sizeof(SrsComplexHandshake));
    //LB_ADD_MEM(complex_hs, sizeof(SrsComplexHandshake));
    SrsAutoFree(SrsComplexHandshake, complex_hs);
    
    if ((ret = complex_hs->handshake_with_server(hs_bytes, io)) != ERROR_SUCCESS) {
        if (ret == ERROR_RTMP_TRY_SIMPLE_HS) {
            // always alloc object at heap.
            // @see https://github.com/ossrs/srs/issues/509
            SrsSimpleHandshake* simple_hs = new SrsSimpleHandshake();
            LB_ADD_MEM(simple_hs, sizeof(SrsSimpleHandshake));
            SrsAutoFree(SrsSimpleHandshake, simple_hs);
            
            if ((ret = simple_hs->handshake_with_server(hs_bytes, io)) != ERROR_SUCCESS) {
                return ret;
            }
        }
        return ret;
    }
    
    srs_freep(hs_bytes);
    
    return ret;
}

int SrsRtmpClient::simple_handshake()
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(hs_bytes);
    
    SrsSimpleHandshake simple_hs;
    if ((ret = simple_hs.handshake_with_server(hs_bytes, io)) != ERROR_SUCCESS) {
        return ret;
    }
    
    srs_freep(hs_bytes);
    
    return ret;
}

int SrsRtmpClient::complex_handshake()
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(hs_bytes);
    
    SrsComplexHandshake complex_hs;
    if ((ret = complex_hs.handshake_with_server(hs_bytes, io)) != ERROR_SUCCESS) {
        return ret;
    }
    
    srs_freep(hs_bytes);
    
    return ret;
}

int SrsRtmpClient::connect_app(string app, string tc_url, SrsRequest* req, bool debug_srs_upnode)
{
    std::string srs_server_ip;
    std::string srs_server;
    std::string srs_primary;
    std::string srs_authors;
    std::string srs_version;
    int srs_id = 0;
    int srs_pid = 0;
    
    return connect_app2(app, tc_url, req, debug_srs_upnode,
        srs_server_ip, srs_server, srs_primary, srs_authors,
        srs_version, srs_id, srs_pid);
}

int SrsRtmpClient::connect_app2(
    string app, string tc_url, SrsRequest* req, bool debug_srs_upnode,
    string& srs_server_ip, string& srs_server, string& srs_primary,
    string& srs_authors, string& srs_version, int& srs_id,
    int& srs_pid
){
    int ret = ERROR_SUCCESS;
    
    // Connect(vhost, app)
    if (true) {
        SrsConnectAppPacket* pkt = new SrsConnectAppPacket();
        LB_ADD_MEM(pkt, sizeof(SrsConnectAppPacket));
        pkt->command_object->set("app", SrsAmf0Any::str(app.c_str()));
        pkt->command_object->set("flashVer", SrsAmf0Any::str("WIN 15,0,0,239"));
        if (req) {
            pkt->command_object->set("swfUrl", SrsAmf0Any::str(req->swfUrl.c_str()));
        } else {
            pkt->command_object->set("swfUrl", SrsAmf0Any::str());
        }
        if (req && req->tcUrl != "") {
            pkt->command_object->set("tcUrl", SrsAmf0Any::str(req->tcUrl.c_str()));
        } else {
            pkt->command_object->set("tcUrl", SrsAmf0Any::str(tc_url.c_str()));
        }
        pkt->command_object->set("fpad", SrsAmf0Any::boolean(false));
        pkt->command_object->set("capabilities", SrsAmf0Any::number(239));
        pkt->command_object->set("audioCodecs", SrsAmf0Any::number(3575));
        pkt->command_object->set("videoCodecs", SrsAmf0Any::number(252));
        pkt->command_object->set("videoFunction", SrsAmf0Any::number(1));
        pkt->command_object->set("streamType", SrsAmf0Any::number(req->streamType));
        if(!req->app.empty())
        {
            pkt->command_object->set("appname", SrsAmf0Any::str(req->app.c_str()));
        }

        if(!req->stream.empty())
        {
            pkt->command_object->set("streamname", SrsAmf0Any::str(req->stream.c_str()));
        }

        if(!req->devicesn.empty())
        {
            pkt->command_object->set("devicesn", SrsAmf0Any::str(req->devicesn.c_str()));
            //svt_trace(m_pLogTag, "set devicesn:%s", m_sDeviceSN.c_str());
        }
        if (req) {
            pkt->command_object->set("pageUrl", SrsAmf0Any::str(req->pageUrl.c_str()));
        } else {
            pkt->command_object->set("pageUrl", SrsAmf0Any::str());
        }
        pkt->command_object->set("objectEncoding", SrsAmf0Any::number(0));
        
        // @see https://github.com/ossrs/srs/issues/160
        // the debug_srs_upnode is config in vhost and default to true.
        if (debug_srs_upnode && req && req->args) {
            srs_freep(pkt->args);
            pkt->args = req->args->copy()->to_object();
        }
        
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            return ret;
        }
    }
    
    // Set Window Acknowledgement size(2500000)
    if (true) {
        SrsSetWindowAckSizePacket* pkt = new SrsSetWindowAckSizePacket();
        LB_ADD_MEM(pkt, sizeof(SrsSetWindowAckSizePacket));
        pkt->ackowledgement_window_size = 2500000;
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            return ret;
        }
    }
    
    // expect connect _result
    SrsCommonMessage* msg = NULL;
    SrsConnectAppResPacket* pkt = NULL;
    if ((ret = expect_message<SrsConnectAppResPacket>(&msg, &pkt)) != ERROR_SUCCESS) {
        srs_error("expect connect app response message failed. ret=%d", ret);
        return ret;
    }
    SrsAutoFree(SrsCommonMessage, msg);
    SrsAutoFree(SrsConnectAppResPacket, pkt);
    
    // server info
    SrsAmf0Any* data = pkt->info->get_property("data");
    if (data && data->is_ecma_array()) {
        SrsAmf0EcmaArray* arr = data->to_ecma_array();
        
        SrsAmf0Any* prop = NULL;
        if ((prop = arr->ensure_property_string("srs_primary")) != NULL) {
            srs_primary = prop->to_str();
        }
        if ((prop = arr->ensure_property_string("srs_authors")) != NULL) {
            srs_authors = prop->to_str();
        }
        if ((prop = arr->ensure_property_string("srs_version")) != NULL) {
            srs_version = prop->to_str();
        }
        if ((prop = arr->ensure_property_string("srs_server_ip")) != NULL) {
            srs_server_ip = prop->to_str();
        }
        if ((prop = arr->ensure_property_string("srs_server")) != NULL) {
            srs_server = prop->to_str();
        }
        if ((prop = arr->ensure_property_number("srs_id")) != NULL) {
            srs_id = (int)prop->to_number();
        }
        if ((prop = arr->ensure_property_number("srs_pid")) != NULL) {
            srs_pid = (int)prop->to_number();
        }
    }
    srs_trace("connected, version=%s, ip=%s, pid=%d, id=%d, dsu=%d",
              srs_version.c_str(), srs_server_ip.c_str(), srs_pid, srs_id, debug_srs_upnode);
    
    return ret;
}

int SrsRtmpClient::create_stream(int& stream_id)
{
    int ret = ERROR_SUCCESS;
    
    // CreateStream
    if (true) {
        SrsCreateStreamPacket* pkt = new SrsCreateStreamPacket();
        LB_ADD_MEM(pkt, sizeof(SrsCreateStreamPacket));
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            return ret;
        }
    }
    
    // CreateStream _result.
    if (true) {
        SrsCommonMessage* msg = NULL;
        SrsCreateStreamResPacket* pkt = NULL;
        if ((ret = expect_message<SrsCreateStreamResPacket>(&msg, &pkt)) != ERROR_SUCCESS) {
            srs_error("expect create stream response message failed. ret=%d", ret);
            return ret;
        }
        SrsAutoFree(SrsCommonMessage, msg);
        SrsAutoFree(SrsCreateStreamResPacket, pkt);
        srs_info("get create stream response message");
        
        stream_id = (int)pkt->stream_id;
    }
    
    return ret;
}

int SrsRtmpClient::play(string stream, int stream_id)
{
    int ret = ERROR_SUCCESS;
    
    // Play(stream)
    if (true) {
        SrsPlayPacket* pkt = new SrsPlayPacket();
        LB_ADD_MEM(pkt, sizeof(SrsPlayPacket));
        pkt->stream_name = stream;
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send play stream failed. "
                "stream=%s, stream_id=%d, ret=%d", 
                stream.c_str(), stream_id, ret);
            return ret;
        }
    }
    
    // SetBufferLength(1000ms)
    int buffer_length_ms = 1000;
    if (true) {
        SrsUserControlPacket* pkt = new SrsUserControlPacket();
        LB_ADD_MEM(pkt, sizeof(SrsUserControlPacket));
        pkt->event_type = SrcPCUCSetBufferLength;
        pkt->event_data = stream_id;
        pkt->extra_data = buffer_length_ms;
        
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send set buffer length failed. "
                "stream=%s, stream_id=%d, bufferLength=%d, ret=%d", 
                stream.c_str(), stream_id, buffer_length_ms, ret);
            return ret;
        }
    }
    
    // SetChunkSize
    if (true) {
        SrsSetChunkSizePacket* pkt = new SrsSetChunkSizePacket();
        LB_ADD_MEM(pkt, sizeof(SrsSetChunkSizePacket));
        pkt->chunk_size = SRS_CONSTS_RTMP_SRS_CHUNK_SIZE;
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send set chunk size failed. "
                "stream=%s, chunk_size=%d, ret=%d", 
                stream.c_str(), SRS_CONSTS_RTMP_SRS_CHUNK_SIZE, ret);
            return ret;
        }
    }
    
    return ret;
}

int SrsRtmpClient::publish(string stream, int stream_id)
{
    int ret = ERROR_SUCCESS;
    
    // SetChunkSize
    if (true) {
        SrsSetChunkSizePacket* pkt = new SrsSetChunkSizePacket();
        LB_ADD_MEM(pkt, sizeof(SrsSetChunkSizePacket));
        pkt->chunk_size = SRS_CONSTS_RTMP_SRS_CHUNK_SIZE;
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send set chunk size failed. "
                "stream=%s, chunk_size=%d, ret=%d", 
                stream.c_str(), SRS_CONSTS_RTMP_SRS_CHUNK_SIZE, ret);
            return ret;
        }
    }
    
    // publish(stream)
    if (true) {
        SrsPublishPacket* pkt = new SrsPublishPacket();
        LB_ADD_MEM(pkt, sizeof(SrsPublishPacket));
        pkt->stream_name = stream;
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send publish message failed. "
                "stream=%s, stream_id=%d, ret=%d", 
                stream.c_str(), stream_id, ret);
            return ret;
        }
    }
    
    return ret;
}

int SrsRtmpClient::fmle_publish(string stream, int& stream_id)
{
    stream_id = 0;
    
    int ret = ERROR_SUCCESS;
    
    // SrsFMLEStartPacket
    if (true) {
        SrsFMLEStartPacket* pkt = SrsFMLEStartPacket::create_release_stream(stream);
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send FMLE publish "
                "release stream failed. stream=%s, ret=%d", stream.c_str(), ret);
            return ret;
        }
    }
    
    // FCPublish
    if (true) {
        SrsFMLEStartPacket* pkt = SrsFMLEStartPacket::create_FC_publish(stream);
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send FMLE publish "
                "FCPublish failed. stream=%s, ret=%d", stream.c_str(), ret);
            return ret;
        }
    }
    
    // CreateStream
    if (true) {
        SrsCreateStreamPacket* pkt = new SrsCreateStreamPacket();
        LB_ADD_MEM(pkt, sizeof(SrsCreateStreamPacket));
        pkt->transaction_id = 4;
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send FMLE publish "
                "createStream failed. stream=%s, ret=%d", stream.c_str(), ret);
            return ret;
        }
    }
    
    // expect result of CreateStream
    if (true) {
        SrsCommonMessage* msg = NULL;
        SrsCreateStreamResPacket* pkt = NULL;
        if ((ret = expect_message<SrsCreateStreamResPacket>(&msg, &pkt)) != ERROR_SUCCESS) {
            srs_error("expect create stream response message failed. ret=%d", ret);
            return ret;
        }
        SrsAutoFree(SrsCommonMessage, msg);
        SrsAutoFree(SrsCreateStreamResPacket, pkt);
        srs_info("get create stream response message");

        stream_id = (int)pkt->stream_id;
    }
    
    // publish(stream)
    if (true) {
        SrsPublishPacket* pkt = new SrsPublishPacket();
        LB_ADD_MEM(pkt, sizeof(SrsPublishPacket));
        pkt->stream_name = stream;
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send FMLE publish publish failed. "
                "stream=%s, stream_id=%d, ret=%d", stream.c_str(), stream_id, ret);
            return ret;
        }
    }
    
    return ret;
}

SrsRtmpServer::SrsRtmpServer(ISrsProtocolReaderWriter* skt)
{
    io = skt;
    protocol = new SrsProtocol(skt);
    LB_ADD_MEM(protocol, sizeof(SrsProtocol));
    hs_bytes = new SrsHandshakeBytes();
    LB_ADD_MEM(hs_bytes, sizeof(SrsHandshakeBytes));
}

SrsRtmpServer::~SrsRtmpServer()
{
    srs_freep(protocol);
    srs_freep(hs_bytes);
}

void SrsRtmpServer::set_auto_response(bool v)
{
    protocol->set_auto_response(v);
}

#ifdef SRS_PERF_MERGED_READ
void SrsRtmpServer::set_merge_read(bool v, IMergeReadHandler* handler)
{
    protocol->set_merge_read(v, handler);
}

void SrsRtmpServer::set_recv_buffer(int buffer_size)
{
    protocol->set_recv_buffer(buffer_size);
}
#endif

void SrsRtmpServer::set_recv_timeout(int64_t timeout_us)
{
    protocol->set_recv_timeout(timeout_us);
}

int64_t SrsRtmpServer::get_recv_timeout()
{
    return protocol->get_recv_timeout();
}

void SrsRtmpServer::set_send_timeout(int64_t timeout_us)
{
    protocol->set_send_timeout(timeout_us);
}

int64_t SrsRtmpServer::get_send_timeout()
{
    return protocol->get_send_timeout();
}

int64_t SrsRtmpServer::get_recv_bytes()
{
    return protocol->get_recv_bytes();
}

int64_t SrsRtmpServer::get_send_bytes()
{
    return protocol->get_send_bytes();
}

int SrsRtmpServer::recv_message(SrsCommonMessage** pmsg)
{
    return protocol->recv_message(pmsg);
}

int SrsRtmpServer::decode_message(SrsCommonMessage* msg, SrsPacket** ppacket)
{
    return protocol->decode_message(msg, ppacket);
}

int SrsRtmpServer::send_and_free_message(SrsSharedPtrMessage* msg, int stream_id)
{
    return protocol->send_and_free_message(msg, stream_id);
}

int SrsRtmpServer::send_and_free_messages(SrsSharedPtrMessage** msgs, int nb_msgs, int stream_id)
{
    return protocol->send_and_free_messages(msgs, nb_msgs, stream_id);
}

int SrsRtmpServer::send_and_free_packet(SrsPacket* packet, int stream_id)
{
    return protocol->send_and_free_packet(packet, stream_id);
}

int SrsRtmpServer::handshake()
{
    int ret = ERROR_SUCCESS;
    srs_info("handshke begin");
    srs_assert(hs_bytes);
    
    SrsComplexHandshake complex_hs;
    if ((ret = complex_hs.handshake_with_client(hs_bytes, io)) != ERROR_SUCCESS) {
        if (ret == ERROR_RTMP_TRY_SIMPLE_HS) {
            SrsSimpleHandshake simple_hs;
            if ((ret = simple_hs.handshake_with_client(hs_bytes, io)) != ERROR_SUCCESS) {
                srs_error("ret:%d = simple_hs.handshake_with_client(hs_bytes:%p, io:%p) failed", ret, hs_bytes, io);
                return ret;
            }
        }
        return ret;
    }
    
    srs_freep(hs_bytes);
    srs_info("handshke end, ret:%d", ret);
    return ret;
}

int SrsRtmpServer::connect_app(SrsRequest* req)
{
    int ret = ERROR_SUCCESS;
    srs_info("connect app begin req:%p", req);
    SrsCommonMessage* msg = NULL;
    SrsConnectAppPacket* pkt = NULL;
    if ((ret = expect_message<SrsConnectAppPacket>(&msg, &pkt)) != ERROR_SUCCESS) {
        srs_error("expect connect app message failed. ret=%d", ret);
        return ret;
    }
    SrsAutoFree(SrsCommonMessage, msg);
    SrsAutoFree(SrsConnectAppPacket, pkt);
    srs_info("get connect app message");
    /*FILE* pfile = fopen("connectapp.data", "wb");
    if(pfile)
    {
        fwrite(msg->payload, 1, msg->size, pfile);
        fclose(pfile);
        srs_trace_memory(msg->payload, msg->size);
    }*/
    SrsAmf0Any* prop = NULL;
    if ((prop = pkt->command_object->ensure_property_string("tcUrl")) == NULL) {
        ret = ERROR_RTMP_REQ_CONNECT;
        srs_error("invalid request, must specifies the tcUrl. ret=%d", ret);
        return ret;
    }
    req->tcUrl = prop->to_str();
    
    if ((prop = pkt->command_object->ensure_property_string("pageUrl")) != NULL) {
        req->pageUrl = prop->to_str();
    }
    
    if ((prop = pkt->command_object->ensure_property_string("swfUrl")) != NULL) {
        req->swfUrl = prop->to_str();
    }
    
    if ((prop = pkt->command_object->ensure_property_number("objectEncoding")) != NULL) {
        req->objectEncoding = prop->to_number();
    }
    if((prop = pkt->command_object->ensure_property_string("sdkVersion")) != NULL)
    {
        req->sdkVersion = prop->to_str();
    }
    if ((prop = pkt->command_object->ensure_property_number("streamType")) != NULL) {
        req->streamType = prop->to_number();
        srs_debug("rtmp connect get streamType:%d\n", req->streamType);
    }
    else
    {
        req->streamType = 0;
        srs_debug("rtmp connect not get streamType, set default value\n", req->streamType);
    }
    
    pkt->command_object->get_property_string("token", req->token);
    pkt->command_object->get_property_string("devicesn", req->devicesn);
    pkt->command_object->get_property_string("appkey", req->appkey);
    pkt->command_object->get_property_string("userid", req->userid);
    pkt->command_object->get_property_string("appname", req->app);
    pkt->command_object->get_property_string("streamname", req->stream);
    srs_rtsp_debug("req->token:%s, req->devicesn:%s, req->appkey:%s, req->userid:%s\n", req->token.c_str(), req->devicesn.c_str(), req->appkey.c_str(), req->userid.c_str());
    if (pkt->args) {
        srs_freep(req->args);
        req->args = pkt->args->copy()->to_object();
        srs_info("copy edge traverse to origin auth args.");
    }
    
    srs_discovery_tc_url(req->tcUrl, 
        req->schema, req->host, req->vhost, req->app, req->stream, req->port,
        req->param, req->token);
    srs_info("req->tcUrl:%s, req->pageUrl:%s, req->swfUrl:%s, req->app:%s, req->stream:%s, req->param:%s, req->token:%s", req->tcUrl.c_str(), req->pageUrl.c_str(), req->swfUrl.c_str(), req->app.c_str(), req->stream.c_str(), req->param.c_str(), req->token.c_str());
    if(req->token.empty())
    {
        ret = parser_value_from_http_param(req->param, "token", req->token);
        srs_rtsp_debug("ret:%d = parser_value_from_http_param(req->param:%s, token, req->token:%s)", ret, req->param.c_str(), req->token.c_str());
    }
    // add by dawson for token authorization
    //prop = pkt->command_object->ensure_property_string("token");
    //srs_trace("prop:%p = pkt->command_object->ensure_property_string(token)", prop);
    /*if (prop)
    {
        req->token = prop->to_str();
        //srs_trace("req->token:%s = prop->to_str()", req->token.c_str());
        req->eauth_type = e_auth_type_no_server;
    }
    else*/
    if(req->token.empty())
    {
        //req->token = "d119eb8a06744065823964797a6ec8bf";
        srs_warn("push rtmp without token!");
        req->eauth_type = e_auth_type_no_token;
    }
    // add by dawson for devicesn authorization
    /*prop = pkt->command_object->ensure_property_string("devicesn");
    srs_trace("prop:%p = pkt->command_object->ensure_property_string(devicesn)", prop);
    if (prop)
    {
        req->devicesn = prop->to_str();
        srs_trace("req->devicesn:%s, req->stream:%s", req->devicesn.c_str(), req->stream.c_str());
    }
    else*/
    if(req->devicesn.empty())
    {
        req->devicesn = req->stream;
        
        // for test
        /*req->stream = "24d4c86a5e2986e22926f302b68fce28";
        req->app = "678d87d67eca1bfe1912b03b75bbc38b";
        req->token = "94a08da1fecbb6e8b46990538c7b50b2";*/
        srs_warn("push rtmp without devicesn:%s!", req->devicesn.c_str());
    }
    if(req->appkey.empty())
    {
        req->appkey = req->app;
    }
    if(protocol)
    {
        protocol->set_device_sn(req->devicesn);
    }

    if((prop = pkt->command_object->ensure_property_string("srs_forward_host_name")) != NULL)
    {
        req->srsForwardHostName = prop->to_str();
    }
    std::string token = req->app + ":" + req->stream + ":" + req->token + ":" + req->srsForwardHostName + ":" + req->devicesn;
    //srs_trace("token:%s\n", token.c_str());
    if((prop = pkt->command_object->ensure_property_string("srs_forward_token")) != NULL)
    {
        req->srsForwardToken = prop->to_str();
        std::string dec_token = decode_rsa_public_key(req->srsForwardToken);
        if(dec_token == token)
        {
            srs_rtsp_debug("dec_token:%s == token:%s\n", dec_token.c_str(), token.c_str());
        }
        else
        {
            srs_rtsp_debug("dec_token:%s != token:%s\n", dec_token.c_str(), token.c_str());
        }
    }

    srs_trace("connect app success. req->app:%s, req->stream:%s, req->token:%s, req->sdkVersion:%s, sn:%s",  req->app.c_str(), req->stream.c_str(), req->token.c_str(), req->sdkVersion.c_str(), req->devicesn.c_str());
    req->strip();
    //srs_trace("connect app end ret:%d", ret);
    return ret;
}

int SrsRtmpServer::set_window_ack_size(int ack_size)
{
    int ret = ERROR_SUCCESS;
    
    SrsSetWindowAckSizePacket* pkt = new SrsSetWindowAckSizePacket();
    LB_ADD_MEM(pkt, sizeof(SrsSetWindowAckSizePacket));
    pkt->ackowledgement_window_size = ack_size;
    if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
        srs_error("send ack size message failed. ret=%d", ret);
        return ret;
    }
    srs_info("send ack size message success. ack_size=%d", ack_size);
    
    return ret;
}

int SrsRtmpServer::set_peer_bandwidth(int bandwidth, int type)
{
    int ret = ERROR_SUCCESS;
    
    SrsSetPeerBandwidthPacket* pkt = new SrsSetPeerBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsSetPeerBandwidthPacket));
    pkt->bandwidth = bandwidth;
    pkt->type = type;
    if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
        srs_error("send set bandwidth message failed. ret=%d", ret);
        return ret;
    }
    srs_info("send set bandwidth message "
        "success. bandwidth=%d, type=%d", bandwidth, type);
    
    return ret;
}

int SrsRtmpServer::response_connect_app(SrsRequest *req, const char* server_ip)
{
    int ret = ERROR_SUCCESS;
    
    SrsConnectAppResPacket* pkt = new SrsConnectAppResPacket();
    LB_ADD_MEM(pkt, sizeof(SrsConnectAppResPacket));
    pkt->props->set("fmsVer", SrsAmf0Any::str("FMS/"RTMP_SIG_FMS_VER));
    pkt->props->set("capabilities", SrsAmf0Any::number(127));
    pkt->props->set("mode", SrsAmf0Any::number(1));
    
    pkt->info->set(StatusLevel, SrsAmf0Any::str(StatusLevelStatus));
    pkt->info->set(StatusCode, SrsAmf0Any::str(StatusCodeConnectSuccess));
    pkt->info->set(StatusDescription, SrsAmf0Any::str("Connection succeeded"));
    pkt->info->set("objectEncoding", SrsAmf0Any::number(req->objectEncoding));
    SrsAmf0EcmaArray* data = SrsAmf0Any::ecma_array();
    pkt->info->set("data", data);
    
    data->set("version", SrsAmf0Any::str(RTMP_SIG_FMS_VER));
    data->set("srs_sig", SrsAmf0Any::str(RTMP_SIG_SRS_KEY));
    data->set("srs_server", SrsAmf0Any::str(RTMP_SIG_SRS_SERVER));
    data->set("srs_license", SrsAmf0Any::str(RTMP_SIG_SRS_LICENSE));
    data->set("srs_role", SrsAmf0Any::str(RTMP_SIG_SRS_ROLE));
    data->set("srs_url", SrsAmf0Any::str(RTMP_SIG_SRS_URL));
    data->set("srs_version", SrsAmf0Any::str(RTMP_SIG_SRS_VERSION));
    data->set("srs_site", SrsAmf0Any::str(RTMP_SIG_SRS_WEB));
    data->set("srs_email", SrsAmf0Any::str(RTMP_SIG_SRS_EMAIL));
    data->set("srs_copyright", SrsAmf0Any::str(RTMP_SIG_SRS_COPYRIGHT));
    data->set("srs_primary", SrsAmf0Any::str(RTMP_SIG_SRS_PRIMARY));
    data->set("srs_authors", SrsAmf0Any::str(RTMP_SIG_SRS_AUTHROS));
    
    if (server_ip) {
        data->set("srs_server_ip", SrsAmf0Any::str(server_ip));
    }
    // for edge to directly get the id of client.
    data->set("srs_pid", SrsAmf0Any::number(getpid()));
    data->set("srs_id", SrsAmf0Any::number(_srs_context->get_id()));
    
    if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
        srs_error("send connect app response message failed. ret=%d", ret);
        return ret;
    }
    srs_info("send connect app response message success.");
    
    return ret;
}

void SrsRtmpServer::response_connect_reject(SrsRequest* /*req*/, const char* desc)
{
    int ret = ERROR_SUCCESS;
    
    SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
    LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
    pkt->data->set(StatusLevel, SrsAmf0Any::str(StatusLevelError));
    pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodeConnectRejected));
    pkt->data->set(StatusDescription, SrsAmf0Any::str(desc));
    
    if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
        srs_error("send connect app response rejected message failed. ret=%d", ret);
        return;
    }
    srs_info("send connect app response rejected message success.");

    return;
}

int SrsRtmpServer::on_bw_done()
{
    int ret = ERROR_SUCCESS;
    
    SrsOnBWDonePacket* pkt = new SrsOnBWDonePacket();
    LB_ADD_MEM(pkt, sizeof(SrsOnBWDonePacket));
    if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
        srs_error("send onBWDone message failed. ret=%d", ret);
        return ret;
    }
    srs_info("send onBWDone message success.");
    
    return ret;
}

int SrsRtmpServer::identify_client(int stream_id, SrsRtmpConnType& type, string& stream_name, std::string& param, double& duration)
{
    type = SrsRtmpConnUnknown;
    int ret = ERROR_SUCCESS;
    
    while (true) {
        SrsCommonMessage* msg = NULL;
        if ((ret = protocol->recv_message(&msg)) != ERROR_SUCCESS) {
            if (!srs_is_client_gracefully_close(ret)) {
                srs_error("recv identify client message failed. ret=%d", ret);
            }
            return ret;
        }

        SrsAutoFree(SrsCommonMessage, msg);
        SrsMessageHeader& h = msg->header;
        
        if (h.is_ackledgement() || h.is_set_chunk_size() || h.is_window_ackledgement_size() || h.is_user_control_message()) {
            continue;
        }
        
        if (!h.is_amf0_command() && !h.is_amf3_command()) {
            srs_trace("identify ignore messages except "
                "AMF0/AMF3 command message. type=%#x", h.message_type);
            continue;
        }
        
        SrsPacket* pkt = NULL;
        if ((ret = protocol->decode_message(msg, &pkt)) != ERROR_SUCCESS) {
            srs_error("identify decode message failed. ret=%d", ret);
            return ret;
        }
        
        SrsAutoFree(SrsPacket, pkt);
        
        if (dynamic_cast<SrsCreateStreamPacket*>(pkt)) {
            srs_info("identify client by create stream, play or flash publish.");
            return identify_create_stream_client(dynamic_cast<SrsCreateStreamPacket*>(pkt), stream_id, type, stream_name, param, duration);
        }
        if (dynamic_cast<SrsFMLEStartPacket*>(pkt)) {
            srs_info("identify client by releaseStream, fmle publish.");
            return identify_fmle_publish_client(dynamic_cast<SrsFMLEStartPacket*>(pkt), type, stream_name, param);
        }
        if (dynamic_cast<SrsPlayPacket*>(pkt)) {
            srs_info("level0 identify client by play.");
            return identify_play_client(dynamic_cast<SrsPlayPacket*>(pkt), type, stream_name, param, duration);
        }
        // call msg,
        // support response null first,
        // @see https://github.com/ossrs/srs/issues/106
        // TODO: FIXME: response in right way, or forward in edge mode.
        SrsCallPacket* call = dynamic_cast<SrsCallPacket*>(pkt);
        if (call) {
            SrsCallResPacket* res = new SrsCallResPacket(call->transaction_id);
            LB_ADD_MEM(res, sizeof(SrsCallResPacket));
            res->command_object = SrsAmf0Any::null();
            res->response = SrsAmf0Any::null();
            if ((ret = protocol->send_and_free_packet(res, 0)) != ERROR_SUCCESS) {
                if (!srs_is_system_control_error(ret) && !srs_is_client_gracefully_close(ret)) {
                    srs_warn("response call failed. ret=%d", ret);
                }
                return ret;
            }
            
            // For encoder of Haivision, it always send a _checkbw call message.
            // @Remark the next message is createStream, so we continue to identify it.
            // @see https://github.com/ossrs/srs/issues/844
            if (call->command_name == "_checkbw") {
                srs_info("Haivision encoder identified.");
                continue;
            }
            continue;
        }
        
        srs_trace("ignore AMF0/AMF3 command message.");
    }
    
    return ret;
}

int SrsRtmpServer::set_chunk_size(int chunk_size)
{
    int ret = ERROR_SUCCESS;
    
    SrsSetChunkSizePacket* pkt = new SrsSetChunkSizePacket();
    LB_ADD_MEM(pkt, sizeof(SrsSetChunkSizePacket));
    pkt->chunk_size = chunk_size;
    if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
        srs_error("send set chunk size message failed. ret=%d", ret);
        return ret;
    }
    srs_info("send set chunk size message success. chunk_size=%d", chunk_size);
    
    return ret;
}

int SrsRtmpServer::start_play(int stream_id)
{
    int ret = ERROR_SUCCESS;
    
    // StreamBegin
    if (true) {
        SrsUserControlPacket* pkt = new SrsUserControlPacket();
        LB_ADD_MEM(pkt, sizeof(SrsUserControlPacket));
        pkt->event_type = SrcPCUCStreamBegin;
        pkt->event_data = stream_id;
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send PCUC(StreamBegin) message failed. ret=%d", ret);
            return ret;
        }
        srs_info("send PCUC(StreamBegin) message success.");
    }
    
    // onStatus(NetStream.Play.Reset)
    if (true) {
        SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
        LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
        
        pkt->data->set(StatusLevel, SrsAmf0Any::str(StatusLevelStatus));
        pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodeStreamReset));
        pkt->data->set(StatusDescription, SrsAmf0Any::str("Playing and resetting stream."));
        pkt->data->set(StatusDetails, SrsAmf0Any::str("stream"));
        pkt->data->set(StatusClientId, SrsAmf0Any::str(RTMP_SIG_CLIENT_ID));
        
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send onStatus(NetStream.Play.Reset) message failed. ret=%d", ret);
            return ret;
        }
        srs_info("send onStatus(NetStream.Play.Reset) message success.");
    }
    
    // onStatus(NetStream.Play.Start)
    if (true) {
        SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
        LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
        pkt->data->set(StatusLevel, SrsAmf0Any::str(StatusLevelStatus));
        pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodeStreamStart));
        pkt->data->set(StatusDescription, SrsAmf0Any::str("Started playing stream."));
        pkt->data->set(StatusDetails, SrsAmf0Any::str("stream"));
        pkt->data->set(StatusClientId, SrsAmf0Any::str(RTMP_SIG_CLIENT_ID));
        
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send onStatus(NetStream.Play.Start) message failed. ret=%d", ret);
            return ret;
        }
        srs_info("send onStatus(NetStream.Play.Start) message success.");
    }
    
    // |RtmpSampleAccess(false, false)
    if (true) {
        SrsSampleAccessPacket* pkt = new SrsSampleAccessPacket();
        LB_ADD_MEM(pkt, sizeof(SrsSampleAccessPacket));
        // allow audio/video sample.
        // @see: https://github.com/ossrs/srs/issues/49
        pkt->audio_sample_access = true;
        pkt->video_sample_access = true;
        
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send |RtmpSampleAccess(false, false) message failed. ret=%d", ret);
            return ret;
        }
        srs_info("send |RtmpSampleAccess(false, false) message success.");
    }
    
    // onStatus(NetStream.Data.Start)
    if (true) {
        SrsOnStatusDataPacket* pkt = new SrsOnStatusDataPacket();
        LB_ADD_MEM(pkt, sizeof(SrsOnStatusDataPacket));
        pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodeDataStart));
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send onStatus(NetStream.Data.Start) message failed. ret=%d", ret);
            return ret;
        }
        srs_info("send onStatus(NetStream.Data.Start) message success.");
    }
    
    srs_info("start play success.");
    
    return ret;
}

int SrsRtmpServer::on_play_client_pause(int stream_id, bool is_pause)
{
    int ret = ERROR_SUCCESS;
    
    if (is_pause) {
        // onStatus(NetStream.Pause.Notify)
        if (true) {
            SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
            LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
            pkt->data->set(StatusLevel, SrsAmf0Any::str(StatusLevelStatus));
            pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodeStreamPause));
            pkt->data->set(StatusDescription, SrsAmf0Any::str("Paused stream."));
            
            if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
                srs_error("send onStatus(NetStream.Pause.Notify) message failed. ret=%d", ret);
                return ret;
            }
            srs_info("send onStatus(NetStream.Pause.Notify) message success.");
        }
        // StreamEOF
        if (true) {
            SrsUserControlPacket* pkt = new SrsUserControlPacket();
            LB_ADD_MEM(pkt, sizeof(SrsUserControlPacket));
            pkt->event_type = SrcPCUCStreamEOF;
            pkt->event_data = stream_id;
            
            if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
                srs_error("send PCUC(StreamEOF) message failed. ret=%d", ret);
                return ret;
            }
            srs_info("send PCUC(StreamEOF) message success.");
        }
    } else {
        // onStatus(NetStream.Unpause.Notify)
        if (true) {
            SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
            LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
            pkt->data->set(StatusLevel, SrsAmf0Any::str(StatusLevelStatus));
            pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodeStreamUnpause));
            pkt->data->set(StatusDescription, SrsAmf0Any::str("Unpaused stream."));
            
            if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
                srs_error("send onStatus(NetStream.Unpause.Notify) message failed. ret=%d", ret);
                return ret;
            }
            srs_info("send onStatus(NetStream.Unpause.Notify) message success.");
        }
        // StreanBegin
        if (true) {
            SrsUserControlPacket* pkt = new SrsUserControlPacket();
            LB_ADD_MEM(pkt, sizeof(SrsUserControlPacket));
            pkt->event_type = SrcPCUCStreamBegin;
            pkt->event_data = stream_id;
            
            if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
                srs_error("send PCUC(StreanBegin) message failed. ret=%d", ret);
                return ret;
            }
            srs_info("send PCUC(StreanBegin) message success.");
        }
    }
    
    return ret;
}

int SrsRtmpServer::start_fmle_publish(int stream_id)
{
    int ret = ERROR_SUCCESS;
    
    // FCPublish
    double fc_publish_tid = 0;
    if (true) {
        SrsCommonMessage* msg = NULL;
        SrsFMLEStartPacket* pkt = NULL;
        //srs_trace("before ret = expect_message<SrsFMLEStartPacket>(&msg, &pkt)");
        if ((ret = expect_message<SrsFMLEStartPacket>(&msg, &pkt)) != ERROR_SUCCESS) {
            srs_error("recv FCPublish message failed. ret=%d", ret);
            return ret;
        }
        //srs_trace("recv FCPublish request message success.");
        
        SrsAutoFree(SrsCommonMessage, msg);
        SrsAutoFree(SrsFMLEStartPacket, pkt);
    
        fc_publish_tid = pkt->transaction_id;
    }
    // FCPublish response
    if (true) {
        //srs_trace("before protocol->send_and_free_packet(pkt, 0) ->SrsFMLEStartResPacket");
        SrsFMLEStartResPacket* pkt = new SrsFMLEStartResPacket(fc_publish_tid);
        LB_ADD_MEM(pkt, sizeof(SrsFMLEStartResPacket));
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send FCPublish response message failed. ret=%d", ret);
            return ret;
        }
        //srs_trace("send FCPublish response message success.");
    }
    
    // createStream
    double create_stream_tid = 0;
    if (true) {
        SrsCommonMessage* msg = NULL;
        SrsCreateStreamPacket* pkt = NULL;
        //srs_trace("ret = expect_message<SrsCreateStreamPacket>(&msg, &pkt)");
        if ((ret = expect_message<SrsCreateStreamPacket>(&msg, &pkt)) != ERROR_SUCCESS) {
            srs_error("recv createStream message failed. ret=%d", ret);
            return ret;
        }
        //srs_trace("recv createStream request message success.");
        
        SrsAutoFree(SrsCommonMessage, msg);
        SrsAutoFree(SrsCreateStreamPacket, pkt);
        
        create_stream_tid = pkt->transaction_id;
    }
    // createStream response
    if (true) {
        SrsCreateStreamResPacket* pkt = new SrsCreateStreamResPacket(create_stream_tid, stream_id);
        LB_ADD_MEM(pkt, sizeof(SrsCreateStreamResPacket));
        //srs_trace("before protocol->send_and_free_packet(pkt, 0) ->SrsCreateStreamResPacket");
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send createStream response message failed. ret=%d", ret);
            return ret;
        }
        //srs_trace("send createStream response message success.");
    }
    
    // publish
    if (true) {
        SrsCommonMessage* msg = NULL;
        SrsPublishPacket* pkt = NULL;
        //srs_trace("before ret = expect_message<SrsPublishPacket>(&msg, &pkt)");
        if ((ret = expect_message<SrsPublishPacket>(&msg, &pkt)) != ERROR_SUCCESS) {
            srs_error("recv publish message failed. ret=%d", ret);
            return ret;
        }
        srs_info("recv publish request message success.");
        
        SrsAutoFree(SrsCommonMessage, msg);
        SrsAutoFree(SrsPublishPacket, pkt);
    }
    // publish response onFCPublish(NetStream.Publish.Start)
    if (true) {
        SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
        LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
        pkt->command_name = RTMP_AMF0_COMMAND_ON_FC_PUBLISH;
        pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodePublishStart));
        pkt->data->set(StatusDescription, SrsAmf0Any::str("Started publishing stream."));
        //srs_trace("before protocol->send_and_free_packet ->SrsOnStatusCallPacket");
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send onFCPublish(NetStream.Publish.Start) message failed. ret=%d", ret);
            return ret;
        }
        //srs_trace("send onFCPublish(NetStream.Publish.Start) message success.");
    }
    // publish response onStatus(NetStream.Publish.Start)
    if (true) {
        SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
        LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
        //srs_trace("before protocol->send_and_free_packet ->SrsOnStatusCallPacket2");
        pkt->data->set(StatusLevel, SrsAmf0Any::str(StatusLevelStatus));
        pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodePublishStart));
        pkt->data->set(StatusDescription, SrsAmf0Any::str("Started publishing stream."));
        pkt->data->set(StatusClientId, SrsAmf0Any::str(RTMP_SIG_CLIENT_ID));
        
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send onStatus(NetStream.Publish.Start) message failed. ret=%d", ret);
            return ret;
        }
        //srs_trace("send onStatus(NetStream.Publish.Start) message success.");
    }
    //srs_trace("FMLE publish success.");
    
    return ret;
}

int SrsRtmpServer::start_haivision_publish(int stream_id)
{
    int ret = ERROR_SUCCESS;
    
    // publish
    if (true) {
        SrsCommonMessage* msg = NULL;
        SrsPublishPacket* pkt = NULL;
        if ((ret = expect_message<SrsPublishPacket>(&msg, &pkt)) != ERROR_SUCCESS) {
            srs_error("recv publish message failed. ret=%d", ret);
            return ret;
        }
        srs_info("recv publish request message success.");
        
        SrsAutoFree(SrsCommonMessage, msg);
        SrsAutoFree(SrsPublishPacket, pkt);
    }
    
    // publish response onFCPublish(NetStream.Publish.Start)
    if (true) {
        SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
        LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
        pkt->command_name = RTMP_AMF0_COMMAND_ON_FC_PUBLISH;
        pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodePublishStart));
        pkt->data->set(StatusDescription, SrsAmf0Any::str("Started publishing stream."));
        
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send onFCPublish(NetStream.Publish.Start) message failed. ret=%d", ret);
            return ret;
        }
        srs_info("send onFCPublish(NetStream.Publish.Start) message success.");
    }
    
    // publish response onStatus(NetStream.Publish.Start)
    if (true) {
        SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
        LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
        pkt->data->set(StatusLevel, SrsAmf0Any::str(StatusLevelStatus));
        pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodePublishStart));
        pkt->data->set(StatusDescription, SrsAmf0Any::str("Started publishing stream."));
        pkt->data->set(StatusClientId, SrsAmf0Any::str(RTMP_SIG_CLIENT_ID));
        
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send onStatus(NetStream.Publish.Start) message failed. ret=%d", ret);
            return ret;
        }
        srs_info("send onStatus(NetStream.Publish.Start) message success.");
    }
    
    srs_info("Haivision publish success.");
    
    return ret;
}

int SrsRtmpServer::fmle_unpublish(int stream_id, double unpublish_tid)
{
    int ret = ERROR_SUCCESS;
    
    // publish response onFCUnpublish(NetStream.unpublish.Success)
    if (true) {
        SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
        LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
        pkt->command_name = RTMP_AMF0_COMMAND_ON_FC_UNPUBLISH;
        pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodeUnpublishSuccess));
        pkt->data->set(StatusDescription, SrsAmf0Any::str("Stop publishing stream."));
        
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            if (!srs_is_system_control_error(ret) && !srs_is_client_gracefully_close(ret)) {
                srs_error("send onFCUnpublish(NetStream.unpublish.Success) message failed. ret=%d", ret);
            }
            return ret;
        }
        srs_info("send onFCUnpublish(NetStream.unpublish.Success) message success.");
    }
    // FCUnpublish response
    if (true) {
        SrsFMLEStartResPacket* pkt = new SrsFMLEStartResPacket(unpublish_tid);
        LB_ADD_MEM(pkt, sizeof(SrsFMLEStartResPacket));
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            if (!srs_is_system_control_error(ret) && !srs_is_client_gracefully_close(ret)) {
                srs_error("send FCUnpublish response message failed. ret=%d", ret);
            }
            return ret;
        }
        srs_info("send FCUnpublish response message success.");
    }
    // publish response onStatus(NetStream.Unpublish.Success)
    if (true) {
        SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
        LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
        pkt->data->set(StatusLevel, SrsAmf0Any::str(StatusLevelStatus));
        pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodeUnpublishSuccess));
        pkt->data->set(StatusDescription, SrsAmf0Any::str("Stream is now unpublished"));
        pkt->data->set(StatusClientId, SrsAmf0Any::str(RTMP_SIG_CLIENT_ID));
        
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            if (!srs_is_system_control_error(ret) && !srs_is_client_gracefully_close(ret)) {
                srs_error("send onStatus(NetStream.Unpublish.Success) message failed. ret=%d", ret);
            }
            return ret;
        }
        srs_info("send onStatus(NetStream.Unpublish.Success) message success.");
    }
    
    srs_info("FMLE unpublish success.");
    
    return ret;
}

int SrsRtmpServer::start_flash_publish(int stream_id)
{
    int ret = ERROR_SUCCESS;
    
    // publish response onStatus(NetStream.Publish.Start)
    if (true) {
        SrsOnStatusCallPacket* pkt = new SrsOnStatusCallPacket();
        LB_ADD_MEM(pkt, sizeof(SrsOnStatusCallPacket));
        pkt->data->set(StatusLevel, SrsAmf0Any::str(StatusLevelStatus));
        pkt->data->set(StatusCode, SrsAmf0Any::str(StatusCodePublishStart));
        pkt->data->set(StatusDescription, SrsAmf0Any::str("Started publishing stream."));
        pkt->data->set(StatusClientId, SrsAmf0Any::str(RTMP_SIG_CLIENT_ID));
        
        if ((ret = protocol->send_and_free_packet(pkt, stream_id)) != ERROR_SUCCESS) {
            srs_error("send onStatus(NetStream.Publish.Start) message failed. ret=%d", ret);
            return ret;
        }
        srs_info("send onStatus(NetStream.Publish.Start) message success.");
    }
    
    srs_info("flash publish success.");
    
    return ret;
}

// add by dawson
int SrsRtmpServer::InitEncrypt(int type, int enctype,  const char* pkey, int skipbytes)
{
    //srs_trace("%s type:%d, enctype:%d, pkey:%s, protocol:%p", __FUNCTION__, type, enctype,  pkey, protocol);
    if(protocol)
    {
        return protocol->InitEncrypt(type, enctype, pkey, skipbytes);
    }
    return ERROR_PROTOCOLNOT_INIT;
}

void SrsRtmpServer::on_stream_start(write_data_cfg* pwdc)
{
    if(protocol)
    {
        return protocol->on_stream_start(pwdc);
    }
}

void SrsRtmpServer::on_stream_stop()
{
    if(protocol)
    {
        return protocol->on_stream_stop();
    }
}

#ifdef ENABLE_WRITE_VIDEO_STREAM
int SrsRtmpServer::SetVideoWriteDataPath(const std::string& vencpath, const std::string& vdatapath)
{
    if(protocol)
    {
        return protocol->SetVideoWriteDataPath(vencpath, vdatapath);
    }

    return ERROR_PROTOCOLNOT_INIT;
}
#endif
#ifdef ENABLE_WRITE_AUDIO_STREAM
int SrsRtmpServer::SetAudioWriteDataPath(const std::string& aencpath, const std::string& adatapath)
{
    if(protocol)
    {
        return protocol->SetAudioWriteDataPath(aencpath, adatapath);
    }
    return ERROR_PROTOCOLNOT_INIT;
}
#endif

int SrsRtmpServer::get_fd()
{
    if(protocol)
    {
        return protocol->get_fd();
    }
}
// add end

int SrsRtmpServer::identify_create_stream_client(SrsCreateStreamPacket* req, int stream_id, SrsRtmpConnType& type, string& stream_name, string& param, double& duration)
{
    int ret = ERROR_SUCCESS;
    
    if (true) {
        SrsCreateStreamResPacket* pkt = new SrsCreateStreamResPacket(req->transaction_id, stream_id);
        LB_ADD_MEM(pkt, sizeof(SrsCreateStreamResPacket));
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send createStream response message failed. ret=%d", ret);
            return ret;
        }
        srs_info("send createStream response message success.");
    }
    
    while (true) {
        SrsCommonMessage* msg = NULL;
        if ((ret = protocol->recv_message(&msg)) != ERROR_SUCCESS) {
            if (!srs_is_client_gracefully_close(ret)) {
                srs_error("recv identify client message failed. ret=%d", ret);
            }
            return ret;
        }

        SrsAutoFree(SrsCommonMessage, msg);
        SrsMessageHeader& h = msg->header;
        
        if (h.is_ackledgement() || h.is_set_chunk_size() || h.is_window_ackledgement_size() || h.is_user_control_message()) {
            continue;
        }
    
        if (!h.is_amf0_command() && !h.is_amf3_command()) {
            srs_trace("identify ignore messages except "
                "AMF0/AMF3 command message. type=%#x", h.message_type);
            continue;
        }
        
        SrsPacket* pkt = NULL;
        if ((ret = protocol->decode_message(msg, &pkt)) != ERROR_SUCCESS) {
            srs_error("identify decode message failed. ret=%d", ret);
            return ret;
        }

        SrsAutoFree(SrsPacket, pkt);
        
        if (dynamic_cast<SrsPlayPacket*>(pkt)) {
            srs_info("level1 identify client by play.");
            return identify_play_client(dynamic_cast<SrsPlayPacket*>(pkt), type, stream_name, param, duration);
        }
        if (dynamic_cast<SrsPublishPacket*>(pkt)) {
            srs_info("identify client by publish, falsh publish.");
            return identify_flash_publish_client(dynamic_cast<SrsPublishPacket*>(pkt), type, stream_name, param);
        }
        if (dynamic_cast<SrsCreateStreamPacket*>(pkt)) {
            srs_info("identify client by create stream, play or flash publish.");
            return identify_create_stream_client(dynamic_cast<SrsCreateStreamPacket*>(pkt), stream_id, type, stream_name, param, duration);
        }
        if (dynamic_cast<SrsFMLEStartPacket*>(pkt)) {
            srs_info("identify client by FCPublish, haivision publish.");
            return identify_haivision_publish_client(dynamic_cast<SrsFMLEStartPacket*>(pkt), type, stream_name, param);
        }
        
        srs_trace("ignore AMF0/AMF3 command message.");
    }
    
    return ret;
}

int SrsRtmpServer::identify_fmle_publish_client(SrsFMLEStartPacket* req, SrsRtmpConnType& type, string& stream_name, string& param)
{
    int ret = ERROR_SUCCESS;
    
    type = SrsRtmpConnFMLEPublish;
    stream_name = req->stream_name;
    
    // releaseStream response
    if (true) {
        SrsFMLEStartResPacket* pkt = new SrsFMLEStartResPacket(req->transaction_id);
        LB_ADD_MEM(pkt, sizeof(SrsFMLEStartResPacket));
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send releaseStream response message failed. ret=%d", ret);
            return ret;
        }
        srs_info("send releaseStream response message success.");
    }
    
    return ret;
}

int SrsRtmpServer::identify_haivision_publish_client(SrsFMLEStartPacket* req, SrsRtmpConnType& type, string& stream_name, string& param)
{
    int ret = ERROR_SUCCESS;
    
    type = SrsRtmpConnHaivisionPublish;
    size_t pos = req->stream_name.find_first_of("?");
    if(std::string::npos != pos)
    {
        param = req->stream_name.substr(pos+1);
        stream_name = req->stream_name.substr(0, pos);
    }
    else
    {
        stream_name = req->stream_name;
    }
    stream_name = req->stream_name;
    
    // FCPublish response
    if (true) {
        SrsFMLEStartResPacket* pkt = new SrsFMLEStartResPacket(req->transaction_id);
        LB_ADD_MEM(pkt, sizeof(SrsFMLEStartResPacket));
        if ((ret = protocol->send_and_free_packet(pkt, 0)) != ERROR_SUCCESS) {
            srs_error("send FCPublish response message failed. ret=%d", ret);
            return ret;
        }
        srs_info("send FCPublish response message success.");
    }
    
    return ret;
}

int SrsRtmpServer::identify_flash_publish_client(SrsPublishPacket* req, SrsRtmpConnType& type, string& stream_name, string& param)
{
    int ret = ERROR_SUCCESS;
    
    type = SrsRtmpConnFlashPublish;
    size_t pos = req->stream_name.find_first_of("?");
    if(std::string::npos != pos)
    {
        param = req->stream_name.substr(pos+1);
        stream_name = req->stream_name.substr(0, pos);
    }
    else
    {
        stream_name = req->stream_name;
    }
    stream_name = req->stream_name;
    
    return ret;
}

int SrsRtmpServer::identify_play_client(SrsPlayPacket* req, SrsRtmpConnType& type, string& stream_name, string& param, double& duration)
{
    int ret = ERROR_SUCCESS;
    
    type = SrsRtmpConnPlay;
    size_t pos = req->stream_name.find_first_of("?");
    if(std::string::npos != pos)
    {
        param = req->stream_name.substr(pos+1);
        stream_name = req->stream_name.substr(0, pos);
    }
    else
    {
        stream_name = req->stream_name;
    }
    
    //stream_name = req->stream_name;
    duration = req->duration;
    
    srs_info("identity client type=play, stream_name=%s, duration=%.2f", stream_name.c_str(), duration);

    return ret;
}

SrsConnectAppPacket::SrsConnectAppPacket()
{
    command_name = RTMP_AMF0_COMMAND_CONNECT;
    transaction_id = 1;
    command_object = SrsAmf0Any::object();
    // optional
    args = NULL;
}

SrsConnectAppPacket::~SrsConnectAppPacket()
{
    srs_freep(command_object);
    srs_freep(args);
}

int SrsConnectAppPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode connect command_name failed. ret=%d", ret);
        return ret;
    }
    if (command_name.empty() || command_name != RTMP_AMF0_COMMAND_CONNECT) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_error("amf0 decode connect command_name failed. "
            "command_name=%s, ret=%d", command_name.c_str(), ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode connect transaction_id failed. ret=%d", ret);
        return ret;
    }
    
    // some client donot send id=1.0, so we only warn user if not match.
    if (transaction_id != 1.0) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_warn("amf0 decode connect transaction_id failed. "
            "required=%.1f, actual=%.1f, ret=%d", 1.0, transaction_id, ret);
        ret = ERROR_SUCCESS;
    }
    
    if ((ret = command_object->read(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode connect command_object failed. ret=%d", ret);
        return ret;
    }
    
    if (!stream->empty()) {
        srs_freep(args);
        
        // see: https://github.com/ossrs/srs/issues/186
        // the args maybe any amf0, for instance, a string. we should drop if not object.
        SrsAmf0Any* any = NULL;
        if ((ret = SrsAmf0Any::discovery(stream, &any)) != ERROR_SUCCESS) {
            srs_error("amf0 find connect args failed. ret=%d", ret);
            return ret;
        }
        srs_assert(any);
        
        // read the instance
        if ((ret = any->read(stream)) != ERROR_SUCCESS) {
            srs_error("amf0 decode connect args failed. ret=%d", ret);
            srs_freep(any);
            return ret;
        }
        
        // drop when not an AMF0 object.
        if (!any->is_object()) {
            srs_warn("drop the args, see: '4.1.1. connect', marker=%#x", any->marker);
            srs_freep(any);
        } else {
            args = any->to_object();
        }
    }
    
    srs_info("amf0 decode connect packet success");
    
    return ret;
}

int SrsConnectAppPacket::get_prefer_cid()
{
    return RTMP_CID_OverConnection;
}

int SrsConnectAppPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsConnectAppPacket::get_size()
{
    int size = 0;
    
    size += SrsAmf0Size::str(command_name);
    size += SrsAmf0Size::number();
    size += SrsAmf0Size::object(command_object);
    if (args) {
        size += SrsAmf0Size::object(args);
    }
    
    return size;
}

int SrsConnectAppPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = command_object->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode command_object failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_object success.");
    
    if (args && (ret = args->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode args failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode args success.");
    
    srs_info("encode connect app request packet success.");
    
    return ret;
}

SrsConnectAppResPacket::SrsConnectAppResPacket()
{
    command_name = RTMP_AMF0_COMMAND_RESULT;
    transaction_id = 1;
    props = SrsAmf0Any::object();
    info = SrsAmf0Any::object();
}

SrsConnectAppResPacket::~SrsConnectAppResPacket()
{
    srs_freep(props);
    srs_freep(info);
}

int SrsConnectAppResPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode connect command_name failed. ret=%d", ret);
        return ret;
    }
    if (command_name.empty() || command_name != RTMP_AMF0_COMMAND_RESULT) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_error("amf0 decode connect command_name failed. "
            "command_name=%s, ret=%d", command_name.c_str(), ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode connect transaction_id failed. ret=%d", ret);
        return ret;
    }
    
    // some client donot send id=1.0, so we only warn user if not match.
    if (transaction_id != 1.0) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_warn("amf0 decode connect transaction_id failed. "
            "required=%.1f, actual=%.1f, ret=%d", 1.0, transaction_id, ret);
        ret = ERROR_SUCCESS;
    }
    
    // for RED5(1.0.6), the props is NULL, we must ignore it.
    // @see https://github.com/ossrs/srs/issues/418
    if (!stream->empty()) {
        SrsAmf0Any* p = NULL;
        if ((ret = srs_amf0_read_any(stream, &p)) != ERROR_SUCCESS) {
            srs_error("amf0 decode connect props failed. ret=%d", ret);
            return ret;
        }
        
        // ignore when props is not amf0 object.
        if (!p->is_object()) {
            srs_warn("ignore connect response props marker=%#x.", (u_int8_t)p->marker);
            srs_freep(p);
        } else {
            srs_freep(props);
            props = p->to_object();
            srs_info("accept amf0 object connect response props");
        }
    }
    
    if ((ret = info->read(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode connect info failed. ret=%d", ret);
        return ret;
    }
    
    srs_info("amf0 decode connect response packet success");
    
    return ret;
}

int SrsConnectAppResPacket::get_prefer_cid()
{
    return RTMP_CID_OverConnection;
}

int SrsConnectAppResPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsConnectAppResPacket::get_size()
{
    return SrsAmf0Size::str(command_name) + SrsAmf0Size::number() 
        + SrsAmf0Size::object(props) + SrsAmf0Size::object(info);
}

int SrsConnectAppResPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = props->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode props failed. ret=%d", ret);
        return ret;
    }

    srs_verbose("encode props success.");
    
    if ((ret = info->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode info failed. ret=%d", ret);
        return ret;
    }

    srs_verbose("encode info success.");
    
    srs_info("encode connect app response packet success.");
    
    return ret;
}

SrsCallPacket::SrsCallPacket()
{
    command_name = "";
    transaction_id = 0;
    command_object = NULL;
    arguments = NULL;
}

SrsCallPacket::~SrsCallPacket()
{
    srs_freep(command_object);
    srs_freep(arguments);
}

int SrsCallPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode call command_name failed. ret=%d", ret);
        return ret;
    }
    if (command_name.empty()) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_error("amf0 decode call command_name failed. "
            "command_name=%s, ret=%d", command_name.c_str(), ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode call transaction_id failed. ret=%d", ret);
        return ret;
    }
    
    srs_freep(command_object);
    if ((ret = SrsAmf0Any::discovery(stream, &command_object)) != ERROR_SUCCESS) {
        srs_error("amf0 discovery call command_object failed. ret=%d", ret);
        return ret;
    }
    if ((ret = command_object->read(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode call command_object failed. ret=%d", ret);
        return ret;
    }
    
    if (!stream->empty()) {
        srs_freep(arguments);
        if ((ret = SrsAmf0Any::discovery(stream, &arguments)) != ERROR_SUCCESS) {
            srs_error("amf0 discovery call arguments failed. ret=%d", ret);
            return ret;
        }
        if ((ret = arguments->read(stream)) != ERROR_SUCCESS) {
            srs_error("amf0 decode call arguments failed. ret=%d", ret);
            return ret;
        }
    }
    
    srs_info("amf0 decode call packet success");
    
    return ret;
}

int SrsCallPacket::get_prefer_cid()
{
    return RTMP_CID_OverConnection;
}

int SrsCallPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsCallPacket::get_size()
{
    int size = 0;
    
    size += SrsAmf0Size::str(command_name) + SrsAmf0Size::number();
    
    if (command_object) {
        size += command_object->total_size();
    }
    
    if (arguments) {
        size += arguments->total_size();
    }
    
    return size;
}

int SrsCallPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if (command_object && (ret = command_object->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode command_object failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_object success.");
    
    if (arguments && (ret = arguments->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode arguments failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode arguments success.");
    
    srs_info("encode create stream request packet success.");
    
    return ret;
}

SrsCallResPacket::SrsCallResPacket(double _transaction_id)
{
    command_name = RTMP_AMF0_COMMAND_RESULT;
    transaction_id = _transaction_id;
    command_object = NULL;
    response = NULL;
}

SrsCallResPacket::~SrsCallResPacket()
{
    srs_freep(command_object);
    srs_freep(response);
}

int SrsCallResPacket::get_prefer_cid()
{
    return RTMP_CID_OverConnection;
}

int SrsCallResPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsCallResPacket::get_size()
{
    int size = 0;
    
    size += SrsAmf0Size::str(command_name) + SrsAmf0Size::number();
    
    if (command_object) {
        size += command_object->total_size();
    }
    
    if (response) {
        size += response->total_size();
    }
    
    return size;
}

int SrsCallResPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if (command_object && (ret = command_object->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode command_object failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_object success.");
    
    if (response && (ret = response->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode response failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode response success.");
    
    
    srs_info("encode call response packet success.");
    
    return ret;
}

SrsCreateStreamPacket::SrsCreateStreamPacket()
{
    command_name = RTMP_AMF0_COMMAND_CREATE_STREAM;
    transaction_id = 2;
    command_object = SrsAmf0Any::null();
}

SrsCreateStreamPacket::~SrsCreateStreamPacket()
{
    srs_freep(command_object);
}

int SrsCreateStreamPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode createStream command_name failed. ret=%d", ret);
        return ret;
    }
    if (command_name.empty() || command_name != RTMP_AMF0_COMMAND_CREATE_STREAM) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_error("amf0 decode createStream command_name failed. "
            "command_name=%s, ret=%d", command_name.c_str(), ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode createStream transaction_id failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_null(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode createStream command_object failed. ret=%d", ret);
        return ret;
    }
    
    srs_info("amf0 decode createStream packet success");
    
    return ret;
}

int SrsCreateStreamPacket::get_prefer_cid()
{
    return RTMP_CID_OverConnection;
}

int SrsCreateStreamPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsCreateStreamPacket::get_size()
{
    return SrsAmf0Size::str(command_name) + SrsAmf0Size::number()
        + SrsAmf0Size::null();
}

int SrsCreateStreamPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = srs_amf0_write_null(stream)) != ERROR_SUCCESS) {
        srs_error("encode command_object failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_object success.");
    
    srs_info("encode create stream request packet success.");
    
    return ret;
}

SrsCreateStreamResPacket::SrsCreateStreamResPacket(double _transaction_id, double _stream_id)
{
    command_name = RTMP_AMF0_COMMAND_RESULT;
    transaction_id = _transaction_id;
    command_object = SrsAmf0Any::null();
    stream_id = _stream_id;
}

SrsCreateStreamResPacket::~SrsCreateStreamResPacket()
{
    srs_freep(command_object);
}

int SrsCreateStreamResPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode createStream command_name failed. ret=%d", ret);
        return ret;
    }
    if (command_name.empty() || command_name != RTMP_AMF0_COMMAND_RESULT) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_error("amf0 decode createStream command_name failed. "
            "command_name=%s, ret=%d", command_name.c_str(), ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode createStream transaction_id failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_null(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode createStream command_object failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, stream_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode createStream stream_id failed. ret=%d", ret);
        return ret;
    }
    
    srs_info("amf0 decode createStream response packet success");
    
    return ret;
}

int SrsCreateStreamResPacket::get_prefer_cid()
{
    return RTMP_CID_OverConnection;
}

int SrsCreateStreamResPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsCreateStreamResPacket::get_size()
{
    return SrsAmf0Size::str(command_name) + SrsAmf0Size::number()
        + SrsAmf0Size::null() + SrsAmf0Size::number();
}

int SrsCreateStreamResPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = srs_amf0_write_null(stream)) != ERROR_SUCCESS) {
        srs_error("encode command_object failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_object success.");
    
    if ((ret = srs_amf0_write_number(stream, stream_id)) != ERROR_SUCCESS) {
        srs_error("encode stream_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode stream_id success.");
    
    
    srs_info("encode createStream response packet success.");
    
    return ret;
}

SrsCloseStreamPacket::SrsCloseStreamPacket()
{
    command_name = RTMP_AMF0_COMMAND_CLOSE_STREAM;
    transaction_id = 0;
    command_object = SrsAmf0Any::null();
}

SrsCloseStreamPacket::~SrsCloseStreamPacket()
{
    srs_freep(command_object);
}

int SrsCloseStreamPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode closeStream command_name failed. ret=%d", ret);
        return ret;
    }

    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode closeStream transaction_id failed. ret=%d", ret);
        return ret;
    }

    if ((ret = srs_amf0_read_null(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode closeStream command_object failed. ret=%d", ret);
        return ret;
    }
    srs_info("amf0 decode closeStream packet success");

    return ret;
}

SrsFMLEStartPacket::SrsFMLEStartPacket()
{
    command_name = RTMP_AMF0_COMMAND_RELEASE_STREAM;
    transaction_id = 0;
    command_object = SrsAmf0Any::null();
}

SrsFMLEStartPacket::~SrsFMLEStartPacket()
{
    srs_freep(command_object);
}

int SrsFMLEStartPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode FMLE start command_name failed. ret=%d", ret);
        return ret;
    }
    if (command_name.empty() 
        || (command_name != RTMP_AMF0_COMMAND_RELEASE_STREAM 
        && command_name != RTMP_AMF0_COMMAND_FC_PUBLISH
        && command_name != RTMP_AMF0_COMMAND_UNPUBLISH)
    ) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_error("amf0 decode FMLE start command_name failed. "
            "command_name=%s, ret=%d", command_name.c_str(), ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode FMLE start transaction_id failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_null(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode FMLE start command_object failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_string(stream, stream_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode FMLE start stream_name failed. ret=%d", ret);
        return ret;
    }
    
    srs_info("amf0 decode FMLE start packet success");
    
    return ret;
}

int SrsFMLEStartPacket::get_prefer_cid()
{
    return RTMP_CID_OverConnection;
}

int SrsFMLEStartPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsFMLEStartPacket::get_size()
{
    return SrsAmf0Size::str(command_name) + SrsAmf0Size::number()
        + SrsAmf0Size::null() + SrsAmf0Size::str(stream_name);
}

int SrsFMLEStartPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = srs_amf0_write_null(stream)) != ERROR_SUCCESS) {
        srs_error("encode command_object failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_object success.");
    
    if ((ret = srs_amf0_write_string(stream, stream_name)) != ERROR_SUCCESS) {
        srs_error("encode stream_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode stream_name success.");
    
    
    srs_info("encode FMLE start response packet success.");
    
    return ret;
}

SrsFMLEStartPacket* SrsFMLEStartPacket::create_release_stream(string stream)
{
    SrsFMLEStartPacket* pkt = new SrsFMLEStartPacket();
    LB_ADD_MEM(pkt, sizeof(SrsFMLEStartPacket));
    pkt->command_name = RTMP_AMF0_COMMAND_RELEASE_STREAM;
    pkt->transaction_id = 2;
    pkt->stream_name = stream;
    
    return pkt;
}

SrsFMLEStartPacket* SrsFMLEStartPacket::create_FC_publish(string stream)
{
    SrsFMLEStartPacket* pkt = new SrsFMLEStartPacket();
    LB_ADD_MEM(pkt, sizeof(SrsFMLEStartPacket));
    pkt->command_name = RTMP_AMF0_COMMAND_FC_PUBLISH;
    pkt->transaction_id = 3;
    pkt->stream_name = stream;
    
    return pkt;
}

SrsFMLEStartResPacket::SrsFMLEStartResPacket(double _transaction_id)
{
    command_name = RTMP_AMF0_COMMAND_RESULT;
    transaction_id = _transaction_id;
    command_object = SrsAmf0Any::null();
    args = SrsAmf0Any::undefined();
}

SrsFMLEStartResPacket::~SrsFMLEStartResPacket()
{
    srs_freep(command_object);
    srs_freep(args);
}

int SrsFMLEStartResPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode FMLE start response command_name failed. ret=%d", ret);
        return ret;
    }
    if (command_name.empty() || command_name != RTMP_AMF0_COMMAND_RESULT) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_error("amf0 decode FMLE start response command_name failed. "
            "command_name=%s, ret=%d", command_name.c_str(), ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode FMLE start response transaction_id failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_null(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode FMLE start response command_object failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_undefined(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode FMLE start response stream_id failed. ret=%d", ret);
        return ret;
    }
    
    srs_info("amf0 decode FMLE start packet success");
    
    return ret;
}

int SrsFMLEStartResPacket::get_prefer_cid()
{
    return RTMP_CID_OverConnection;
}

int SrsFMLEStartResPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsFMLEStartResPacket::get_size()
{
    return SrsAmf0Size::str(command_name) + SrsAmf0Size::number()
        + SrsAmf0Size::null() + SrsAmf0Size::undefined();
}

int SrsFMLEStartResPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = srs_amf0_write_null(stream)) != ERROR_SUCCESS) {
        srs_error("encode command_object failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_object success.");
    
    if ((ret = srs_amf0_write_undefined(stream)) != ERROR_SUCCESS) {
        srs_error("encode args failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode args success.");
    
    
    srs_info("encode FMLE start response packet success.");
    
    return ret;
}

SrsPublishPacket::SrsPublishPacket()
{
    command_name = RTMP_AMF0_COMMAND_PUBLISH;
    transaction_id = 0;
    command_object = SrsAmf0Any::null();
    type = "live";
}

SrsPublishPacket::~SrsPublishPacket()
{
    srs_freep(command_object);
}

int SrsPublishPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode publish command_name failed. ret=%d", ret);
        return ret;
    }
    if (command_name.empty() || command_name != RTMP_AMF0_COMMAND_PUBLISH) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_error("amf0 decode publish command_name failed. "
            "command_name=%s, ret=%d", command_name.c_str(), ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode publish transaction_id failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_null(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode publish command_object failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_string(stream, stream_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode publish stream_name failed. ret=%d", ret);
        return ret;
    }
    
    if (!stream->empty() && (ret = srs_amf0_read_string(stream, type)) != ERROR_SUCCESS) {
        srs_error("amf0 decode publish type failed. ret=%d", ret);
        return ret;
    }
    
    srs_info("amf0 decode publish packet success");
    
    return ret;
}

int SrsPublishPacket::get_prefer_cid()
{
    return RTMP_CID_OverStream;
}

int SrsPublishPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsPublishPacket::get_size()
{
    return SrsAmf0Size::str(command_name) + SrsAmf0Size::number()
        + SrsAmf0Size::null() + SrsAmf0Size::str(stream_name)
        + SrsAmf0Size::str(type);
}

int SrsPublishPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = srs_amf0_write_null(stream)) != ERROR_SUCCESS) {
        srs_error("encode command_object failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_object success.");
    
    if ((ret = srs_amf0_write_string(stream, stream_name)) != ERROR_SUCCESS) {
        srs_error("encode stream_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode stream_name success.");
    
    if ((ret = srs_amf0_write_string(stream, type)) != ERROR_SUCCESS) {
        srs_error("encode type failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode type success.");
    
    srs_info("encode play request packet success.");
    
    return ret;
}

SrsPausePacket::SrsPausePacket()
{
    command_name = RTMP_AMF0_COMMAND_PAUSE;
    transaction_id = 0;
    command_object = SrsAmf0Any::null();

    time_ms = 0;
    is_pause = true;
}

SrsPausePacket::~SrsPausePacket()
{
    srs_freep(command_object);
}

int SrsPausePacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode pause command_name failed. ret=%d", ret);
        return ret;
    }
    if (command_name.empty() || command_name != RTMP_AMF0_COMMAND_PAUSE) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_error("amf0 decode pause command_name failed. "
            "command_name=%s, ret=%d", command_name.c_str(), ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode pause transaction_id failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_null(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode pause command_object failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_boolean(stream, is_pause)) != ERROR_SUCCESS) {
        srs_error("amf0 decode pause is_pause failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, time_ms)) != ERROR_SUCCESS) {
        srs_error("amf0 decode pause time_ms failed. ret=%d", ret);
        return ret;
    }
    
    srs_info("amf0 decode pause packet success");
    
    return ret;
}

SrsPlayPacket::SrsPlayPacket()
{
    command_name = RTMP_AMF0_COMMAND_PLAY;
    transaction_id = 0;
    command_object = SrsAmf0Any::null();

    start = -2;
    duration = -1;
    reset = true;
}

SrsPlayPacket::~SrsPlayPacket()
{
    srs_freep(command_object);
}

int SrsPlayPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode play command_name failed. ret=%d", ret);
        return ret;
    }
    if (command_name.empty() || command_name != RTMP_AMF0_COMMAND_PLAY) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_error("amf0 decode play command_name failed. "
            "command_name=%s, ret=%d", command_name.c_str(), ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode play transaction_id failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_null(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode play command_object failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = srs_amf0_read_string(stream, stream_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode play stream_name failed. ret=%d", ret);
        return ret;
    }
    
    if (!stream->empty() && (ret = srs_amf0_read_number(stream, start)) != ERROR_SUCCESS) {
        srs_error("amf0 decode play start failed. ret=%d", ret);
        return ret;
    }
    if (!stream->empty() && (ret = srs_amf0_read_number(stream, duration)) != ERROR_SUCCESS) {
        srs_error("amf0 decode play duration failed. ret=%d", ret);
        return ret;
    }

    if (stream->empty()) {
        return ret;
    }
    
    SrsAmf0Any* reset_value = NULL;
    if ((ret = srs_amf0_read_any(stream, &reset_value)) != ERROR_SUCCESS) {
        ret = ERROR_RTMP_AMF0_DECODE;
        srs_error("amf0 read play reset marker failed. ret=%d", ret);
        return ret;
    }
    SrsAutoFree(SrsAmf0Any, reset_value);
    
    if (reset_value) {
        // check if the value is bool or number
        // An optional Boolean value or number that specifies whether
        // to flush any previous playlist
        if (reset_value->is_boolean()) {
            reset = reset_value->to_boolean();
        } else if (reset_value->is_number()) {
            reset = (reset_value->to_number() != 0);
        } else {
            ret = ERROR_RTMP_AMF0_DECODE;
            srs_error("amf0 invalid type=%#x, requires number or bool, ret=%d", reset_value->marker, ret);
            return ret;
        }
    }

    srs_info("amf0 decode play packet success");
    
    return ret;
}

int SrsPlayPacket::get_prefer_cid()
{
    return RTMP_CID_OverStream;
}

int SrsPlayPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsPlayPacket::get_size()
{
    int size = SrsAmf0Size::str(command_name) + SrsAmf0Size::number()
        + SrsAmf0Size::null() + SrsAmf0Size::str(stream_name);
    
    if (start != -2 || duration != -1 || !reset) {
        size += SrsAmf0Size::number();
    }
    
    if (duration != -1 || !reset) {
        size += SrsAmf0Size::number();
    }
    
    if (!reset) {
        size += SrsAmf0Size::boolean();
    }
    
    return size;
}

int SrsPlayPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = srs_amf0_write_null(stream)) != ERROR_SUCCESS) {
        srs_error("encode command_object failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_object success.");
    
    if ((ret = srs_amf0_write_string(stream, stream_name)) != ERROR_SUCCESS) {
        srs_error("encode stream_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode stream_name success.");
    
    if ((start != -2 || duration != -1 || !reset) && (ret = srs_amf0_write_number(stream, start)) != ERROR_SUCCESS) {
        srs_error("encode start failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode start success.");
    
    if ((duration != -1 || !reset) && (ret = srs_amf0_write_number(stream, duration)) != ERROR_SUCCESS) {
        srs_error("encode duration failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode duration success.");
    
    if (!reset && (ret = srs_amf0_write_boolean(stream, reset)) != ERROR_SUCCESS) {
        srs_error("encode reset failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode reset success.");
    
    srs_info("encode play request packet success.");
    
    return ret;
}

SrsPlayResPacket::SrsPlayResPacket()
{
    command_name = RTMP_AMF0_COMMAND_RESULT;
    transaction_id = 0;
    command_object = SrsAmf0Any::null();
    desc = SrsAmf0Any::object();
}

SrsPlayResPacket::~SrsPlayResPacket()
{
    srs_freep(command_object);
    srs_freep(desc);
}

int SrsPlayResPacket::get_prefer_cid()
{
    return RTMP_CID_OverStream;
}

int SrsPlayResPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsPlayResPacket::get_size()
{
    return SrsAmf0Size::str(command_name) + SrsAmf0Size::number()
        + SrsAmf0Size::null() + SrsAmf0Size::object(desc);
}

int SrsPlayResPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = srs_amf0_write_null(stream)) != ERROR_SUCCESS) {
        srs_error("encode command_object failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_object success.");
    
    if ((ret = desc->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode desc failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode desc success.");
    
    
    srs_info("encode play response packet success.");
    
    return ret;
}

SrsOnBWDonePacket::SrsOnBWDonePacket()
{
    command_name = RTMP_AMF0_COMMAND_ON_BW_DONE;
    transaction_id = 0;
    args = SrsAmf0Any::null();
}

SrsOnBWDonePacket::~SrsOnBWDonePacket()
{
    srs_freep(args);
}

int SrsOnBWDonePacket::get_prefer_cid()
{
    return RTMP_CID_OverConnection;
}

int SrsOnBWDonePacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsOnBWDonePacket::get_size()
{
    return SrsAmf0Size::str(command_name) + SrsAmf0Size::number()
        + SrsAmf0Size::null();
}

int SrsOnBWDonePacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = srs_amf0_write_null(stream)) != ERROR_SUCCESS) {
        srs_error("encode args failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode args success.");
    
    srs_info("encode onBWDone packet success.");
    
    return ret;
}

SrsOnStatusCallPacket::SrsOnStatusCallPacket()
{
    command_name = RTMP_AMF0_COMMAND_ON_STATUS;
    transaction_id = 0;
    args = SrsAmf0Any::null();
    data = SrsAmf0Any::object();
}

SrsOnStatusCallPacket::~SrsOnStatusCallPacket()
{
    srs_freep(args);
    srs_freep(data);
}

int SrsOnStatusCallPacket::get_prefer_cid()
{
    return RTMP_CID_OverStream;
}

int SrsOnStatusCallPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsOnStatusCallPacket::get_size()
{
    return SrsAmf0Size::str(command_name) + SrsAmf0Size::number()
        + SrsAmf0Size::null() + SrsAmf0Size::object(data);
}

int SrsOnStatusCallPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = srs_amf0_write_null(stream)) != ERROR_SUCCESS) {
        srs_error("encode args failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode args success.");;
    
    if ((ret = data->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode data failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode data success.");
    
    srs_info("encode onStatus(Call) packet success.");
    
    return ret;
}

SrsBandwidthPacket::SrsBandwidthPacket()
{
    command_name = RTMP_AMF0_COMMAND_ON_STATUS;
    transaction_id = 0;
    args = SrsAmf0Any::null();
    data = SrsAmf0Any::object();
}

SrsBandwidthPacket::~SrsBandwidthPacket()
{
    srs_freep(args);
    srs_freep(data);
}

int SrsBandwidthPacket::decode(SrsStream *stream)
{
    int ret = ERROR_SUCCESS;

    if ((ret = srs_amf0_read_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("amf0 decode bwtc command_name failed. ret=%d", ret);
        return ret;
    }

    if ((ret = srs_amf0_read_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("amf0 decode bwtc transaction_id failed. ret=%d", ret);
        return ret;
    }

    if ((ret = srs_amf0_read_null(stream)) != ERROR_SUCCESS) {
        srs_error("amf0 decode bwtc command_object failed. ret=%d", ret);
        return ret;
    }
    
    // @remark, for bandwidth test, ignore the data field.
    // only decode the stop-play, start-publish and finish packet.
    if (is_stop_play() || is_start_publish() || is_finish()) {
        if ((ret = data->read(stream)) != ERROR_SUCCESS) {
            srs_error("amf0 decode bwtc command_object failed. ret=%d", ret);
            return ret;
        }
    }

    srs_info("decode SrsBandwidthPacket success.");

    return ret;
}

int SrsBandwidthPacket::get_prefer_cid()
{
    return RTMP_CID_OverStream;
}

int SrsBandwidthPacket::get_message_type()
{
    return RTMP_MSG_AMF0CommandMessage;
}

int SrsBandwidthPacket::get_size()
{
    return SrsAmf0Size::str(command_name) + SrsAmf0Size::number()
        + SrsAmf0Size::null() + SrsAmf0Size::object(data);
}

int SrsBandwidthPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_number(stream, transaction_id)) != ERROR_SUCCESS) {
        srs_error("encode transaction_id failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode transaction_id success.");
    
    if ((ret = srs_amf0_write_null(stream)) != ERROR_SUCCESS) {
        srs_error("encode args failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode args success.");;
    
    if ((ret = data->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode data failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode data success.");
    
    srs_info("encode onStatus(Call) packet success.");
    
    return ret;
}

bool SrsBandwidthPacket::is_start_play()
{
    return command_name == SRS_BW_CHECK_START_PLAY;
}

bool SrsBandwidthPacket::is_starting_play()
{
    return command_name == SRS_BW_CHECK_STARTING_PLAY;
}

bool SrsBandwidthPacket::is_stop_play()
{
    return command_name == SRS_BW_CHECK_STOP_PLAY;
}

bool SrsBandwidthPacket::is_stopped_play()
{
    return command_name == SRS_BW_CHECK_STOPPED_PLAY;
}

bool SrsBandwidthPacket::is_start_publish()
{
    return command_name == SRS_BW_CHECK_START_PUBLISH;
}

bool SrsBandwidthPacket::is_starting_publish()
{
    return command_name == SRS_BW_CHECK_STARTING_PUBLISH;
}

bool SrsBandwidthPacket::is_stop_publish()
{
    return command_name == SRS_BW_CHECK_STOP_PUBLISH;
}

bool SrsBandwidthPacket::is_stopped_publish()
{
    return command_name == SRS_BW_CHECK_STOPPED_PUBLISH;
}

bool SrsBandwidthPacket::is_finish()
{
    return command_name == SRS_BW_CHECK_FINISHED;
}

bool SrsBandwidthPacket::is_final()
{
    return command_name == SRS_BW_CHECK_FINAL;
}

SrsBandwidthPacket* SrsBandwidthPacket::create_start_play()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_START_PLAY);
}

SrsBandwidthPacket* SrsBandwidthPacket::create_starting_play()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_STARTING_PLAY);
}

SrsBandwidthPacket* SrsBandwidthPacket::create_playing()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_PLAYING);
}

SrsBandwidthPacket* SrsBandwidthPacket::create_stop_play()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_STOP_PLAY);
}

SrsBandwidthPacket* SrsBandwidthPacket::create_stopped_play()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_STOPPED_PLAY);
}

SrsBandwidthPacket* SrsBandwidthPacket::create_start_publish()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_START_PUBLISH);
}

SrsBandwidthPacket* SrsBandwidthPacket::create_starting_publish()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_STARTING_PUBLISH);
}

SrsBandwidthPacket* SrsBandwidthPacket::create_publishing()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_PUBLISHING);
}

SrsBandwidthPacket* SrsBandwidthPacket::create_stop_publish()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_STOP_PUBLISH);
}

SrsBandwidthPacket* SrsBandwidthPacket::create_stopped_publish()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_STOPPED_PUBLISH);
}

SrsBandwidthPacket* SrsBandwidthPacket::create_finish()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_FINISHED);
}

SrsBandwidthPacket* SrsBandwidthPacket::create_final()
{
    SrsBandwidthPacket* pkt = new SrsBandwidthPacket();
    LB_ADD_MEM(pkt, sizeof(SrsBandwidthPacket));
    return pkt->set_command(SRS_BW_CHECK_FINAL);
}

SrsBandwidthPacket* SrsBandwidthPacket::set_command(string command)
{
    command_name = command;
    
    return this;
}

SrsOnStatusDataPacket::SrsOnStatusDataPacket()
{
    command_name = RTMP_AMF0_COMMAND_ON_STATUS;
    data = SrsAmf0Any::object();
}

SrsOnStatusDataPacket::~SrsOnStatusDataPacket()
{
    srs_freep(data);
}

int SrsOnStatusDataPacket::get_prefer_cid()
{
    return RTMP_CID_OverStream;
}

int SrsOnStatusDataPacket::get_message_type()
{
    return RTMP_MSG_AMF0DataMessage;
}

int SrsOnStatusDataPacket::get_size()
{
    return SrsAmf0Size::str(command_name) + SrsAmf0Size::object(data);
}

int SrsOnStatusDataPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = data->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode data failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode data success.");
    
    srs_info("encode onStatus(Data) packet success.");
    
    return ret;
}

SrsSampleAccessPacket::SrsSampleAccessPacket()
{
    command_name = RTMP_AMF0_DATA_SAMPLE_ACCESS;
    video_sample_access = false;
    audio_sample_access = false;
}

SrsSampleAccessPacket::~SrsSampleAccessPacket()
{
}

int SrsSampleAccessPacket::get_prefer_cid()
{
    return RTMP_CID_OverStream;
}

int SrsSampleAccessPacket::get_message_type()
{
    return RTMP_MSG_AMF0DataMessage;
}

int SrsSampleAccessPacket::get_size()
{
    return SrsAmf0Size::str(command_name)
        + SrsAmf0Size::boolean() + SrsAmf0Size::boolean();
}

int SrsSampleAccessPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, command_name)) != ERROR_SUCCESS) {
        srs_error("encode command_name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode command_name success.");
    
    if ((ret = srs_amf0_write_boolean(stream, video_sample_access)) != ERROR_SUCCESS) {
        srs_error("encode video_sample_access failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode video_sample_access success.");
    
    if ((ret = srs_amf0_write_boolean(stream, audio_sample_access)) != ERROR_SUCCESS) {
        srs_error("encode audio_sample_access failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode audio_sample_access success.");;
    
    srs_info("encode |RtmpSampleAccess packet success.");
    
    return ret;
}

SrsOnMetaDataPacket::SrsOnMetaDataPacket()
{
    name = SRS_CONSTS_RTMP_ON_METADATA;
    metadata = SrsAmf0Any::object();
}

SrsOnMetaDataPacket::~SrsOnMetaDataPacket()
{
    srs_freep(metadata);
}

int SrsOnMetaDataPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_read_string(stream, name)) != ERROR_SUCCESS) {
        srs_error("decode metadata name failed. ret=%d", ret);
        return ret;
    }

    // ignore the @setDataFrame
    if (name == SRS_CONSTS_RTMP_SET_DATAFRAME) {
        if ((ret = srs_amf0_read_string(stream, name)) != ERROR_SUCCESS) {
            srs_error("decode metadata name failed. ret=%d", ret);
            return ret;
        }
    }
    
    srs_verbose("decode metadata name success. name=%s", name.c_str());
    
    // the metadata maybe object or ecma array
    SrsAmf0Any* any = NULL;
    if ((ret = srs_amf0_read_any(stream, &any)) != ERROR_SUCCESS) {
        srs_error("decode metadata metadata failed. ret=%d", ret);
        return ret;
    }
    
    srs_assert(any);
    if (any->is_object()) {
        srs_freep(metadata);
        metadata = any->to_object();
        srs_info("decode metadata object success");
        return ret;
    }
    
    SrsAutoFree(SrsAmf0Any, any);
    
    if (any->is_ecma_array()) {
        SrsAmf0EcmaArray* arr = any->to_ecma_array();
    
        // if ecma array, copy to object.
        for (int i = 0; i < arr->count(); i++) {
            metadata->set(arr->key_at(i), arr->value_at(i)->copy());
        }
        
        srs_info("decode metadata array success");
    }
    
    return ret;
}

int SrsOnMetaDataPacket::get_prefer_cid()
{
    return RTMP_CID_OverConnection2;
}

int SrsOnMetaDataPacket::get_message_type()
{
    return RTMP_MSG_AMF0DataMessage;
}

int SrsOnMetaDataPacket::get_size()
{
    return SrsAmf0Size::str(name) + SrsAmf0Size::object(metadata);
}

int SrsOnMetaDataPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = srs_amf0_write_string(stream, name)) != ERROR_SUCCESS) {
        srs_error("encode name failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode name success.");
    
    if ((ret = metadata->write(stream)) != ERROR_SUCCESS) {
        srs_error("encode metadata failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("encode metadata success.");
    
    srs_info("encode onMetaData packet success.");
    return ret;
}

SrsSetWindowAckSizePacket::SrsSetWindowAckSizePacket()
{
    ackowledgement_window_size = 0;
}

SrsSetWindowAckSizePacket::~SrsSetWindowAckSizePacket()
{
}

int SrsSetWindowAckSizePacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if (!stream->require(4)) {
        ret = ERROR_RTMP_MESSAGE_DECODE;
        srs_error("decode ack window size failed. ret=%d", ret);
        return ret;
    }
    
    ackowledgement_window_size = stream->read_4bytes();
    srs_info("decode ack window size success");
    
    return ret;
}

int SrsSetWindowAckSizePacket::get_prefer_cid()
{
    return RTMP_CID_ProtocolControl;
}

int SrsSetWindowAckSizePacket::get_message_type()
{
    return RTMP_MSG_WindowAcknowledgementSize;
}

int SrsSetWindowAckSizePacket::get_size()
{
    return 4;
}

int SrsSetWindowAckSizePacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if (!stream->require(4)) {
        ret = ERROR_RTMP_MESSAGE_ENCODE;
        srs_error("encode ack size packet failed. ret=%d", ret);
        return ret;
    }
    
    stream->write_4bytes(ackowledgement_window_size);
    
    srs_verbose("encode ack size packet "
        "success. ack_size=%d", ackowledgement_window_size);
    
    return ret;
}

SrsAcknowledgementPacket::SrsAcknowledgementPacket()
{
    sequence_number = 0;
}

SrsAcknowledgementPacket::~SrsAcknowledgementPacket()
{
}

int SrsAcknowledgementPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if (!stream->require(4)) {
        ret = ERROR_RTMP_MESSAGE_DECODE;
        srs_error("decode acknowledgement failed. ret=%d", ret);
        return ret;
    }
    
    sequence_number = (uint32_t)stream->read_4bytes();
    srs_info("decode acknowledgement success");
    
    return ret;
}

int SrsAcknowledgementPacket::get_prefer_cid()
{
    return RTMP_CID_ProtocolControl;
}

int SrsAcknowledgementPacket::get_message_type()
{
    return RTMP_MSG_Acknowledgement;
}

int SrsAcknowledgementPacket::get_size()
{
    return 4;
}

int SrsAcknowledgementPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if (!stream->require(4)) {
        ret = ERROR_RTMP_MESSAGE_ENCODE;
        srs_error("encode acknowledgement packet failed. ret=%d", ret);
        return ret;
    }
    
    stream->write_4bytes(sequence_number);
    
    srs_verbose("encode acknowledgement packet "
        "success. sequence_number=%d", sequence_number);
    
    return ret;
}

SrsSetChunkSizePacket::SrsSetChunkSizePacket()
{
    chunk_size = SRS_CONSTS_RTMP_PROTOCOL_CHUNK_SIZE;
}

SrsSetChunkSizePacket::~SrsSetChunkSizePacket()
{
}

int SrsSetChunkSizePacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if (!stream->require(4)) {
        ret = ERROR_RTMP_MESSAGE_DECODE;
        srs_error("decode chunk size failed. ret=%d", ret);
        return ret;
    }
    
    chunk_size = stream->read_4bytes();
    srs_info("decode chunk size success. chunk_size=%d", chunk_size);
    
    return ret;
}

int SrsSetChunkSizePacket::get_prefer_cid()
{
    return RTMP_CID_ProtocolControl;
}

int SrsSetChunkSizePacket::get_message_type()
{
    return RTMP_MSG_SetChunkSize;
}

int SrsSetChunkSizePacket::get_size()
{
    return 4;
}

int SrsSetChunkSizePacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if (!stream->require(4)) {
        ret = ERROR_RTMP_MESSAGE_ENCODE;
        srs_error("encode chunk packet failed. ret=%d", ret);
        return ret;
    }
    
    stream->write_4bytes(chunk_size);
    
    srs_verbose("encode chunk packet success. ack_size=%d", chunk_size);
    
    return ret;
}

SrsSetPeerBandwidthPacket::SrsSetPeerBandwidthPacket()
{
    bandwidth = 0;
    type = SrsPeerBandwidthDynamic;
}

SrsSetPeerBandwidthPacket::~SrsSetPeerBandwidthPacket()
{
}

int SrsSetPeerBandwidthPacket::get_prefer_cid()
{
    return RTMP_CID_ProtocolControl;
}

int SrsSetPeerBandwidthPacket::get_message_type()
{
    return RTMP_MSG_SetPeerBandwidth;
}

int SrsSetPeerBandwidthPacket::get_size()
{
    return 5;
}

int SrsSetPeerBandwidthPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if (!stream->require(5)) {
        ret = ERROR_RTMP_MESSAGE_ENCODE;
        srs_error("encode set bandwidth packet failed. ret=%d", ret);
        return ret;
    }
    
    stream->write_4bytes(bandwidth);
    stream->write_1bytes(type);
    
    srs_verbose("encode set bandwidth packet "
        "success. bandwidth=%d, type=%d", bandwidth, type);
    
    return ret;
}

SrsUserControlPacket::SrsUserControlPacket()
{
    event_type = 0;
    event_data = 0;
    extra_data = 0;
}

SrsUserControlPacket::~SrsUserControlPacket()
{
}

int SrsUserControlPacket::decode(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if (!stream->require(2)) {
        ret = ERROR_RTMP_MESSAGE_DECODE;
        srs_error("decode user control failed. ret=%d", ret);
        return ret;
    }
    
    event_type = stream->read_2bytes();
    
    if (event_type == SrsPCUCFmsEvent0) {
        if (!stream->require(1)) {
            ret = ERROR_RTMP_MESSAGE_DECODE;
            srs_error("decode user control failed. ret=%d", ret);
            return ret;
        }
        event_data = stream->read_1bytes();
    } else {
        if (!stream->require(4)) {
            ret = ERROR_RTMP_MESSAGE_DECODE;
            srs_error("decode user control failed. ret=%d", ret);
            return ret;
        }
        event_data = stream->read_4bytes();
    }
    
    if (event_type == SrcPCUCSetBufferLength) {
        if (!stream->require(4)) {
            ret = ERROR_RTMP_MESSAGE_ENCODE;
            srs_error("decode user control packet failed. ret=%d", ret);
            return ret;
        }
        extra_data = stream->read_4bytes();
    }
    
    srs_info("decode user control success. "
        "event_type=%d, event_data=%d, extra_data=%d", 
        event_type, event_data, extra_data);
    
    return ret;
}

int SrsUserControlPacket::get_prefer_cid()
{
    return RTMP_CID_ProtocolControl;
}

int SrsUserControlPacket::get_message_type()
{
    return RTMP_MSG_UserControlMessage;
}

int SrsUserControlPacket::get_size()
{
    int size = 2;
    
    if (event_type == SrsPCUCFmsEvent0) {
        size += 1;
    } else {
        size += 4;
    }
    
    if (event_type == SrcPCUCSetBufferLength) {
        size += 4;
    }
    
    return size;
}

int SrsUserControlPacket::encode_packet(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    
    if (!stream->require(get_size())) {
        ret = ERROR_RTMP_MESSAGE_ENCODE;
        srs_error("encode user control packet failed. ret=%d", ret);
        return ret;
    }
    
    stream->write_2bytes(event_type);
    
    if (event_type == SrsPCUCFmsEvent0) {
        stream->write_1bytes(event_data);
    } else {
        stream->write_4bytes(event_data);
    }

    // when event type is set buffer length,
    // write the extra buffer length.
    if (event_type == SrcPCUCSetBufferLength) {
        stream->write_4bytes(extra_data);
        srs_verbose("user control message, buffer_length=%d", extra_data);
    }
    
    srs_verbose("encode user control packet success. "
        "event_type=%d, event_data=%d", event_type, event_data);
    
    return ret;
}


