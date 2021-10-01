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

#include <srs_rtsp_stack.hpp>

#if !defined(SRS_EXPORT_LIBRTMP)

#include <stdlib.h>
#include <map>
#include <sys/time.h>
#include <unistd.h>
using namespace std;

#include <srs_rtmp_io.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_kernel_consts.hpp>
#include <srs_core_autofree.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_kernel_stream.hpp>
#include <srs_kernel_codec.hpp>
#include <lbsp_openssl_utility.hpp>
#include <lbsp_utility_string.hpp>
#include <lbsp_utility_common.hpp>
#include <lbsp_media_parser.hpp>
using namespace lbsp_util;
#ifdef SRS_AUTO_STREAM_CASTER

#define SRS_RTSP_BUFFER 4096

// get the status text of code.
string srs_generate_rtsp_status_text(int status)
{
    static std::map<int, std::string> _status_map;
    if (_status_map.empty()) {
        _status_map[SRS_CONSTS_RTSP_Continue                       ] = SRS_CONSTS_RTSP_Continue_str                        ;      
        _status_map[SRS_CONSTS_RTSP_OK                             ] = SRS_CONSTS_RTSP_OK_str                              ;      
        _status_map[SRS_CONSTS_RTSP_Created                        ] = SRS_CONSTS_RTSP_Created_str                         ;      
        _status_map[SRS_CONSTS_RTSP_LowOnStorageSpace              ] = SRS_CONSTS_RTSP_LowOnStorageSpace_str               ;      
        _status_map[SRS_CONSTS_RTSP_MultipleChoices                ] = SRS_CONSTS_RTSP_MultipleChoices_str                 ;      
        _status_map[SRS_CONSTS_RTSP_MovedPermanently               ] = SRS_CONSTS_RTSP_MovedPermanently_str                ;      
        _status_map[SRS_CONSTS_RTSP_MovedTemporarily               ] = SRS_CONSTS_RTSP_MovedTemporarily_str                ;      
        _status_map[SRS_CONSTS_RTSP_SeeOther                       ] = SRS_CONSTS_RTSP_SeeOther_str                        ;      
        _status_map[SRS_CONSTS_RTSP_NotModified                    ] = SRS_CONSTS_RTSP_NotModified_str                     ;      
        _status_map[SRS_CONSTS_RTSP_UseProxy                       ] = SRS_CONSTS_RTSP_UseProxy_str                        ;      
        _status_map[SRS_CONSTS_RTSP_BadRequest                     ] = SRS_CONSTS_RTSP_BadRequest_str                      ;      
        _status_map[SRS_CONSTS_RTSP_Unauthorized                   ] = SRS_CONSTS_RTSP_Unauthorized_str                    ;      
        _status_map[SRS_CONSTS_RTSP_PaymentRequired                ] = SRS_CONSTS_RTSP_PaymentRequired_str                 ;      
        _status_map[SRS_CONSTS_RTSP_Forbidden                      ] = SRS_CONSTS_RTSP_Forbidden_str                       ;      
        _status_map[SRS_CONSTS_RTSP_NotFound                       ] = SRS_CONSTS_RTSP_NotFound_str                        ;      
        _status_map[SRS_CONSTS_RTSP_MethodNotAllowed               ] = SRS_CONSTS_RTSP_MethodNotAllowed_str                ;      
        _status_map[SRS_CONSTS_RTSP_NotAcceptable                  ] = SRS_CONSTS_RTSP_NotAcceptable_str                   ;      
        _status_map[SRS_CONSTS_RTSP_ProxyAuthenticationRequired    ] = SRS_CONSTS_RTSP_ProxyAuthenticationRequired_str     ;      
        _status_map[SRS_CONSTS_RTSP_RequestTimeout                 ] = SRS_CONSTS_RTSP_RequestTimeout_str                  ;      
        _status_map[SRS_CONSTS_RTSP_Gone                           ] = SRS_CONSTS_RTSP_Gone_str                            ;      
        _status_map[SRS_CONSTS_RTSP_LengthRequired                 ] = SRS_CONSTS_RTSP_LengthRequired_str                  ;      
        _status_map[SRS_CONSTS_RTSP_PreconditionFailed             ] = SRS_CONSTS_RTSP_PreconditionFailed_str              ;      
        _status_map[SRS_CONSTS_RTSP_RequestEntityTooLarge          ] = SRS_CONSTS_RTSP_RequestEntityTooLarge_str           ;      
        _status_map[SRS_CONSTS_RTSP_RequestURITooLarge             ] = SRS_CONSTS_RTSP_RequestURITooLarge_str              ;      
        _status_map[SRS_CONSTS_RTSP_UnsupportedMediaType           ] = SRS_CONSTS_RTSP_UnsupportedMediaType_str            ;      
        _status_map[SRS_CONSTS_RTSP_ParameterNotUnderstood         ] = SRS_CONSTS_RTSP_ParameterNotUnderstood_str          ;      
        _status_map[SRS_CONSTS_RTSP_ConferenceNotFound             ] = SRS_CONSTS_RTSP_ConferenceNotFound_str              ;      
        _status_map[SRS_CONSTS_RTSP_NotEnoughBandwidth             ] = SRS_CONSTS_RTSP_NotEnoughBandwidth_str              ;      
        _status_map[SRS_CONSTS_RTSP_SessionNotFound                ] = SRS_CONSTS_RTSP_SessionNotFound_str                 ;      
        _status_map[SRS_CONSTS_RTSP_MethodNotValidInThisState      ] = SRS_CONSTS_RTSP_MethodNotValidInThisState_str       ;      
        _status_map[SRS_CONSTS_RTSP_HeaderFieldNotValidForResource ] = SRS_CONSTS_RTSP_HeaderFieldNotValidForResource_str  ;      
        _status_map[SRS_CONSTS_RTSP_InvalidRange                   ] = SRS_CONSTS_RTSP_InvalidRange_str                    ;      
        _status_map[SRS_CONSTS_RTSP_ParameterIsReadOnly            ] = SRS_CONSTS_RTSP_ParameterIsReadOnly_str             ;      
        _status_map[SRS_CONSTS_RTSP_AggregateOperationNotAllowed   ] = SRS_CONSTS_RTSP_AggregateOperationNotAllowed_str    ;      
        _status_map[SRS_CONSTS_RTSP_OnlyAggregateOperationAllowed  ] = SRS_CONSTS_RTSP_OnlyAggregateOperationAllowed_str   ;      
        _status_map[SRS_CONSTS_RTSP_UnsupportedTransport           ] = SRS_CONSTS_RTSP_UnsupportedTransport_str            ;      
        _status_map[SRS_CONSTS_RTSP_DestinationUnreachable         ] = SRS_CONSTS_RTSP_DestinationUnreachable_str          ;      
        _status_map[SRS_CONSTS_RTSP_InternalServerError            ] = SRS_CONSTS_RTSP_InternalServerError_str             ;      
        _status_map[SRS_CONSTS_RTSP_NotImplemented                 ] = SRS_CONSTS_RTSP_NotImplemented_str                  ;      
        _status_map[SRS_CONSTS_RTSP_BadGateway                     ] = SRS_CONSTS_RTSP_BadGateway_str                      ;     
        _status_map[SRS_CONSTS_RTSP_ServiceUnavailable             ] = SRS_CONSTS_RTSP_ServiceUnavailable_str              ;     
        _status_map[SRS_CONSTS_RTSP_GatewayTimeout                 ] = SRS_CONSTS_RTSP_GatewayTimeout_str                  ;     
        _status_map[SRS_CONSTS_RTSP_RTSPVersionNotSupported        ] = SRS_CONSTS_RTSP_RTSPVersionNotSupported_str         ;     
        _status_map[SRS_CONSTS_RTSP_OptionNotSupported             ] = SRS_CONSTS_RTSP_OptionNotSupported_str              ;        
    }
    
    std::string status_text;
    if (_status_map.find(status) == _status_map.end()) {
        status_text = "Status Unknown";
    } else {
        status_text = _status_map[status];
    }
    
    return status_text;
}

std::string srs_generate_rtsp_method_str(SrsRtspMethod method) 
{
    switch (method) {
        case SrsRtspMethodDescribe: return SRS_METHOD_DESCRIBE;
        case SrsRtspMethodAnnounce: return SRS_METHOD_ANNOUNCE;
        case SrsRtspMethodGetParameter: return SRS_METHOD_GET_PARAMETER;
        case SrsRtspMethodOptions: return SRS_METHOD_OPTIONS;
        case SrsRtspMethodPause: return SRS_METHOD_PAUSE;
        case SrsRtspMethodPlay: return SRS_METHOD_PLAY;
        case SrsRtspMethodRecord: return SRS_METHOD_RECORD;
        case SrsRtspMethodRedirect: return SRS_METHOD_REDIRECT;
        case SrsRtspMethodSetup: return SRS_METHOD_SETUP;
        case SrsRtspMethodSetParameter: return SRS_METHOD_SET_PARAMETER;
        case SrsRtspMethodTeardown: return SRS_METHOD_TEARDOWN;
        default: return "Unknown";
    }
}

SrsRtcpSDESItem::SrsRtcpSDESItem(unsigned char tag, char const* pval)
{
    init(tag, pval);
}
SrsRtcpSDESItem::~SrsRtcpSDESItem()
{
}

char const* SrsRtcpSDESItem::data()
{
    return (char const*)data_buf;
}

int SrsRtcpSDESItem::size()
{
    return 2 + (int)data_buf[1];
}

int SrsRtcpSDESItem::init(unsigned char tag, char const* pval)
{
    SRS_CHECK_PARAM_PTR(pval, -1);
    item_tag = tag;
    uint8_t len = strlen(pval);
    data_buf[0] = tag;
    data_buf[1] = len;
    memcpy(data_buf + 2, pval, len);
    srs_rtsp_debug("data_buf len:%d, data:", size());
    srs_rtsp_debug_memory((const char*)data_buf, size());
    return 0;
}

int SrsRtcpSDESItem::write(SrsStream* stream)
{
    SRS_CHECK_PARAM_PTR(stream, -1);
    if(!stream->require(size()))
    {
        srs_error("Not enought buffer for rtcp sdes item wirte, remain:%d, nedd:%d\n", stream->remain(), size());
        return -1;
    }

    return stream->write_bytes((char*)data(), size());
}

SrsSDESPacket::SrsSDESPacket()
{

}

SrsSDESPacket::~SrsSDESPacket()
{

}
int SrsSDESPacket::encode(char* pdata, int len)
//int SrsSDESPacket::write(char* pdata, int len)
{
    int ret = SrsRtcpPacket::encode(pdata, len);
    SRS_CHECK_RESULT(ret);
    for(size_t i = 0; i < sdes_item_list.size(); i++)
    {
        SrsRtcpSDESItem* pitem = sdes_item_list[i];
        if(pitem && m_pstream)
        {
            ret = pitem->write(m_pstream);
            SRS_CHECK_RESULT(ret);
        }
    }
    if(ret != ERROR_SUCCESS)
    {
        return ret;
    }
    //srs_rtsp_debug("SrsSDESPacket packet len:%d, data:", m_pstream->pos());
    //srs_rtsp_debug_memory(pdata, m_pstream->pos());
    return m_pstream->pos();
}

int SrsSDESPacket::add_sdes_item(uint8_t tag, SrsRtcpSDESItem* pitem)
{
    if(SRS_RTCP_SDES_CNAME == tag && NULL == pitem)
    {
        char buf[100] = {0};
        gethostname(buf, 100);
        pitem = new SrsRtcpSDESItem(tag, buf);
        LB_ADD_MEM(pitem, sizeof(SrsRtcpSDESItem));
    }
    else if(NULL == pitem)
    {
        return -1;
    }

    sdes_item_list.push_back(pitem);
    return 0;
}

int SrsSDESPacket::get_sc_rc_count()
{
    int cnt = ussrc == 0 ? 0 : 1;
    cnt += csrc_list.size();
    return cnt;
}

int SrsSDESPacket::get_length()
{
    int len = 0;
    for(size_t i = 0; i < sdes_item_list.size(); i++)
    {
        SrsRtcpSDESItem* pitem = sdes_item_list[i];
        if(pitem && m_pstream)
        {
            len += pitem->size();
        }
    }

    return len;
}

int SrsRtcpPacket::write(char* pdata, int len)
{
    SRS_CHECK_PARAM_PTR(pdata, -1);
    SRS_CHECK_PARAM_PTR(m_pstream, -1);

    int ret = encode(pdata, len);

    return ret;
}

SrsRtcpPacket::SrsRtcpPacket()
{
    version = 2;
    padding = 0;
    recv_count = 0;
    payload_type = -1;
    length = 0;
    ussrc = 0;
    payload = NULL;
    m_pstream = NULL;
}

SrsRtcpPacket::~SrsRtcpPacket()
{
    srs_freep(payload);
}

int SrsRtcpPacket::encode(char* pdata, int len)
{
    if(NULL == m_pstream)
    {
        m_pstream = new CBitStream();
        LB_ADD_MEM(m_pstream, sizeof(CBitStream));
    }
    int ret = m_pstream->initialize(pdata, len);
    SRS_CHECK_RESULT(ret);
    if(!m_pstream->require(RTCP_PACKET_HEADER_SIZE))
    {
        srs_error("not enought pdata buf len:%d for rtcp header size:%d\n", len, RTCP_PACKET_HEADER_SIZE);
        return -1;
    }
    recv_count = get_sc_rc_count();
    length = get_length();
    ret = m_pstream->write_bits(2, version); // rtcp version bit(2bit): 2
    SRS_CHECK_RESULT(ret);
    ret = m_pstream->write_bits(1, padding); // rtcp padding bit(1bit): 0
    SRS_CHECK_RESULT(ret);
    ret = m_pstream->write_bits(5, recv_count); // rtcp recv_count bit(5bit)
    SRS_CHECK_RESULT(ret);
    ret = m_pstream->write_bits(8, payload_type); // rtcp payload_type bit(8bit)
    SRS_CHECK_RESULT(ret);
    ret = m_pstream->write_bits(16, length); // rtcp length bit(16bit)
    SRS_CHECK_RESULT(ret);
    ret = m_pstream->write_bits(32, ussrc); // rtcp ssrc bit(32bit)
    SRS_CHECK_RESULT(ret);
    srs_rtsp_debug("version:%d, padding:%d, recv_count:%d, payload_type:%d, length:%d, ussrc:%0x\n", (int)version, (int)padding, (int)recv_count, (int)payload_type, (int)length, ussrc);
    srs_rtsp_debug("rtcp pkt heder len:%d, data:", RTCP_PACKET_HEADER_SIZE);
    srs_rtsp_debug_memory(pdata, RTCP_PACKET_HEADER_SIZE);
    return RTCP_PACKET_HEADER_SIZE;
}

int SrsRtcpPacket::set_ssrc(uint32_t ssrc)
{
    ussrc = ssrc;
    srs_rtsp_debug("set ssrc:%0x\n", ssrc);
    return 0;
}

int SrsRtcpPacket::add_csrc(uint32_t csrc)
{
    std::vector<uint32_t>::iterator it = csrc_list.begin();
    for(; it != csrc_list.end(); it++)
    {
        if(*it == csrc)
        {
            return 0;
        }
    }
    if(csrc_list.size() >= 15)
    {
        srs_error("rtcp csrc have full %d\n", csrc_list.size());
        return -1;
    }

    csrc_list.push_back(csrc);
    return 0;
}

int SrsRtcpPacket::remove_csrc(uint32_t csrc)
{
    std::vector<uint32_t>::iterator it = csrc_list.begin();
    for(; it != csrc_list.end(); it++)
    {
        if(*it == csrc)
        {
            csrc_list.erase(it);
            return 0;
        }
    }

    return -1;
}

int SrsRtcpPacket::get_sc_rc_count()
{
    srs_rtsp_debug("SrsRtcpPacket::get_sc_rc_count() failed!\n");
    return 0;
}

int SrsRtcpPacket::get_length()
{
    srs_rtsp_debug("SrsRtcpPacket::get_length() failed!\n");
    return 0;
}

SrsRtcpSenderReport::SrsRtcpSenderReport()
{

}

SrsRtcpSenderReport::~SrsRtcpSenderReport()
{

}

int SrsRtcpSenderReport::encode(char* pdata, int len)
{
    return -1;
}

int SrsRtcpSenderReport::get_sc_rc_count()
{
    return -1;
}

int SrsRtcpSenderReport::get_length()
{
    return -1;
}

SrsRtpPacket::SrsRtpPacket()
{
    version = 2;
    padding = 0;
    extension = 0;
    csrc_count = 0;
    marker = 1;

    payload_type = 0;
    npts_offset = INT32_MIN;
    sequence_number = 0;
    total_sequence_number = 0;
    timestamp = 0;
    ssrc = 0;
    total_payload_bytes = 0;
    time_scale = SRS_RTSP_PTS_TIME_BASE;
#ifdef WRITE_RTSP_RTP_DATA
    m_pfile = NULL;
#endif
    SrsSimpleBuffer* payload = new SrsSimpleBuffer();
    LB_ADD_MEM(payload, sizeof(SrsSimpleBuffer));
    vrtp_packet_list.push_back(payload);
    //vrtp_packet_list.push_back(payload);
    audio_samples = new SrsCodecSample();
    LB_ADD_MEM(audio_samples, sizeof(SrsCodecSample));
    chunked = false;
    completed = false;
    m_pbitstream = new lazy_bitstream();
    LB_ADD_MEM(m_pbitstream, sizeof(CBitStream));
    m_estreaming_type = SrsRtspStreamingTypeTCP;
    m_prtp_packet = NULL;
    m_nmax_rtp_packet_size = 0;
}

SrsRtpPacket::~SrsRtpPacket()
{
    //srs_freep(payload);
    for(size_t i = 0; i < vrtp_packet_list.size(); i++)
    {
        srs_freep(vrtp_packet_list[i]);
    }
    vrtp_packet_list.clear();
    srs_freep(audio_samples);
    srs_freep(m_pbitstream);
#ifdef WRITE_RTSP_RTP_DATA
    if(m_pfile)
    {
        fclose(m_pfile);
        m_pfile = NULL;
    }
#endif
    srs_freepa(m_prtp_packet);

    m_nmax_rtp_packet_size = 0;
}

void SrsRtpPacket::copy(SrsRtpPacket* src)
{
    version = src->version;
    padding = src->padding;
    extension = src->extension;
    csrc_count = src->csrc_count;
    marker = src->marker;
    payload_type = src->payload_type;
    sequence_number = src->sequence_number;
    timestamp = src->timestamp;
    ssrc = src->ssrc;

    chunked = src->chunked;
    completed = src->completed;
    audio_samples = new SrsCodecSample();
    LB_ADD_MEM(audio_samples, sizeof(SrsCodecSample));
    for(size_t i = 0; i < src->vrtp_packet_list.size(); i++)
    {
        SrsSimpleBuffer* psb = new SrsSimpleBuffer();
        LB_ADD_MEM(psb, sizeof(SrsSimpleBuffer));
        psb->append(src->vrtp_packet_list[i]->bytes(), src->vrtp_packet_list[i]->length());
        vrtp_packet_list.push_back(psb);
    }
    //payload->append(src->payload->bytes(), src->payload->length());
}

void SrsRtpPacket::reap(SrsRtpPacket* src)
{
    copy(src);
    for(size_t i = 0; i < src->vrtp_packet_list.size(); i++)
        srs_freep(src->vrtp_packet_list[i]);

    src->vrtp_packet_list.clear();
    
    srs_freep(audio_samples);
    audio_samples = src->audio_samples;
    src->audio_samples = NULL;
}

SrsSimpleBuffer* SrsRtpPacket::get_payload()
{
    if(vrtp_packet_list.size() == 0)
    {
        return NULL;
    }
    else
    {
        return vrtp_packet_list[vrtp_packet_list.size()-1];
    }
}

SrsSimpleBuffer* SrsRtpPacket::next_payload()
{
    SrsSimpleBuffer* psb = get_payload();
    if(psb && NULL == psb->bytes())
    {
        return psb;
    }
    else
    {
        psb = new SrsSimpleBuffer();
        LB_ADD_MEM(psb, sizeof(SrsSimpleBuffer));
        vrtp_packet_list.push_back(psb);
        return psb;
    }
    
}

int SrsRtpPacket::decode(lazy_bitstream* stream)
{
    int ret = ERROR_SUCCESS;

    // 12bytes header
    if (!stream->require(12)) {
        ret = ERROR_RTP_HEADER_CORRUPT;
        srs_error("rtsp: rtp header corrupt. ret=%d", ret);
        return ret;
    }

    int8_t vv = stream->read_byte(1);
    version = (vv >> 6) & 0x03;
    padding = (vv >> 5) & 0x01;
    extension = (vv >> 4) & 0x01;
    csrc_count = vv & 0x0f;

    int8_t mv = stream->read_byte(1);
    marker = (mv >> 7) & 0x01;
    payload_type = mv & 0x7f;

    sequence_number = stream->read_byte(2);
    timestamp = stream->read_byte(4);
    ssrc = stream->read_byte(4);

    // TODO: FIXME: check sequence number.

    // video codec.
    if (payload_type == SRS_RTSP_AVC_PAYLOAD_TYPE) {
        return decode_96(stream);
    } else if (payload_type == 97) {
        return decode_97(stream);
    }

    return ret;
}

int SrsRtpPacket::decode_97(lazy_bitstream* stream)
{
    int ret = ERROR_SUCCESS;

    // atleast 2bytes content.
    if (!stream->require(2)) {
        ret = ERROR_RTP_TYPE97_CORRUPT;
        srs_error("rtsp: rtp type97 corrupt. ret=%d", ret);
        return ret;
    }

    int8_t hasv = stream->read_byte(1);
    int8_t lasv = stream->read_byte(1);
    u_int16_t au_size = ((hasv << 5) & 0xE0) | ((lasv >> 3) & 0x1f);

    if (!stream->require(au_size)) {
        ret = ERROR_RTP_TYPE97_CORRUPT;
        srs_error("rtsp: rtp type97 au_size corrupt. ret=%d", ret);
        return ret;
    }
    SrsSimpleBuffer* payload = get_payload();
    int required_size = 0;

    // append left bytes to payload.
    payload->append(
        (const char*)(stream->data() + stream->pos()) + au_size, 
        stream->size() - stream->pos() - au_size
    );
    char* p = payload->bytes();

    for (int i = 0; i < au_size; i += 2) {
        hasv = stream->read_byte(1);
        lasv = stream->read_byte(1);

        u_int16_t sample_size = ((hasv << 5) & 0xE0) | ((lasv >> 3) & 0x1f);
        // TODO: FIXME: finger out how to parse the size of sample.
        if (sample_size < 0x100 && stream->require(required_size + sample_size + 0x100)) {
            sample_size = sample_size | 0x100;
        }

        char* sample = p + required_size;
        required_size += sample_size;

        if (!stream->require(required_size)) {
            ret = ERROR_RTP_TYPE97_CORRUPT;
            srs_error("rtsp: rtp type97 samples corrupt. ret=%d", ret);
            return ret;
        }

        if ((ret = audio_samples->add_sample_unit(sample, sample_size)) != ERROR_SUCCESS) {
            srs_error("rtsp: rtp type97 add sample failed. ret=%d", ret);
            return ret;
        }
    }

    // parsed ok.
    completed = true;

    return ret;
}

int SrsRtpPacket::decode_96(lazy_bitstream* stream)
{
    int ret = ERROR_SUCCESS;

    // atleast 2bytes content.
    if (!stream->require(2)) {
        ret = ERROR_RTP_TYPE96_CORRUPT;
        srs_error("rtsp: rtp type96 corrupt. ret=%d", ret);
        return ret;
    }

    // frame type
    // 0... .... reserverd
    // .11. .... NALU[0]&0x60
    // ...1 11.. FU indicator
    // .... ..00 reserverd
    int8_t ftv = stream->read_byte(1);
    int8_t nalu_0x60 = ftv & 0x60;
    int8_t fu_indicator = ftv & 0x1c;

    // nri, whatever
    // 10.. .... first chunk.
    // 00.. .... continous chunk.
    // 01.. .... last chunk.
    // ...1 1111 NALU[0]&0x1f
    int8_t nriv = stream->read_byte(1);
    bool first_chunk = (nriv & 0xC0) == 0x80;
    bool last_chunk = (nriv & 0xC0) == 0x40;
    bool contious_chunk = (nriv & 0xC0) == 0x00;
    int8_t nalu_0x1f = nriv & 0x1f;
    SrsSimpleBuffer* payload = get_payload();

    // chunked, generate the first byte NALU.
    if (fu_indicator == 0x1c && (first_chunk || last_chunk || contious_chunk)) {
        chunked = true;
        completed = last_chunk;

        // generate and append the first byte NALU.
        if (first_chunk) {
            int8_t nalu_byte0 = nalu_0x60 | nalu_0x1f;
            payload->append((char*)&nalu_byte0, 1);
        }
        
        payload->append((const char*)(stream->data() + stream->pos()), stream->size() - stream->pos());
        return ret;
    }

    // no chunked, append to payload.
    stream->move(-2, 0);
    payload->append((const char*)(stream->data() + stream->pos()), stream->size() - stream->pos());
    completed = true;

    return ret;
}

int SrsRtpPacket::encode(uint32_t ssrc, int pt, int channel_id, char* pdata, int len, uint32_t& sequence_num, int64_t pts)
{
    //srs_rtsp_debug("ssrc:%u, pt:%d, pdata:%p, len:%d, sequence_num:%u, pts:%"PRId64"\n", ssrc, pt, pdata, len, (int)sequence_num, pts);
    uint8_t* pbegin = (uint8_t*)pdata;
    int data_len = len;
    int pos = 0;
    int nalu_type = 0;
    int start = 1;
    int end = 0;
    int nri = 0;
    //int forbiden = 0;
    int ret = 0;
    int64_t rtsp_pts = 0;
    rtsp_pts = pts * time_scale/SRS_RTMP_PTS_TIME_BASE;
    rtsp_pts += timestamp;
    //srs_rtsp_debug("ssrc:%u, pt:%d, pdata:%p, len:%d, sequence_num:%u, pts:%"PRId64", rtsp_pts:%"PRId64", timestamp:%u, time_scale:%u/SRS_RTMP_PTS_TIME_BASE:%d\n", ssrc, pt, pdata, len, (int)sequence_num, pts, rtsp_pts, timestamp, time_scale, SRS_RTMP_PTS_TIME_BASE);
    //pts = 0;
    clear();
    if(total_sequence_number < sequence_number)
    {
        total_sequence_number = sequence_number;
    }
    if(NULL == m_prtp_packet)
    {
        m_prtp_packet = new uint8_t[SRS_MAX_MTU_SIZE];
        LB_ADD_MEM(m_prtp_packet, SRS_MAX_MTU_SIZE);
        m_nmax_rtp_packet_size = SRS_MAX_MTU_SIZE;
    }

    if(SRS_RTSP_AVC_PAYLOAD_TYPE == pt)
    {
        int start_code_size = 0;
        int frame_size = 0;
        //int offset = 0;
        lazy_avc_parser h264parser;
        const char* pnal = h264parser.get_nalu_frame((const char*)pbegin, data_len, &frame_size);//h264parser.get_frame_nalu(pbegin, data_len, &pos, &nalu_type, &start_code_size);
        if(NULL == pnal || frame_size <= 0)
        {
            srs_error("parser h264 frame failed, pnal:%p, frame_size:%d\n", pnal, frame_size);
            //srs_trace_memory((char*)pbegin, data_len > 48 ? 48:data_len);
            return 0;
        }
#if 1
        static FILE* ph264file = NULL;
        if(NULL == ph264file)
        {
            ph264file = fopen("fwd_h264.data", "wb");
        }
        if(ph264file)
        {
            fwrite(pdata, 1, len, ph264file);
        }
#endif
        pos += start_code_size;
        lazy_bitstream bs(pbegin + pos, data_len - pos);
        int forbiden = bs.read_bit(1);
        if(0 != forbiden)
        {
            srs_error("0 != forbiden:%d, NAL type error", forbiden);
            FILE* pfile = fopen("err_nal.data", "wb");
            fwrite(pdata, 1, len, pfile);
            fclose(pfile);
        }
        //assert(0 == forbiden);
        nri = bs.read_bit(2);
        nalu_type = bs.read_bit(5);
        //srs_rtsp_debug("forbiden:%d, nri:%d, nalu_type:%d, pos:%d\n", forbiden, nri, nalu_type, pos);
        //srs_trace_memory((char*)pbegin + pos, data_len - pos > 48 ? 48:data_len-pos);
        pos++;
    }
    else if(97 == pt && 0xff == *pbegin)
    {
        pbegin += 7;
        data_len -= 7;
        marker = 1;
    }

    
    while(pos < data_len)
    {
        int  pkt_body_len = m_nmax_rtp_packet_size;
        char pkthdr[256] = {0};
       
        int pktlen = data_len - pos > MAX_RTP_PACKET_SIZE ? MAX_RTP_PACKET_SIZE : data_len - pos;
        total_payload_bytes += pktlen;
        if(SRS_RTSP_AVC_PAYLOAD_TYPE == pt)
        {
            //start = pos == 0 ? 1 : 0;
            end = data_len - pos == pktlen ? 1:0;
            marker = end;
        }
        SrsSimpleBuffer* payload = next_payload();
        //int ret = 0;

        if(SRS_RTSP_AVC_PAYLOAD_TYPE == pt)
        {
            ret = encode_96(pbegin + pos, pktlen, start, end, nri, nalu_type, m_prtp_packet, &pkt_body_len);
            SRS_CHECK_VALUE(ret > 0, ret);
        }
        else if(97 == pt)
        {
           ret = encode_97(pbegin + pos, pktlen, m_prtp_packet, &pkt_body_len);
           SRS_CHECK_VALUE(ret > 0, ret);
        }
        else
        {
            srs_error("payload type %d not support now!", pt);
            return -1;
        }
        m_pbitstream->initialize(pkthdr, 256);
        /*if(SrsRtspStreamingTypeTCP == m_estreaming_type)
        {
            ret = m_pbitstream->write_byte('$', 1);
            ret = m_pbitstream->write_byte(channel_id, 1);
            ret = m_pbitstream->write_byte(pkt_body_len + FIX_RTP_HEADER_SIZE, 2);
        }*/
        // write rtp header
        ret = m_pbitstream->write_bit(version, 2); // rtp version: 2
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(padding, 1); // rtp padding bit(1bit): 0
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(extension, 1); // rtp extension header bit(1bit): 0
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(csrc_count, 4); // rtp csrc count(4bit): 0
        SRS_CHECK_RESULT(ret);
        //srs_rtsp_debug("first byte, m_pbitstream->pos():%d\n", m_pbitstream->pos());
        ret = m_pbitstream->write_bit(marker, 1); // markbit: 0: not a frame's end, 1: a frame's end
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(pt, 7); // payload type (7bits): rtp packet payload type
        SRS_CHECK_RESULT(ret);
        //srs_rtsp_debug("second byte, m_pbitstream->pos():%d\n", m_pbitstream->pos());
        ret = m_pbitstream->write_byte(total_sequence_number++%65536, 2); // sequence number (2bytes)
        SRS_CHECK_RESULT(ret);
        //srs_rtsp_debug("4 byte, m_pbitstream->pos():%d\n", m_pbitstream->pos());
        ret = m_pbitstream->write_byte(rtsp_pts, 4); // rtp packet pts
        SRS_CHECK_RESULT(ret);
        //srs_rtsp_debug("8 byte, m_pbitstream->pos():%d\n", m_pbitstream->pos());
        ret = m_pbitstream->write_byte(ssrc, 4); // rtp packet ssrc
        SRS_CHECK_RESULT(ret);
        
        //srs_rtsp_debug("version:%d, padding:%d, extension:%d, csrc_count:%d, marker:%d, pt:%d, sequence_num:%d, pts:%u, ssrc:%0x, nalu_type:%d, pos:%ld, pktlen:%d, pkt_body_len:%d\n", (int)version, (int)padding, (int)extension, (int)csrc_count, (int)marker, (int)pt, (int)sequence_num, pts, ssrc, nalu_type, m_pbitstream->pos(), pktlen, pkt_body_len);
        //srs_trace_memory(pkthdr, m_pbitstream->pos());
        payload->append(pkthdr, m_pbitstream->pos());
        payload->append((char*)m_prtp_packet, pkt_body_len);
        pos += pktlen;
        start = 0;
    }

    return 0;
}

int SrsRtpPacket::encode(uint32_t ssrc, int pt, char* pdata, int len, uint32_t& sequence_num, int64_t pts)
{
    int ret = 0;
    int64_t rtsp_pts = pts * time_scale/SRS_RTMP_PTS_TIME_BASE;
    rtsp_pts += timestamp;
    const char* psrc = pdata;
    const char* pend = pdata + len;
    const char* pnal = NULL;
    int remain_len = len;
    srs_info("ssrc:%u, pt:%d, pdata:%p, len:%d, pts:%" PRId64 ", rtsp_pts:%" PRId64 ", begin_timestamp:%u, pts_dur:%u, pts*time_scale:%u/SRS_RTMP_PTS_TIME_BASE:%d\n", ssrc, pt, pdata, len, pts, rtsp_pts, timestamp, pts - m_ulast_pts, time_scale, SRS_RTMP_PTS_TIME_BASE);
    //srs_trace_memory(pdata, 32);
    //pts = 0;
    clear();
    if(NULL == m_prtp_packet)
    {
        m_prtp_packet = new uint8_t[SRS_MAX_MTU_SIZE];
        LB_ADD_MEM(m_prtp_packet, SRS_MAX_MTU_SIZE);
        m_nmax_rtp_packet_size = SRS_MAX_MTU_SIZE;
    }

    if(NULL == m_pbitstream)
    {
        m_pbitstream = new lazy_bitstream();
        LB_ADD_MEM(m_pbitstream, sizeof(lazy_bitstream));
    }

    if(SRS_RTSP_AVC_PAYLOAD_TYPE == pt || SRS_RTSP_HEVC_PAYLOAD_TYPE == pt)
    {
        int nal_len = 0, nal_type = 0;
        lazy_xvc_stream xs(SRS_RTSP_AVC_PAYLOAD_TYPE == pt ? 4 : 5);
        while(pnal = xs.get_nal(psrc, remain_len, &nal_len, &nal_type))
        {
            //srs_rtsp_debug("pnal:%0x, nal_type:%d, nal_len:%d, pts:%" PRId64 ", rtsp_pts:% " PRId64 ", remain_len:%d\n", pnal[0], nal_type, nal_len, pts, rtsp_pts, remain_len);
            if(xs.is_sequence_header(nal_type) || xs.is_frame_nalu(nal_type))
            {
                //srs_trace_memory(pnal, 32);
                ret = encode_packet(pt, ssrc, sequence_num, rtsp_pts, (uint8_t*)pnal, nal_len);
                SRS_CHECK_RESULT(ret);
            }
            psrc = pnal + nal_len;
            remain_len = pend - pnal - nal_len;
        };

    }
    else
    {
        ret = encode_packet(pt, ssrc, sequence_num, rtsp_pts, (uint8_t*)psrc, len);
        SRS_CHECK_RESULT(ret);
    }

    return ret;
}

#if 1
/*********************************************************************************
* AU-HEADER-length
*  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
*  |   au-header-length(16bits)    |aac packet length 13bit|  0  |
*
* au-header-length: 16bit, au-header length in bits, unusally is 16
* aac packet length: 13bit, aac packet length
* reserver: 3bit, must be 0
*********************************************************************************/ 
int SrsRtpPacket::encode_97(uint8_t* pdata, int len, uint8_t* pout, int* poutlen)
{
    if(NULL == m_pbitstream || NULL == pdata || NULL == pout || NULL == poutlen)
    {
        srs_error("Invalid parameter, m_pbitstream:%p, pdata:%p, pout:%p, poutlen:%p\n", m_pbitstream, pdata, pout, poutlen);
        return -1;
    }

    m_pbitstream->initialize(pout, *poutlen);
    if(!m_pbitstream->require(4 + len))
    {
        srs_error("not enought memory buffer for encoder 97\n");
        *poutlen = 4 + len;
        return 0;
    }

    // write rtp header
    int ret = m_pbitstream->write_byte(16, 2); // aac audio au-header-length 16bits
    SRS_CHECK_RESULT(ret);
    ret = m_pbitstream->write_bit(len, 13); // rtp audio packet length(13bit): 0
    SRS_CHECK_RESULT(ret);
    ret = m_pbitstream->write_bit(0, 3); // reserve bit, must be 0
    SRS_CHECK_RESULT(ret);

    ret = m_pbitstream->write_bytes(pdata, len);
    SRS_CHECK_RESULT(ret);
    if(poutlen)
    {
        *poutlen = m_pbitstream->pos();
    }
    return m_pbitstream->pos();
}

int SrsRtpPacket::encode_96(uint8_t* pdata, int len, int start, int end, int nri, int nalu_type, uint8_t* pout, int* poutlen)
{
    int payload_type = 0;
    int ret = 0;
    if(NULL == m_pbitstream || NULL == pdata || NULL == pout || NULL == poutlen)
    {
        srs_error("Invalid parameter, m_pbitstream:%p, pdata:%p, pout:%p, poutlen:%p\n", m_pbitstream, pdata, pout, poutlen);
        return -1;
    }

    m_pbitstream->initialize(pout, *poutlen);
    if(!m_pbitstream->require(2 + len))
    {
        srs_error("not enought memory buffer for encoder 97\n");
        *poutlen = 2 + len;
        return 0;
    }
    
    if(start == 1 && end == 1)
    {
        // no fragment unit
        payload_type = nalu_type;
    }
    else
    {
        // FU-A
        payload_type = SRS_RTSP_RTP_PACKET_TYPE_FU_A;
    }
    
    // fu-a packet header
    ret = m_pbitstream->write_bit(0, 1); // forbidden bit, must be 0
    SRS_CHECK_RESULT(ret);
    ret = m_pbitstream->write_bit(nri, 2); // NAL reference idc, 3 indicate most important
    SRS_CHECK_RESULT(ret);
    ret = m_pbitstream->write_bit(payload_type, 5); // NAL reference idc, 3 indicate most important
    SRS_CHECK_RESULT(ret);
    if(SRS_RTSP_RTP_PACKET_TYPE_FU_A == payload_type)
    {
        ret = m_pbitstream->write_bit(start, 1); // start flag(1bit)
        SRS_CHECK_RESULT(ret); 
        ret = m_pbitstream->write_bit(end, 1); // end flag(1bit)
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(0, 1); // reserved bit(1bit), must be 0
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(nalu_type, 5); // payload type(5bit), must be 0
        SRS_CHECK_RESULT(ret);
        //srs_rtsp_debug("pdata:%p, len:%d, start:%d, end:%d, nri:%d, nalu_type:%d, payload_type:%d, fu header:%0x\n", pdata, len, start, end, nri, nalu_type, payload_type, (int)*(m_pbitstream->data() + m_pbitstream->pos() - 1));
    }

    ret = m_pbitstream->write_bytes(pdata, len);
    SRS_CHECK_RESULT(ret);
    if(poutlen)
    {
        *poutlen = m_pbitstream->pos();
    }
    return m_pbitstream->pos();
}
#else
int SrsRtpPacket::encode_97(uint8_t* pdata, int len)
{
    if(NULL == m_pbitstream)
    {
        return -1;
    }
    SrsSimpleBuffer* payload = get_payload();
    char pkthdr[256] = {0};
    m_pbitstream->initialize((uint8_t*)pkthdr, 256);

    // write rtp header
    int ret = m_pbitstream->write_byte(16, 2); // aac audio au-header-length 16bits
    SRS_CHECK_RESULT(ret);
    ret = m_pbitstream->write_bit(len, 13); // rtp audio packet length(13bit): 0
    SRS_CHECK_RESULT(ret);
    ret = m_pbitstream->write_bit(0, 3); // reserve bit, must be 0
    SRS_CHECK_RESULT(ret);

    if(pout && poutlen)
    {
        if(*poutlen >= m_pbitstream->pos() + len)
        {
            memcpy(pout, m_pbitstream->data(), m_pbitstream->pos());
            memcpy(pout + m_pbitstream->pos(), pdata, len);
        }
        else
        {
            return -1;
        }
        
    }
    else
    {
        payload->append((const char*)m_pbitstream->data(), m_pbitstream->pos());
        payload->append(pdata, len);
    }

    return ret;
}
int SrsRtpPacket::encode_96(uint8_t* pdata, int len, int start, int end, int nri, int nalu_type, uint8_t* pout, int* poutlen)
{
    int ret = -1;
    int payload_type = 0;
    srs_rtsp_debug("encode_96(pdata:%p, len:%d, start:%d, end:%d, nri:%d, nalu_type:%d)\n", pdata, len, start, end, nri, nalu_type);
    if(NULL == m_pbitstream)
    {
        return -1;
    }
    SrsSimpleBuffer* payload = get_payload();
    int i = 0;
    while(*(pdata +i) != 0) break;
    if(i >= 2 && *(pdata+i) == 1)
    {
        i++;
    }

    if(start == 1 && end == 1)
    {
        // no fragment unit
        payload_type = nalu_type;
    }
    else
    {
        // FU-A
        payload_type = SRS_RTSP_RTP_PACKET_TYPE_FU_A;
    }
    char fuhdr[256] = {0};
    m_pbitstream->initialize(fuhdr, 256);
    // fu-a packet header
    ret = m_pbitstream->write_bit(0, 1); // forbidden bit, must be 0
    SRS_CHECK_RESULT(ret);

    ret = m_pbitstream->write_bit(nri, 2); // NAL reference idc, 3 indicate most important
    SRS_CHECK_RESULT(ret);
    ret = m_pbitstream->write_bit(payload_type, 5); // NAL reference idc, 3 indicate most important
    SRS_CHECK_RESULT(ret);
    if(SRS_RTSP_RTP_PACKET_TYPE_FU_A == payload_type)
    {
        ret = m_pbitstream->write_bit(start, 1); // start flag(1bit)
        SRS_CHECK_RESULT(ret); 
        ret = m_pbitstream->write_bit(end, 1); // end flag(1bit)
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(0, 1); // reserved bit(1bit), must be 0
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(payload_type, 5); // payload type(5bit), must be 0
        SRS_CHECK_RESULT(ret);
    }
    payload->append(fuhdr, m_pbitstream->pos());
    
    payload->append(pdata, len);
    srs_rtsp_debug("payload->append(pdata:%p, len:%d), payload->length():%d\n", pdata, len, payload->length());
    return 0;
}
#endif

int SrsRtpPacket::encode_packet(int pt, uint32_t ssrc, uint32_t& sequence_num, int64_t pts, uint8_t* pdata, int len)
{
    int pos = 0;
    int start = 1, end = 0;
    int marker = 0;
    int rtp_pkt_len = 0;
    uint16_t seq_num = 0;
    // h264 nal param
    uint8_t forbiden = 0, nri = 0, nal_type = 0, payload_type = SRS_RTSP_HEVC_PAYLOAD_TYPE == pt ? SRS_RTSP_RTP_PACKET_TYPE_HEVC : SRS_RTSP_RTP_PACKET_TYPE_FU_A;
    // h265 nal param
    uint8_t layerid = 0, tid = 0;
    int ret = m_pbitstream->initialize(pdata, len);
    SRS_CHECK_RESULT(ret);
    
    forbiden = m_pbitstream->read_bit(1);
    if(SRS_RTSP_AVC_PAYLOAD_TYPE == pt)
    {
        nri = m_pbitstream->read_bit(2);
        nal_type = m_pbitstream->read_bit(5);
        pos = 1;
    }
    else if(SRS_RTSP_HEVC_PAYLOAD_TYPE == pt)
    {
        nal_type = m_pbitstream->read_bit(6);
        layerid = m_pbitstream->read_bit(6);
        tid = m_pbitstream->read_bit(3);
        pos = 2;
    }
    else if(SRS_RTSP_AAC_PAYLOAD_TYPE == pt)
    {
        if( 0xff == pdata[0])
        {
            pos += 7;
        }
        //srs_rtsp_debug_memory((char*)pdata, 32);
        marker = end = 1;
    }
    else
    {
        srs_error("Invalid nalu payload type:%d, pdata[0]:%0x\n", pt, (int)pdata[0]);
        
        return -1;
    }

    //srs_rtsp_debug("encode_packet(pt:%d, ssrc:%p, sequence_num:%u, pts:%" PRId64 ", pdata:%p, len:%d), nal_type:%d\n", pt, ssrc, sequence_num, pts, pdata, len, nal_type);
    //srs_trace_memory((char*)pdata, 32);
    //total_sequence_number = sequence_num;
    while(pos < len)
    {
        rtp_pkt_len = len - pos > MAX_RTP_PACKET_SIZE ? MAX_RTP_PACKET_SIZE : len - pos; 
        if((SRS_RTSP_AVC_PAYLOAD_TYPE == pt || SRS_RTSP_HEVC_PAYLOAD_TYPE == pt) && rtp_pkt_len <= MAX_RTP_PACKET_SIZE)
        {
            //start = pos == 0 ? 1 : 0;
            end = len - pos == rtp_pkt_len ? 1:0;
            marker = end;
        }
        ret = m_pbitstream->initialize(m_prtp_packet, m_nmax_rtp_packet_size);
        SRS_CHECK_RESULT(ret);
        
        SrsSimpleBuffer* payload = next_payload();

        // write rtp header
        ret = m_pbitstream->write_bit(version, 2); // rtp version: 2
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(padding, 1); // rtp padding bit(1bit): 0
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(extension, 1); // rtp extension header bit(1bit): 0
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(csrc_count, 4); // rtp csrc count(4bit): 0
        SRS_CHECK_RESULT(ret);
        //srs_rtsp_debug("first byte, m_pbitstream->pos():%d\n", m_pbitstream->pos());
        ret = m_pbitstream->write_bit(marker, 1); // markbit: 0: not a frame's end, 1: a frame's end
        SRS_CHECK_RESULT(ret);
        ret = m_pbitstream->write_bit(pt, 7); // payload type (7bits): rtp packet payload type
        SRS_CHECK_RESULT(ret);
        //srs_rtsp_debug("second byte, m_pbitstream->pos():%d\n", m_pbitstream->pos());
        seq_num = (uint16_t)(sequence_num++%65536);
        ret = m_pbitstream->write_byte(seq_num, 2); // sequence number (2bytes)
        SRS_CHECK_RESULT(ret);
        //srs_rtsp_debug("4 byte, m_pbitstream->pos():%d\n", m_pbitstream->pos());
        ret = m_pbitstream->write_byte(pts, 4); // rtp packet pts
        SRS_CHECK_RESULT(ret);
        //srs_rtsp_debug("8 byte, m_pbitstream->pos():%d\n", m_pbitstream->pos());
        ret = m_pbitstream->write_byte(ssrc, 4); // rtp packet ssrc
        SRS_CHECK_RESULT(ret);
        //srs_rtsp_debug("rtp packet len:%0x\n", rtp_pkt_len);
        if(1 == start && 1 == end && (SRS_RTSP_AVC_PAYLOAD_TYPE == pt || SRS_RTSP_HEVC_PAYLOAD_TYPE == pt))
        {
            pos = 0;
            rtp_pkt_len = len;
        }
        else if(SRS_RTSP_AVC_PAYLOAD_TYPE == pt)
        {
            // write h264 FU indicator
            // forbiden bit
            ret = m_pbitstream->write_bit(forbiden, 1);
            SRS_CHECK_RESULT(ret);
            // nalu reference idc
            ret = m_pbitstream->write_bit(nri, 2);
            SRS_CHECK_RESULT(ret);
            // payload type
            ret = m_pbitstream->write_bit(payload_type, 5);
            SRS_CHECK_RESULT(ret);
            // FU header
            // start bit
            ret = m_pbitstream->write_bit(start, 1); // start flag(1bit)
            SRS_CHECK_RESULT(ret); 
            // end bit
            ret = m_pbitstream->write_bit(end, 1); // end flag(1bit)
            SRS_CHECK_RESULT(ret);
            // reserved bit
            ret = m_pbitstream->write_bit(0, 1); // reserved bit(1bit), must be 0
            SRS_CHECK_RESULT(ret);
            // nal type
            ret = m_pbitstream->write_bit(nal_type, 5); // payload type(5bit)
            SRS_CHECK_RESULT(ret);
        }
        else if(97 == pt)
        {
            // write au-header
            ret = m_pbitstream->write_byte(16, 2); // aac audio au-header-length 16bits
            SRS_CHECK_RESULT(ret);
            ret = m_pbitstream->write_bit(rtp_pkt_len, 13); // rtp audio packet length(13bit): 0
            SRS_CHECK_RESULT(ret);
            ret = m_pbitstream->write_bit(0, 3); // reserve bit, must be 0
            SRS_CHECK_RESULT(ret);
        }
        else if(SRS_RTSP_HEVC_PAYLOAD_TYPE == pt)
        {
            if(rtp_pkt_len >= MAX_RTP_PACKET_SIZE)
            {
                rtp_pkt_len--;  
            }
            
            // write hevc FU indicator
             ret = m_pbitstream->write_bit(forbiden, 1);
            SRS_CHECK_RESULT(ret);
            // rtp payload type
            ret = m_pbitstream->write_bit(payload_type, 6);
            SRS_CHECK_RESULT(ret);
            // layer id
            ret = m_pbitstream->write_bit(layerid, 6);
            SRS_CHECK_RESULT(ret);
            // rtp nalu data tid
            ret = m_pbitstream->write_bit(tid, 3);
            SRS_CHECK_RESULT(ret);

            // FU header
            // start bit
            ret = m_pbitstream->write_bit(start, 1); // start flag(1bit)
            SRS_CHECK_RESULT(ret); 
            // end bit
            ret = m_pbitstream->write_bit(end, 1); // end flag(1bit)
            SRS_CHECK_RESULT(ret);
            // reserved bit
            ret = m_pbitstream->write_bit(0, 1); // reserved bit(1bit), must be 0
            SRS_CHECK_RESULT(ret);
            // nal type
            ret = m_pbitstream->write_bit(nal_type, 5); // payload type(5bit)
            SRS_CHECK_RESULT(ret);
            //srs_rtsp_debug("hevc m_pbitstream->pos():%d\n", m_pbitstream->pos());
        }
        else
        {
            srs_error("payload type %d not support now!", pt);
            return -1;
        }

        // write payload data
        //ret = m_pbitstream->write_bytes(pdata + pos, rtp_pkt_len);
        //SRS_CHECK_RESULT(ret);
        //sequence_num = total_sequence_number;
        //srs_rtsp_debug("write rtp header, version:%d, padding:%d, extension:%d, csrc_count:%d, marker:%d, pt:%d, sequence_num:%d, seq_num:%d, pts:%u, ssrc:%0x, start:%d, end:%d, nal_type:%d, pos:%d, rtp_pkt_len:%d\n", (int)version, (int)padding, (int)extension, (int)csrc_count, (int)marker, (int)pt, (int)sequence_num, (int)seq_num, pts, ssrc, start, end, nal_type, m_pbitstream->pos(), rtp_pkt_len);
        //srs_trace_memory((char*)m_prtp_packet, m_pbitstream->pos());
        //payload->append(pkthdr, m_pbitstream->pos());
        payload->append((char*)m_prtp_packet, m_pbitstream->pos());
        payload->append((char*)pdata + pos, rtp_pkt_len);

        pos += rtp_pkt_len;
        total_payload_bytes += rtp_pkt_len;
        start = 0;
    };

    
    return 0;
}
void SrsRtpPacket::clear()
{
    for(size_t i = 0; i < vrtp_packet_list.size(); i++)
    {
        if(vrtp_packet_list[i])
        {
            srs_freep(vrtp_packet_list[i]);
        }
    }
    vrtp_packet_list.clear();
}

void SrsRtpPacket::load_default_param()
{
    version = 2;
    padding = 0;
    extension = 0;
    csrc_count = 0;
    marker = -1;
    payload_type = 0;
    sequence_number = 0;
    timestamp = 0;

    ssrc = 0;
    /*// whether transport in chunked payload.
    bool chunked;
    // whether message is completed.
    // normal message always completed.
    // while chunked completed when the last chunk arriaved.
    bool completed;*/
}

SrsRtspSdpMediaDesc::SrsRtspSdpMediaDesc()
{
    npayload_type = 0;
    nrtsp_time_base = 90000;
    nport = 0;
    nsample_rate = 0;
    nchannel = 0;
    nbit_rate = 0;
    ntrack_num = -1;
    npacketization_mode = 0;
    local_ip = "0.0.0.0";
    /*sps = NULL;
    sps_len = 16;
    sps = new char[sps_len];

    pps_len = 4;
    pps = new char[pps_len];
    sps = {0x67, 0x42, 0x00, 0x2a, 0x96, 0x35, 0xc0, 0xf0, 0x04, 0x4f, 0xcb, 0x37, 0x01, 0x01, 0x01, 0x02};
    pps = {0x68, 0xce, 0x3c, 0x80};*/
}

SrsRtspSdpMediaDesc::~SrsRtspSdpMediaDesc()
{

}


int SrsRtspSdpMediaDesc::init_media_desc(std::string mt, int pt, int port, std::string ip, int bitrate, std::string track_name)
{
    media_type = mt;
    npayload_type = pt;
    nport = port;
    local_ip = ip;
    nbitrate = bitrate;
    track_id = track_name;

    return 0;
}

std::string SrsRtspSdpMediaDesc::gen_h264_media_desc(uint8_t* sps, int sps_len, uint8_t* pps, int pps_len)
{
#if 1
    std::stringstream ss;
    ss << "m=" << media_type << SRS_RTSP_SP << nport << " RTP/AVP " << npayload_type << SRS_RTSP_CRLF
    << "c=IN IP4 " << local_ip << SRS_RTSP_CRLF
    << "b=AS:" << nbitrate << SRS_RTSP_CRLF
    << "a=rtpmap:" <<  npayload_type << SRS_RTSP_SP << "H264" << '/' << nrtsp_time_base << SRS_RTSP_CRLF;
    npacketization_mode = 1;
    ss << "a=fmtp:" << npayload_type << SRS_RTSP_SP << "packetization-mode=" << npacketization_mode;
    if(sps && pps)
    {
        int profileLevelId = (sps[1]<<16) | (sps[2]<<8) | sps[3];
        char sps_enc[256] = {0};
        char pps_enc[256] = {0};
        srs_av_base64_encode(sps_enc, 256, sps, sps_len);
        srs_av_base64_encode(pps_enc, 256, pps, pps_len);
        
        ss << ";profile-level-id=" << string_format("%06X", profileLevelId) << ";sprop-parameter-sets=" << sps_enc << "," << pps_enc;
    }
    ss << SRS_RTSP_CRLF;
    ss << "a=control:" << track_id << SRS_RTSP_CRLF;
    string h264_desc = ss.str();
    //srs_trace("h264_desc:%s\n", h264_desc.c_str());
    return h264_desc;
#else
    

    char const* mediafmt = "m=%s %d RTP/AVP %d\r\n"
                            "c=IN IP4 %s\r\n"
                            "b=AS:%d\r\n"
                            "a=rtpmap:%d %s/%d\r\n"
                            "a=fmtp:%d packetization-mode=%d"
                            ";profile-level-id=%06X"
                            ";sprop-parameter-sets=%s,%s\r\n"
                            "a=control:%s\r\n";
    char media_buf[1024] = {0};
    char sps_enc[256] = {0};
    char pps_enc[256] = {0};
    int profileLevelId = (sps[1]<<16) | (sps[2]<<8) | sps[3];
    npacketization_mode = 1;
    
    srs_av_base64_encode(sps_enc, 256, sps, sps_len);
    srs_av_base64_encode(pps_enc, 256, pps, pps_len);
    sprintf(media_buf, mediafmt, media_type.c_str(), nport, npayload_type, local_ip.c_str(), nbitrate, npayload_type, "H264", nrtsp_time_base, npayload_type, npacketization_mode, profileLevelId, sps_enc, pps_enc, track_id.c_str());
    //srs_rtsp_debug("h264:%s\n", media_buf);
    return std::string(media_buf);
    #endif
}

std::string SrsRtspSdpMediaDesc::gen_h265_media_desc(uint8_t* vps, int vps_len, uint8_t* sps, int sps_len, uint8_t* pps, int pps_len)
{
    lazy_xvc_stream xs(5);
    std::stringstream ss;
    ss << "m=" << media_type << SRS_RTSP_SP << nport << " RTP/AVP " << npayload_type << SRS_RTSP_CRLF
    << "c=IN IP4 " << local_ip << SRS_RTSP_CRLF
    << "b=AS:" << nbitrate << SRS_RTSP_CRLF
    << "a=rtpmap:" <<  npayload_type << SRS_RTSP_SP << "H265" << '/' << nrtsp_time_base << SRS_RTSP_CRLF;
    npacketization_mode = 1;
    string evps = xs.rbsp_from_nalu((const char*)vps, vps_len);
    srs_rtsp_debug_memory(evps.data(), evps.size());
    u_int8_t const* profileTierLevelHeaderBytes = (u_int8_t const*)evps.data() + 6;
    unsigned profileSpace  = profileTierLevelHeaderBytes[0]>>6; // general_profile_space
    unsigned profileId = profileTierLevelHeaderBytes[0]&0x1F; // general_profile_idc
    unsigned tierFlag = (profileTierLevelHeaderBytes[0]>>5)&0x1; // general_tier_flag
    unsigned levelId = profileTierLevelHeaderBytes[11]; // general_level_idc
    u_int8_t const* interop_constraints = &profileTierLevelHeaderBytes[5];
    char interopConstraintsStr[100] = {0};
    sprintf(interopConstraintsStr, "%02X%02X%02X%02X%02X%02X", 
        interop_constraints[0], interop_constraints[1], interop_constraints[2],
        interop_constraints[3], interop_constraints[4], interop_constraints[5]);
    char vps_enc[256] = {0};
    char sps_enc[256] = {0};
    char pps_enc[256] = {0};
    srs_av_base64_encode(vps_enc, 256, vps, vps_len);
    srs_av_base64_encode(sps_enc, 256, sps, sps_len);
    srs_av_base64_encode(pps_enc, 256, pps, pps_len);
    //delete[] vpsWEB;
    ss << "a=fmtp:" << npayload_type << SRS_RTSP_SP
    << "profile-space=" << profileSpace << SRS_RTSP_COMMA
    << "profile-id=" << profileId << SRS_RTSP_COMMA
    << "tier-flag=" << tierFlag << SRS_RTSP_COMMA
    << "level-id=" << levelId << SRS_RTSP_COMMA
    << "interop-constraints=" << interopConstraintsStr << SRS_RTSP_COMMA
    << "sprop-vps=" << vps_enc << SRS_RTSP_COMMA
    << "sprop-sps=" << sps_enc << SRS_RTSP_COMMA
    << "sprop-pps=" << pps_enc << SRS_RTSP_COMMA;
    /*if(sps && pps)
    {
        int profileLevelId = (sps[1]<<16) | (sps[2]<<8) | sps[3];
        char vps_enc[256] = {0};
        char sps_enc[256] = {0};
        char pps_enc[256] = {0};
        srs_av_base64_encode(vps_enc, 256, vps, vps_len);
        srs_av_base64_encode(sps_enc, 256, sps, sps_len);
        srs_av_base64_encode(pps_enc, 256, pps, pps_len);
        
        ss << ";profile-level-id=" << string_format("%06X", profileLevelId) << ";sprop-parameter-sets=" << vps_enc << "," << sps_enc << "," << pps_enc;
    }*/
    ss << SRS_RTSP_CRLF;
    ss << "a=control:" << track_id << SRS_RTSP_CRLF;
    string h265_desc = ss.str();
    srs_trace("h265_desc:%s\n", h265_desc.c_str());
    return h265_desc;
}
/*std::string SrsRtspSdpMediaDesc::h264_fmtp_gen(int pt, uint8_t* sps, int sps_len, uint8_t* pps, int pps_Len)
{
    std::string fmtp_str;
    char fmtp_buf[1024] = {0};
    char* psps_enc[256] = {0};
    char* pps_enc[256] = {0};
    int profileLevelId = (sps[1]<<16) | (sps[2]<<8) | sps[3];
    char const* fmtpFmt =
    "a=fmtp:%d packetization-mode=1"
    ";profile-level-id=%06X"
    ";sprop-parameter-sets=%s,%s\r\n";
    srs_av_base64_encode(sps_enc, sps_len*2, sps, sps_len);
    srs_av_base64_encode(pps_enc, pps_len*2, pps, pps_len);
    sprintf(fmtp_buf, fmtpFmt, pt, profileLevelId, sps_enc, pps_enc);
    srs_trace("fmtp_buf:%s\n", fmtp_buf);

    return std::string(fmtp_buf);
}*/

std::string SrsRtspSdpMediaDesc::gen_mpeg4_generic_media_desc(uint8_t* pcfg, int len)
{
    char const* mediafmt = "m=%s %d RTP/AVP %d\r\n"
                            "c=IN IP4 %s\r\n"
                            "b=AS:%d\r\n"
                            "a=rtpmap:%d %s/%d\r\n"
                            "a=fmtp:%d "
                            "streamtype=%d;profile-level-id=1;"
                            "mode=%s;sizelength=13;indexlength=3;indexdeltalength=3;"
                            "config=%04X\r\n"
                            "a=control:%s\r\n";
    int audio_config = (pcfg[0]<<8) | pcfg[1];
    char media_buf[1024] = {0};
    lbsp_util::aac_parser aacparser;
    aacparser.parser_audio_specific_config(pcfg, len);
    //lbsp_util::CAacConfig aaccfg;
    //aaccfg.parser_audio_specific_config(pcfg, len);
    sprintf(media_buf, mediafmt, media_type.c_str(), nport, npayload_type, local_ip.c_str(), nbitrate, npayload_type, 
    "MPEG4-GENERIC", aacparser.sample_rate(), npayload_type, media_type == "video" ? 4 : 5, "AAC-hbr", audio_config, track_id.c_str());
    //srs_rtsp_debug("mpeg4 aac:%s\n", media_buf);
    return std::string(media_buf);
}

SrsRtspSdp::SrsRtspSdp()
{
    state = SrsRtspSdpStateOthers;
}

SrsRtspSdp::~SrsRtspSdp()
{
}

int SrsRtspSdp::parse(string token)
{
    int ret = ERROR_SUCCESS;

    if (token.empty()) {
        srs_info("rtsp: ignore empty token.");
        return ret;
    }
    
    size_t pos = string::npos;

    char* start = (char*)token.data();
    char* end = start + (int)token.length();
    char* p = start;

    // key, first 2bytes.
    // v=0
    // o=- 0 0 IN IP4 127.0.0.1
    // s=No Name
    // c=IN IP4 192.168.43.23
    // t=0 0
    // a=tool:libavformat 53.9.0
    // m=video 0 RTP/AVP 96
    // b=AS:850
    // a=rtpmap:96 H264/90000
    // a=fmtp:96 packetization-mode=1; sprop-parameter-sets=Z2QAKKzRwFAFu/8ALQAiEAAAAwAQAAADAwjxgxHg,aOmrLIs=
    // a=control:streamid=0
    // m=audio 0 RTP/AVP 97
    // b=AS:49
    // a=rtpmap:97 MPEG4-GENERIC/44100/2
    // a=fmtp:97 profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3; config=139056E5A0
    // a=control:streamid=1
    char key = p[0];
    p += 2;

    // left bytes as attr string.
    std::string attr_str;
    if (end - p) {
        attr_str.append(p, end - p);
    }

    // parse the attributes from left bytes.
    std::vector<std::string> attrs;
    while (p < end) {
        // parse an attribute, split by SP.
        char* pa = p;
        for (; p < end && p[0] != SRS_RTSP_SP; p++) {
        }
        std::string attr;
        if (p > pa) {
            attr.append(pa, p - pa);
            attrs.push_back(attr);
        }
        p++;
    }

    // parse the first attr as desc, update the first elem for desc.
    // for example, the value can be "tool", "AS", "rtpmap", "fmtp", "control"
    std::string desc_key;
    if (attrs.size() > 0) {
        std::string attr = attrs.at(0);
        if ((pos = attr.find(":")) != string::npos) {
            desc_key = attr.substr(0, pos);
            attr = attr.substr(pos + 1);
            attr_str = attr_str.substr(pos + 1);
            attrs[0] = attr;
        } else {
            desc_key = attr;
        }
    }

    // interpret the attribute according by key.
    switch (key) {
        case 'v': version = attr_str; break;
        case 'o':
            owner_username = (attrs.size() > 0)? attrs[0]:"";
            owner_session_id = (attrs.size() > 1)? attrs[1]:"";
            owner_session_version = (attrs.size() > 2)? attrs[2]:"";
            owner_network_type = (attrs.size() > 3)? attrs[3]:"";
            owner_address_type = (attrs.size() > 4)? attrs[4]:"";
            owner_address = (attrs.size() > 5)? attrs[5]:"";
            break;
        case 's': session_name = attr_str; break;
        case 'c':
            connection_network_type = (attrs.size() > 0)? attrs[0]:"";
            connection_address_type = (attrs.size() > 0)? attrs[0]:"";
            connection_address = (attrs.size() > 0)? attrs[0]:"";
            break;
        case 'a':
            if (desc_key == "tool") {
                tool = attr_str;
            } else if (desc_key == "rtpmap") {
                if (state == SrsRtspSdpStateVideo) {
                    video_codec = (attrs.size() > 1)? attrs[1]:"";
                    if ((pos = video_codec.find("/")) != string::npos) {
                        video_sample_rate = video_codec.substr(pos + 1);
                        video_codec = video_codec.substr(0, pos);
                    }
                } else if (state == SrsRtspSdpStateAudio) {
                    audio_codec = (attrs.size() > 1)? attrs[1]:"";
                    if ((pos = audio_codec.find("/")) != string::npos) {
                        audio_sample_rate = audio_codec.substr(pos + 1);
                        audio_codec = audio_codec.substr(0, pos);
                    }
                    if ((pos = audio_sample_rate.find("/")) != string::npos) {
                        audio_channel = audio_sample_rate.substr(pos + 1);
                        audio_sample_rate = audio_sample_rate.substr(0, pos);
                    }
                }
            } else if (desc_key == "fmtp") {
                for (int i = 1; i < (int)attrs.size(); i++) {
                    std::string attr = attrs.at(i);
                    if ((ret = parse_fmtp_attribute(attr)) != ERROR_SUCCESS) {
                        srs_error("rtsp: parse fmtp failed, attr=%s. ret=%d", attr.c_str(), ret);
                        return ret;
                    }
                }
            } else if (desc_key == "control") {
                for (int i = 0; i < (int)attrs.size(); i++) {
                    std::string attr = attrs.at(i);
                    if ((ret = parse_control_attribute(attr)) != ERROR_SUCCESS) {
                        srs_error("rtsp: parse control failed, attr=%s. ret=%d", attr.c_str(), ret);
                        return ret;
                    }
                }
            }
            break;
        case 'm':
            if (desc_key == "video") {
                state = SrsRtspSdpStateVideo;
                video_port = (attrs.size() > 1)? attrs[1]:"";
                video_protocol = (attrs.size() > 2)? attrs[2]:"";
                video_transport_format = (attrs.size() > 3)? attrs[3]:"";
            } else if (desc_key == "audio") {
                state = SrsRtspSdpStateAudio;
                audio_port = (attrs.size() > 1)? attrs[1]:"";
                audio_protocol = (attrs.size() > 2)? attrs[2]:"";
                audio_transport_format = (attrs.size() > 3)? attrs[3]:"";
            }
            break;
        case 'b':
            if (desc_key == "AS") {
                if (state == SrsRtspSdpStateVideo) {
                    video_bandwidth_kbps = (attrs.size() > 0)? attrs[0]:"";
                } else if (state == SrsRtspSdpStateAudio) {
                    audio_bandwidth_kbps = (attrs.size() > 0)? attrs[0]:"";
                }
            }
            break;
        case 't':
        default: break;
    }

    return ret;
}

int SrsRtspSdp::init_sdp(std::string address, std::string sessionname, std::string mediatitle)
{
    srs_rtsp_debug("init_sdp(address:%s, sessionname:%s, mediatitle:%s)\n", address.c_str(), sessionname.c_str(), mediatitle.c_str());
    owner_address = address;
    session_name = sessionname;
    media_title = mediatitle;
    m_sdp_desc.clear();
    //encode(NULL);
    return 0;
}

int SrsRtspSdp::encode(std::stringstream* ss)
{
    if(m_sdp_desc.empty())
    {
        char const* const sdpPrefixFmt =
        "v=0\r\n"
        "o=- %ld%06ld %d IN IP4 %s\r\n"
        "s=%s\r\n"
        "i=%s\r\n"
        "t=0 0\r\n"
        "a=tool:%s%s\r\n"
        "a=type:broadcast\r\n"
        "a=control:*\r\n"
        "a=range:npt=0-\r\n"
        "a=x-qt-text-nam:%s\r\n"
        "a=x-qt-text-inf:%s\r\n";
        /*"m=video 0 RTP/AVP 33\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "b=AS:5000\r\n"
        "a=control:track1\r\n";*/
        char sdp_desc[4096] = {0};
        struct timeval tv;
        gettimeofday(&tv, NULL);
        snprintf(sdp_desc, 4096, sdpPrefixFmt, tv.tv_sec, tv.tv_usec, 1, owner_address.c_str(), session_name.c_str(), media_title.c_str(), SRS_RTSP_SERVER_NAME, SRS_RTSP_SERVER_VERSION_STRING, session_name.c_str(), media_title.c_str());
        m_sdp_desc = sdp_desc + m_sdp_media_video + m_sdp_media_audio;
        //srs_rtsp_debug("sdp:%0x, sdp_desc:%s\nm_sdp_media_video:%s\nm_sdp_media_audio:%d\n", this, sdp_desc, m_sdp_media_video.c_str(), m_sdp_media_audio.c_str());
    }
    if(ss)
    {
        //srs_rtsp_debug("m_sdp_desc\n%s\nm_sdp_media_video:%s\nm_sdp_media_audio:%s\n", m_sdp_desc.c_str(), m_sdp_media_video.c_str(), m_sdp_media_audio.c_str());
        *ss << m_sdp_desc;
    }
    
    return 0;
     /*ss << "v=" << version << SRS_RTSP_CRLF
     << "o" << owner_username <<  SRS_RTSP_SP
     << owner_session_id << SRS_RTSP_SP
     << owner_session_version << SRS_RTSP_SP
     << owner_network_type << SRS_RTSP_SP
     << owner_address_type << SRS_RTSP_SP
     << owner_address << SRS_RTSP_CRLF
     << "s=" << session_name << SRS_RTSP_CRLF
     << "i=" << media_title << SRS_RTSP_CRLF
     << "t=0 0" << SRS_RTSP_CRLF
     << "a=tool:" << tool << SRS_RTSP_CRLF
     << "a=type:broadcast" << SRS_RTSP_CRLF
     << "a=control:*" << SRS_RTSP_CRLF
     << "a=range:npt=0-" << SRS_RTSP_CRLF
     << "a=x-qt-text-nam:" << session_name << SRS_RTSP_CRLF
     << "a=x-qt-text-inf:" << media_title << SRS_RTSP_CRLF
     << "m=video 0 RTP/AVP 33" << SRS_RTSP_CRLF
     << "c=IN IP4 0.0.0.0" << SRS_RTSP_CRLF
      << "b=AS:5000" << SRS_RTSP_CRLF
      << "a=control:track1" << SRS_RTSP_CRLF;

      return 0;*/
}

int SrsRtspSdp::length()
{
    return m_sdp_desc.length();
}

int SrsRtspSdp::add_media_video(std::string mt, int port, int pt,  std::string track_name, uint8_t* vps, int vps_len, uint8_t* sps, int sps_len, uint8_t* pps, int pps_len)
{
    SrsRtspSdpMediaDesc media_desc;
    //init_media_desc(std::string mt, int pt, int port, std::string ip, int bitrate, std::string track_name);
    int ret = media_desc.init_media_desc(mt, pt, port, "0.0.0.0", 500, track_name);
    //lbtrace("ret:%d = media_desc.init_media_desc(mt:%s, pt:%d, port:%d, 0.0.0.0, 500, track_name:%s)\n", ret, mt.c_str(), pt, port, track_name.c_str());
    if(SRS_RTSP_AVC_PAYLOAD_TYPE == pt)
    {
        // h.264
        m_sdp_media_video = media_desc.gen_h264_media_desc(sps, sps_len, pps, pps_len);
        //lbtrace("m_sdp_media_video:%s = media_desc.gen_h264_media_desc(sps:%p, sps_len:%d, pps:%p, pps_len:%d)\n", m_sdp_media_video.c_str(), sps, sps_len, pps, pps_len);
    }
    else if(SRS_RTSP_HEVC_PAYLOAD_TYPE == pt)
    {
        //h.265
        m_sdp_media_video = media_desc.gen_h265_media_desc(vps, vps_len, sps, sps_len, pps, pps_len);
    }
    //srs_rtsp_debug("sdp:%0x, m_sdp_media_video:%s\n", this, m_sdp_media_video.c_str());
    return m_sdp_media_video.empty() ? -1 : 0;
}

int SrsRtspSdp::add_media_audio(std::string mt, int port, int pt, std::string track_name, uint8_t* pcfg, int cfg_len)
{
    SrsRtspSdpMediaDesc media_desc;
    //init_media_desc(std::string mt, int pt, int port, std::string ip, int bitrate, std::string track_name);
    media_desc.init_media_desc(mt, pt, port, "0.0.0.0", 96, track_name);
    m_sdp_media_audio = media_desc.gen_mpeg4_generic_media_desc(pcfg, cfg_len);
    //srs_rtsp_debug("sdp:%0x, m_sdp_media_audio:%s\n", this, m_sdp_media_audio.c_str());
    return m_sdp_media_audio.empty() ? -1 : 0;
}

int SrsRtspSdp::parse_fmtp_attribute(string attr)
{
    int ret = ERROR_SUCCESS;
    
    size_t pos = string::npos;
    std::string token = attr;

    while (!token.empty()) {
        std::string item = token;
        if ((pos = item.find(";")) != string::npos) {
            item = token.substr(0, pos);
            token = token.substr(pos + 1);
        } else {
            token = "";
        }

        std::string item_key = item, item_value;
        if ((pos = item.find("=")) != string::npos) {
            item_key = item.substr(0, pos);
            item_value = item.substr(pos + 1);
        }

        if (state == SrsRtspSdpStateVideo) {
            if (item_key == "packetization-mode") {
                video_packetization_mode = item_value;
            } else if (item_key == "sprop-parameter-sets") {
                video_sps = item_value;
                if ((pos = video_sps.find(",")) != string::npos) {
                    video_pps = video_sps.substr(pos + 1);
                    video_sps = video_sps.substr(0, pos);
                }
                // decode the sps/pps by base64
                video_sps = base64_decode(video_sps);
                video_pps = base64_decode(video_pps);
            }
        } else if (state == SrsRtspSdpStateAudio) {
            if (item_key == "profile-level-id") {
                audio_profile_level_id = item_value;
            } else if (item_key == "mode") {
                audio_mode = item_value;
            } else if (item_key == "sizelength") {
                audio_size_length = item_value;
            } else if (item_key == "indexlength") {
                audio_index_length = item_value;
            } else if (item_key == "indexdeltalength") {
                audio_index_delta_length = item_value;
            } else if (item_key == "config") {
                if (item_value.length() <= 0) {
                    ret = ERROR_RTSP_AUDIO_CONFIG;
                    srs_error("rtsp: audio config failed. ret=%d", ret);
                    return ret;
                }

                char* tmp_sh = new char[item_value.length()];
                LB_ADD_MEM(tmp_sh, item_value.length());
                SrsAutoFreeA(char, tmp_sh);
                int nb_tmp_sh = ff_hex_to_data((u_int8_t*)tmp_sh, item_value.c_str());
                srs_assert(nb_tmp_sh > 0);
                audio_sh.append(tmp_sh, nb_tmp_sh);
            }
        }
    }

    return ret;
}

int SrsRtspSdp::parse_control_attribute(string attr)
{
    int ret = ERROR_SUCCESS;
    
    size_t pos = string::npos;
    std::string token = attr;

    while (!token.empty()) {
        std::string item = token;
        if ((pos = item.find(";")) != string::npos) {
            item = token.substr(0, pos);
            token = token.substr(pos + 1);
        } else {
            token = "";
        }

        std::string item_key = item, item_value;
        if ((pos = item.find("=")) != string::npos) {
            item_key = item.substr(0, pos);
            item_value = item.substr(pos + 1);
        }

        if (state == SrsRtspSdpStateVideo) {
            if (item_key == "streamid") {
                video_stream_id = item_value;
            }
        } else if (state == SrsRtspSdpStateAudio) {
            if (item_key == "streamid") {
                audio_stream_id = item_value;
            }
        }
    }

    return ret;
}

string SrsRtspSdp::base64_decode(string value)
{
    if (value.empty()) {
        return "";
    }

    int nb_output = (int)(value.length() * 2);
    u_int8_t* output = new u_int8_t[nb_output];
    LB_ADD_MEM(output, nb_output);
    SrsAutoFreeA(u_int8_t, output);

    int ret = srs_av_base64_decode(output, (char*)value.c_str(), nb_output);
    if (ret <= 0) {
        return "";
    }

    std::string plaintext;
    plaintext.append((char*)output, ret);
    return plaintext;
}

SrsRtspTransport::SrsRtspTransport()
{
    client_port_min = 0;
    client_port_max = 0;
    rtp_channel_id = 0;
    rtcp_channel_id = 0;
}

SrsRtspTransport::~SrsRtspTransport()
{
}

int SrsRtspTransport::parse(string attr)
{
    int ret = ERROR_SUCCESS;
    
    size_t pos = string::npos;
    std::string token = attr;

    while (!token.empty()) {
        std::string item = token;
        if ((pos = item.find(";")) != string::npos) {
            item = token.substr(0, pos);
            token = token.substr(pos + 1);
        } else {
            token = "";
        }

        std::string item_key = item, item_value;
        if ((pos = item.find("=")) != string::npos) {
            item_key = item.substr(0, pos);
            item_value = item.substr(pos + 1);
        }

        if (transport.empty()) {
            transport = item_key;
            if ((pos = transport.find("/")) != string::npos) {
                profile = transport.substr(pos + 1);
                transport = transport.substr(0, pos);
            }
            if ((pos = profile.find("/")) != string::npos) {
                lower_transport = profile.substr(pos + 1);
                profile = profile.substr(0, pos);
            }
        }

        if (item_key == "unicast" || item_key == "multicast") {
            cast_type = item_key;
        } else if (item_key == "mode") {
            mode = item_value;
        } else if (item_key == "client_port") {
            std::string sport = item_value;
            std::string eport = item_value;
            if ((pos = eport.find("-")) != string::npos) {
                sport = eport.substr(0, pos);
                eport = eport.substr(pos + 1);
            }
            client_port_min = ::atoi(sport.c_str());
            client_port_max = ::atoi(eport.c_str());
        }
        else if(item_key == "interleaved")
        {
           sscanf(item_value.c_str(), "%u-%u", &rtp_channel_id, &rtcp_channel_id);
           //srs_rtsp_debug("interleaved:item_value:%s, rtp_channel_id:%u, rtcp_channel_id:%u\n", item_value.c_str(), rtp_channel_id, rtcp_channel_id);
        }
    }

    return ret;
}

int SrsRtspAuthorization::parser(std::string attr)
{
    std::string next_item;
    //srs_rtsp_debug("parser(attr:%s)\n", attr.c_str());
    m_mkey_val_list.clear();
    attr = srs_string_trim_start(attr, " ");//string_trim(attr, " ");

    int ret = string_split(attr, next_item, " ");
    //srs_rtsp_debug("ret:%d = string_split(attr:%s, next_item:%s, \" \")\n", ret, attr.c_str(), next_item.c_str());
    SRS_CHECK_RESULT(ret);
    do
    {
        //srs_rtsp_debug("attr:%s\n", attr.c_str());
        ret = string_split(attr, next_item, ",");
        srs_rtsp_debug("ret:%d = string_split(attr:%s, next_item:%s, \" \")\n", ret, attr.c_str(), next_item.c_str());
        //SRS_CHECK_RESULT(ret);
        if(!next_item.empty())
        {
           ret = read_key_value_pair(next_item);
           SRS_CHECK_RESULT(ret);
        }
    }while(!attr.empty());
    
    return m_mkey_val_list.size() > 0 ? ERROR_SUCCESS : -1;
}

int SrsRtspAuthorization::read_key_value_pair(std::string attr)
{
    std::string key;
    int ret = string_split(attr, key, "=");
    key = srs_string_trim(key, " ");
    attr =  srs_string_trim(attr, "\"");
    /*size_t pos1 = attr.find_first_not_of("=");
    size_t pos2 = attr.find_last_not_of("=");
    pos1 = pos1 == string::npos ? 0 : pos1;
    pos2 = pos2 == string::npos ? attr.length() : pos2 + 1;

    std::string trim_str =  attr.substr(pos1, pos2);
    srs_rtsp_debug("trim_str:%s =  str.substr(pos1:%d, pos2:%d), attr:%s\n", trim_str.c_str(), pos1, pos2, attr.c_str());*/
    SRS_CHECK_RESULT(ret);
    m_mkey_val_list[key] = attr;
    srs_rtsp_debug("key:%s, val:%s, size:%d\n", key.c_str(), attr.c_str(), m_mkey_val_list.size());

    return ret;
}

std::string SrsRtspAuthorization::gen_response_by_pwd(const std::string& cmd, const std::string& url, const std::string& username, const std::string& pwd)
{
    std::map<std::string, std::string>::iterator it = m_mkey_val_list.find("realm");
    if(it == m_mkey_val_list.end())
    {
        return std::string();
    }

    std::string org_str = username + ":" + it->second + ":" + pwd;
    std::string hash1 = lbsp_util::CMD5Maker::gen_md5_by_string(org_str);
    //srs_rtsp_debug("hash1:%s, org_str:%s", hash1.c_str(), org_str.c_str());

    std::string org_str2 = cmd + ":" +  url;
    std::string hash2 = lbsp_util::CMD5Maker::gen_md5_by_string(org_str2);
    //srs_rtsp_debug("hash2:%s, org_str2:%s", hash2.c_str(), org_str2.c_str());
    it = m_mkey_val_list.find("nonce");
    if(it == m_mkey_val_list.end())
    {
        return std::string();
    }

    std::string org_str3 = hash1 + ":" + it->second + ":" + hash2;
    std::string hash3 = lbsp_util::CMD5Maker::gen_md5_by_string(org_str3);
    //srs_rtsp_debug("hash3:%s, org_str3:%s", hash3.c_str(), org_str3.c_str());
    return hash3;
}
std::string  SrsRtspAuthorization::get_attribute(std::string attr_name)
{
    std::string value;
    if(!attr_name.empty())
    {
        std::map<std::string, std::string>::iterator it = m_mkey_val_list.find(attr_name);
        if(m_mkey_val_list.end() != it)
        {
            value = it->second;
        }
    }

    return value;
}

SrsRtspRequest::SrsRtspRequest()
{
    seq = 0;
    content_length = 0;
    stream_id = 0;
    sdp = NULL;
    transport = NULL;
    start_range = -1.0;
    stop_range  = -1.0;
	pauthorize = NULL;
}

SrsRtspRequest::~SrsRtspRequest()
{
    srs_freep(sdp);
    srs_freep(transport);
}

bool SrsRtspRequest::is_options()
{
    return method == SRS_METHOD_OPTIONS;
}

bool SrsRtspRequest::is_announce()
{
    return method == SRS_METHOD_ANNOUNCE;
}

bool SrsRtspRequest::is_setup()
{
    return method == SRS_METHOD_SETUP;
}

bool SrsRtspRequest::is_record()
{
    return method == SRS_METHOD_RECORD;
}

bool SrsRtspRequest::is_describe()
{
    return method == SRS_METHOD_DESCRIBE;
}
bool SrsRtspRequest::is_play()
{
    return method == SRS_METHOD_PLAY;
}

bool SrsRtspRequest::is_shutdown()
{
    return method == SRS_METHOD_TEARDOWN;
}

bool SrsRtspRequest::is_rtcp()
{
    return method == SRS_TOKEN_RTCP;
}

SrsRtspResponse::SrsRtspResponse(int cseq)
{
    seq = cseq;
    status = SRS_CONSTS_RTSP_OK;
    start_range = -1.0;
    stop_range  = -1.0;
    session_timeout = 0;
	sdp = NULL;
}

SrsRtspResponse::~SrsRtspResponse()
{
}

int SrsRtspResponse::encode(stringstream& ss)
{
    int ret = ERROR_SUCCESS;
    char datebuf[256] = {0};
    time_t tt = time(NULL);
    strftime(datebuf, sizeof(datebuf), "%a, %b %d %Y %H:%M:%S GMT", gmtime(&tt));
    // status line
    ss << SRS_RTSP_VERSION << SRS_RTSP_SP 
        << status << SRS_RTSP_SP 
        << srs_generate_rtsp_status_text(status) << SRS_RTSP_CRLF;

    // cseq
    ss << SRS_RTSP_TOKEN_CSEQ << ":" << SRS_RTSP_SP << seq << SRS_RTSP_CRLF;

    //date
    //ss << SRS_RTSP_TOKEN_DATE << ":" << SRS_RTSP_SP << datebuf << SRS_RTSP_CRLF;

    // play range
    char start_str[100] = {0};
    char end_str[100] = {0};
    sprintf(start_str, "%.3lf", start_range);
    sprintf(end_str, "%.3lf", stop_range);
    srs_rtsp_debug("start_range:%lf, stop_range:%lf, start_str:%s, end_str:%s\n", start_range, stop_range, start_str, end_str);
    if(start_range >= 0.0)
    {
        
        ss << SRS_RTSP_TOKEN_RANGE << ":" << SRS_RTSP_SP << "npt=" << start_str << "-";
        if(stop_range > 0)
        {
            ss << end_str;
        }
        ss << SRS_RTSP_CRLF;
    }
    if(!ext_hdr.empty())
    {
        ss << ext_hdr << SRS_RTSP_CRLF;
    }
    // others.
    /*ss << "Cache-Control: no-store" << SRS_RTSP_CRLF
        << "Pragma: no-cache" << SRS_RTSP_CRLF
        << "Server: " << RTMP_SIG_SRS_SERVER << SRS_RTSP_CRLF;*/

    if ((ret = encode_header(ss)) != ERROR_SUCCESS) {
        srs_error("rtsp: encode header failed. ret=%d", ret);
        return ret;
    };
    // session if specified.
    if (!session.empty()) {
        ss << SRS_RTSP_TOKEN_SESSION << ": " << session;
        if(session_timeout > 0)
        {
            ss << ";timeout=" << session_timeout;
        }
        ss << SRS_RTSP_CRLF;
    }

    // RTP-Info
    if(0 != vrtp_info_list.size())
    {
        ss << SRS_RTSP_TOKEN_RTP_INFO << ":" << SRS_RTSP_SP ;
        for(size_t i = 0; i < vrtp_info_list.size(); i++)
        {
            ss << "url="<< vrtp_info_list[i].url << ";";
            ss << "seq="<< vrtp_info_list[i].seq_number << ";";
            ss << "rtptime="<< vrtp_info_list[i].rtp_timestamp;
            if(i < vrtp_info_list.size() - 1)
            {
                ss << ",";
            }
            
        }
        ss << SRS_RTSP_CRLF;
    }
    // header EOF.
    ss << SRS_RTSP_CRLF;
    //srs_rtsp_debug("rtsp response %s\n", ss.str().c_str());
    return ret;
}

int SrsRtspResponse::encode_header(std::stringstream& ss)
{
    return ERROR_SUCCESS;
}

SrsRtspOptionsResponse::SrsRtspOptionsResponse(int cseq) : SrsRtspResponse(cseq)
{
    methods = (SrsRtspMethod)(SrsRtspMethodDescribe | SrsRtspMethodOptions 
        | SrsRtspMethodPause | SrsRtspMethodPlay | SrsRtspMethodSetup | SrsRtspMethodTeardown
        | SrsRtspMethodAnnounce | SrsRtspMethodRecord);
}

SrsRtspOptionsResponse::~SrsRtspOptionsResponse()
{
}

int SrsRtspOptionsResponse::encode_header(stringstream& ss)
{
    SrsRtspMethod rtsp_methods[] = {
        SrsRtspMethodDescribe,
        SrsRtspMethodAnnounce,
        SrsRtspMethodGetParameter,
        SrsRtspMethodOptions,
        SrsRtspMethodPause,
        SrsRtspMethodPlay,
        SrsRtspMethodRecord,
        SrsRtspMethodRedirect,
        SrsRtspMethodSetup,
        SrsRtspMethodSetParameter,
        SrsRtspMethodTeardown,
    };

    ss << SRS_RTSP_TOKEN_PUBLIC << ":" << SRS_RTSP_SP;

    bool appended = false;
    int nb_methods = (int)(sizeof(rtsp_methods) / sizeof(SrsRtspMethod));
    for (int i = 0; i < nb_methods; i++) {
        SrsRtspMethod method = rtsp_methods[i];
        if (((int)methods & (int)method) != (int)method) {
            continue;
        }

        if (appended) {
            ss << ", ";
        }
        ss << srs_generate_rtsp_method_str(method);
        appended = true;
    }
    ss << SRS_RTSP_CRLF;

    return ERROR_SUCCESS;
}

SrsRtspSetupResponse::SrsRtspSetupResponse(int seq) : SrsRtspResponse(seq)
{
    local_port_min = 0;
    local_port_max = 0;
}

SrsRtspSetupResponse::~SrsRtspSetupResponse()
{
}

int SrsRtspSetupResponse::set_transport_protocol(std::string protocol, std::string dst_ip, std::string src_ip, int rtp_id, int rtcp_id, uint32_t sess_timeout)
{
    lower_trasport = protocol;
    destination_ip = dst_ip;
    source_ip = src_ip;
    rtp_channel_id = rtp_id;
    rtcp_channel_id = rtcp_id;
    session_timeout = sess_timeout;

    return 0;
}

int SrsRtspSetupResponse::encode_header(stringstream& ss)
{
    //ss << SRS_RTSP_TOKEN_SESSION << ":" << SRS_RTSP_SP << session << SRS_RTSP_CRLF;
    ss << SRS_RTSP_TOKEN_TRANSPORT << ":" << SRS_RTSP_SP ;
    if(lower_trasport == "TCP")
    {
        ss << "RTP/AVP/TCP;unicast;destination=" << destination_ip << ";source=" << source_ip << ";interleaved="
        << rtp_channel_id << "-" << rtcp_channel_id
        << SRS_RTSP_CRLF;
    }
    else
    {
        ss << "RTP/AVP;unicast;client_port=" << client_port_min << "-" << client_port_max << ";"
        << "server_port=" << local_port_min << "-" << local_port_max
        << SRS_RTSP_CRLF;
    }
       
    return ERROR_SUCCESS;
}

SrsRtspDescribeResponse::SrsRtspDescribeResponse(int seq):SrsRtspResponse(seq)
{

}

int SrsRtspDescribeResponse::init_sdp(std::string address, std::string sessionname, std::string mediatitle)
{
    if(NULL == sdp)
    {
        sdp = new SrsRtspSdp();
        LB_ADD_MEM(sdp, sizeof(SrsRtspSdp));
    }

    sdp->init_sdp(address, sessionname, mediatitle);
    return 0;
}

int SrsRtspDescribeResponse::add_media_video(std::string mt, int port, int pt,  std::string track_name, uint8_t* vps, int vps_len, uint8_t* sps, int sps_len, uint8_t* pps, int pps_len)
{
    if(NULL == sdp)
    {
        sdp = new SrsRtspSdp();
        LB_ADD_MEM(sdp, sizeof(SrsRtspSdp));
    }
    return sdp->add_media_video(mt, port, pt, track_name, vps, vps_len, sps, sps_len, pps, pps_len);
}

int SrsRtspDescribeResponse::add_media_audio(std::string mt, int port, int pt, std::string track_name, uint8_t* pcfg, int cfg_len)
{
     if(NULL == sdp)
    {
        sdp = new SrsRtspSdp();
        LB_ADD_MEM(sdp, sizeof(SrsRtspSdp));
    }
    return sdp->add_media_audio(mt, port, pt, track_name, pcfg, cfg_len);
}

int SrsRtspDescribeResponse::encode(std::stringstream& ss)
{
    int ret = SrsRtspResponse::encode(ss);
    //srs_rtsp_debug("ret:%d = SrsRtspResponse::encode(ss), sdp:%p\n", ret, sdp);
    if(ERROR_SUCCESS != ret)
    {
        srs_error("ret:%d = SrsRtspResponse::encode(ss) failed\n", ret);
        return ret;
    }

    if(sdp)
    {
        ret = sdp->encode(&ss);
        if(ERROR_SUCCESS != ret)
        {
            srs_error("ret:%d = sdp->encode(ss) failed\n", ret);
            return ret;
        }

        std::string desc_resp = ss.str();
        //srs_rtsp_debug("desc_resp:%s\n", desc_resp.c_str());
    }
    return ret;
}


int SrsRtspDescribeResponse::encode_header(std::stringstream& ss)
{
    ss << "Content-Base: " << content_base << SRS_RTSP_CRLF;
    if(sdp)
    {
        sdp->encode(NULL);
        ss << "Content-Type: application/sdp" << SRS_RTSP_CRLF
        << "Content-Length: " << sdp->length() << SRS_RTSP_CRLF;
    }
    
    return 0;
}

rtsp_over_tcp_packet::rtsp_over_tcp_packet()
{
    nchannel_id = -1;
    nlength = 0;
}

rtsp_over_tcp_packet::~rtsp_over_tcp_packet()
{

}

int rtsp_over_tcp_packet::encode_header(int channel_id, int in_len, void* pout, int& out_len)
{
    uint8_t* pdst = (uint8_t*)pout;
    if(NULL == pout || out_len >= 4)
    {
        lberror("(NULL == pout:%p || out_len:%d >= 4\n", pout, out_len);
        return -1;
    }

    pdst[0] = 0x24;
    pdst[1] = (uint8_t)channel_id;
    pdst[2] = 0xff & (in_len >> 8);
    pdst[3] = in_len & 0xff;

    return 0;
}

int rtsp_over_tcp_packet::decode_header(const void* pin, int in_len)
{
    const uint8_t* psrc = (const uint8_t*) pin;
    if(NULL == pin || in_len < 4 || 0x24 != psrc[0])
    {
        lberror("Invalid parameter, NULL == pin:%p || in_len:%d < 4, psrc[0]:%0x\n", pin, in_len, psrc ? psrc[0] : 0);
        return -1;
    }

    assert(0x24 == psrc[0]);
    nchannel_id = psrc[1];
    nlength = (psrc[2] << 8) + psrc[3];

    return 0;
}

int rtsp_over_tcp_packet::encode(int channel_id, const void* pin, int in_len, void* pout, int& out_len)
{
    //const uint8_t* psrc = (const uint8_t*)pin;
    uint8_t* pdst = (uint8_t*)pout;
    if(NULL == pin || NULL == pout || in_len > out_len - 4)
    {
        lberror("NULL == pin:%p || NULL == pout:%p || in_len:%d > out_len:%d - 4\n", pin, pout, in_len, out_len);
        return -1;
    }
    pdst[0] = 0x24;
    pdst[1] = (uint8_t)channel_id;
    pdst[2] = 0xff & (in_len >> 8);
    pdst[3] = in_len & 0xff;
    memcpy(pdst + 4, pin, in_len);
    out_len = in_len;
    return 0;
}

int rtsp_over_tcp_packet::decode(const void* pdata, int len, void* pout, int& out_len)
{
    const uint8_t* psrc = (const uint8_t*) pdata;
    if(NULL == pdata || len < 4 || 0x24 == psrc[0])
    {
        lberror("Invalid parameter, NULL == pdata:%p || len:%d < 4, psrc[0]:%0x\n", pdata, len, psrc ? psrc[0] : 0);
        return -1;
    }
    int ret = decode_header(pdata, len);
    if(ret < 0 || len - 4 < nlength)
    {
        lberror("ret:%d = decode_header(pdata:%p, len:%d) failed or len - 4 < nlength:%d\n", ret, pdata, len, nlength);
        return ret;
    }
    
    memcpy(pout, psrc + 4, nlength);
    out_len = nlength;
    return 0;
}

SrsRtspStack::SrsRtspStack(ISrsProtocolReaderWriter* s)
{
    buf = new SrsSimpleBuffer();
    LB_ADD_MEM(buf, sizeof(SrsSimpleBuffer));
    skt = s;
    lpts_offset = INT64_MIN;
#ifdef WRITE_RTSP_RTP_DATA
    m_pfile = NULL;
    m_prtsp_file = NULL;
    m_pprotocol_file = NULL;
#endif
}

SrsRtspStack::~SrsRtspStack()
{
    srs_freep(buf);
    std::map<int, SrsRtpPacket*>::iterator it = mpt_map_rtp_packet.begin();
    for(; it != mpt_map_rtp_packet.end(); it++)
    {
        if(it->second)
        {
            srs_freep(it->second);
        }
    }

    mpt_map_rtp_packet.clear();
#ifdef WRITE_RTSP_RTP_DATA
    if(m_pfile)
    {
        fclose(m_pfile);
        m_pfile = NULL;
    }

    if(m_pprotocol_file)
    {
        fclose(m_pprotocol_file);
        m_pprotocol_file = NULL;
    }

    if(m_prtsp_file)
    {
        fclose(m_prtsp_file);
        m_prtsp_file = NULL;
    }
#endif
}

int SrsRtspStack::recv_message(SrsRtspRequest** preq)
{
    int ret = ERROR_SUCCESS;

    SrsRtspRequest* req = new SrsRtspRequest();
    LB_ADD_MEM(req, sizeof(SrsRtspRequest));
    if ((ret = do_recv_message(req)) != ERROR_SUCCESS) {
        srs_freep(req);
        return ret;
    }

    *preq = req;

    return ret;
}//"Date: Wed, Apr 29 2020 06:13:41 GMT\r\n" 
char* resp[] = {"RTSP/1.0 200 OK\r\n" \
"CSeq: 1\r\n%s" \
"Content-Base: rtsp:%s:8443/live/P020101000101191216300001/\r\n" \
"Content-Type: application/sdp\r\n" \
"Content-Length: 831\r\n\r\n" \
"v=0\r\n" \
"o=- 1588140821592217 1 IN IP4 %s\r\n" \
"s=Matroska video+audio+(optional)subtitles, streamed by the LIVE555 Media Server\r\n" \
"i=live/P020101000101191216300001\r\n" \
"t=0 0\r\n" \
"a=tool:LIVE555 Streaming Media v2020.04.24\r\n" \
"a=type:broadcast\r\n" \
"a=control:*\r\n" \
"a=range:npt=0-20.877\r\n" \
"a=x-qt-text-nam:Matroska video+audio+(optional)subtitles, streamed by the LIVE555 Media Server\r\n" \
"a=x-qt-text-inf:live/P020101000101191216300001\r\n" \
"m=video 0 RTP/AVP 96\r\n" \
"c=IN IP4 0.0.0.0\r\n" \
"b=AS:500\r\n" \
"a=rtpmap:96 H264/90000\r\n" \
"a=fmtp:96 packetization-mode=1;profile-level-id=42002A;sprop-parameter-sets=Z0IAKpY1wPAET8s3AQEBAg==,aM48gA==\r\n" \
"a=control:track1\r\n" \
"m=audio 0 RTP/AVP 97\r\n" \
"c=IN IP4 0.0.0.0\r\n" \
"b=AS:96\r\n" \
"a=rtpmap:97 MPEG4-GENERIC/8000\r\n" \
"a=fmtp:97 streamtype=5;profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1588\r\n" \
"a=control:track2\r\n", 
//"Date: Wed, Apr 29 2020 06:13:41 GMT\r\n"
"RTSP/1.0 200 OK\r\n" \
"CSeq: 2\r\n%s" \
"Transport: RTP/AVP/TCP;unicast;destination=61.238.104.191;source=172.31.22.150;interleaved=0-1\r\n" \
"Session: 294C9BF8;timeout=65\r\n",
//"Date: Wed, Apr 29 2020 06:13:41 GMT\r\n"
"RTSP/1.0 200 OK\r\n" \
"CSeq: 3\r\n%s" \
"Transport: RTP/AVP/TCP;unicast;destination=61.238.104.191;source=172.31.22.150;interleaved=2-3\r\n" \
"Session: 294C9BF8;timeout=65\r\n\r\n"
//"Date: Wed, Apr 29 2020 06:13:42 GMT\r\n"
"RTSP/1.0 200 OK\r\n" \
"CSeq: 4\r\n%s" \
"Range: npt=0.000-\r\n" \
"Session: 294C9BF8\r\n" \
"RTP-Info: url=rtsp://172.31.22.150:8443/live/P020101000101191216300001/track1;seq=2942;rtptime=543887511,url=rtsp://172.31.22.150:8443/live/P020101000101191216300001/track2;seq=39829;rtptime=1907567110\r\n\r\n"
};
int SrsRtspStack::send_message(SrsRtspResponse* res)
{
    int ret = ERROR_SUCCESS;

    /*if(res->seq > 0 && res->seq <= 2)
    {
        char buf[200];
        char send_buf[4096] = {0};
        time_t tt = time(NULL);
        string localip = lazy_get_local_ip(get_fd());
        strftime(buf, sizeof buf, "Date: %a, %b %d %Y %H:%M:%S GMT\r\n", gmtime(&tt));
        sprintf(send_buf, resp[res->seq-1], buf, localip.c_str(), localip.c_str());
        ret = skt->write(send_buf, strlen(send_buf), NULL);
        srs_rtsp_debug("ret = skt->write(resp[i]:%s, strlen(resp[i:%d]), NULL)", send_buf, res->seq-1);
        if (ret != ERROR_SUCCESS) {
            if (!srs_is_client_gracefully_close(ret)) {
                srs_error("rtsp: send response failed. ret=%d", ret);
            }
            return ret;
        }
        return ret;
    }*/

    std::stringstream ss;
    // encode the message to string.
    res->encode(ss);

    std::string str = ss.str();
    srs_info("send len:%d, msg:\n%s", (int)str.length(), str.c_str());
    srs_assert(!str.empty());
#ifdef WRITE_RTSP_RTP_DATA
    if(NULL == m_pprotocol_file)
    {
        char filename[256] = {0};
        sprintf(filename, "rtsp_protocol_%ld.data", get_timestamp());
        m_pprotocol_file = fopen(filename, "wb");
        srs_trace("m_pprotocol_file:%p = fopen(filename:%s, wb)\n", m_pprotocol_file, filename);
    }
    if(m_pprotocol_file)
    {
        fwrite(str.c_str(), 1, (int)str.length(), m_pprotocol_file);
    }
#endif
    ret = send_data((char*)str.c_str(), (int)str.length());
    srs_rtsp_debug("ret:%d = send_data((char*)str:%s, (int)str.length())\n", ret, str.c_str());
    if (ret != ERROR_SUCCESS) {
    //if ((ret = skt->write((char*)str.c_str(), (int)str.length(), NULL)) != ERROR_SUCCESS) {
        if (!srs_is_client_gracefully_close(ret)) {
            srs_error("rtsp: send response failed. ret=%d", ret);
        }
        return ret;
    }
    srs_info("rtsp: send response ok");

    return ret;
}

int SrsRtspStack::send_packet(uint32_t ssrc, int pt, char* pdata, int len, int64_t pts)
{
    int ret = 0;
    srs_rtsp_debug("send_packet(ssrc:%u, pt:%d, pdata:%p, len:%d, pts:%"PRId64")\n", ssrc, pt, pdata, len, pts);
    std::map<int, SrsRtpPacket*>::iterator it = mpt_map_rtp_packet.find(pt);
    if(it == mpt_map_rtp_packet.end())
    {

        SrsRtpPacket* prtppkt = new SrsRtpPacket();
        LB_ADD_MEM(prtppkt, sizeof(SrsRtpPacket));
        std::map<int, RTP_INFO*>::iterator it = mrtp_info_list.find(pt);
        if(it != mrtp_info_list.end() &&  it->second)
        {
            prtppkt->payload_type = pt;
            prtppkt->sequence_number = it->second->seq_number%56635;
            prtppkt->timestamp = it->second->rtp_timestamp;
            prtppkt->m_nchannel_id = it->second->rtp_channel_id;
            prtppkt->ssrc = it->second->ussrc;
            prtppkt->time_scale = it->second->time_scale;
            prtppkt->npts_offset = pts;
            //srs_rtsp_debug("prtppkt->payload_type:%d, prtppkt->sequence_number:%d, prtppkt->timestamp:%u, prtppkt->m_nchannel_id:%d, prtppkt->time_scale:%d\n", prtppkt->payload_type, (int)prtppkt->sequence_number, prtppkt->timestamp, prtppkt->m_nchannel_id, prtppkt->time_scale);
        }
        else if(it == mrtp_info_list.end())
        {
            srs_rtsp_debug("it == mrtp_info_list.end()\n");
        }
        mpt_map_rtp_packet[pt] = prtppkt;
    }
	
    SrsRtpPacket* prtppkt = mpt_map_rtp_packet[pt];
    /*if(INT32_MIN == prtppkt->npts_offset)
    {
        prtppkt->npts_offset = pts;
    }*/
    pts = pts - prtppkt->npts_offset;
    //ret = prtppkt->encode(prtppkt->ssrc, pt, prtppkt->m_nchannel_id, pdata, len, prtppkt->sequence_number, pts);
    ret = prtppkt->encode(prtppkt->ssrc, pt, pdata, len, prtppkt->sequence_number, pts);
    //srs_rtsp_debug("ret:%d = prtppkt->encode(ssrc:%u, pt:%d, prtppkt->m_nchannel_id:%d, pdata:%p, len:%d, prtppkt->sequence_number:%d, pts:%"PRId64")\n", ret, prtppkt->ssrc, pt, prtppkt->m_nchannel_id, pdata, len, (int)prtppkt->sequence_number, pts);
    for(int i = 0; i < prtppkt->vrtp_packet_list.size(); i++)
    {
#ifdef WRITE_RTSP_RTP_DATA
        if(NULL == prtppkt->m_pfile)
        {
            char filename[128] = {0};
            sprintf(filename, "rtp_%d_%ld.data", pt, get_timestamp());
            prtppkt->m_pfile = fopen(filename, "wb");
            srs_trace("prtppkt->m_pfile:%p = fopen(filename:%s, wb)\n", prtppkt->m_pfile, filename);
        }

        if(prtppkt->m_pfile)
        {
            fwrite(prtppkt->vrtp_packet_list[i]->bytes(), 1, prtppkt->vrtp_packet_list[i]->length(), prtppkt->m_pfile);
        }
#endif
        ret = send_rtsp_over_tcp_packet(prtppkt->m_nchannel_id, prtppkt->vrtp_packet_list[i]->bytes(), prtppkt->vrtp_packet_list[i]->length());
        //ret = send_data(prtppkt->vrtp_packet_list[i]->bytes(), prtppkt->vrtp_packet_list[i]->length());//skt->write(prtppkt->vrtp_packet_list[i]->bytes(), prtppkt->vrtp_packet_list[i]->length(), NULL);
        //srs_rtsp_debug("ret:%d = skt->write(%p, %d, NULL), pt:%d", ret, prtppkt->vrtp_packet_list[i]->bytes(), prtppkt->vrtp_packet_list[i]->length(), pt);
        if(ret != ERROR_SUCCESS)
        {
            srs_error("ret:%d = send_data(%p, %d) failed\n", ret, prtppkt->vrtp_packet_list[i]->bytes(), prtppkt->vrtp_packet_list[i]->length());
        }
    }
    return ret;
}
char* desc = "RTSP/1.0 200 OK\r\n" \
"CSeq: 1\r\n" \
"Content-Base: rtsp://172.31.22.150:8443/live/P020101000101191216300001/\r\n" \
"Content-Type: application/sdp\r\n" \
"Content-Length: 831\r\n\r\n" \
"v=0\r\n" \
"o=- %ld%06ld 1 IN IP4 172.31.22.150\r\n" \
"s=Matroska video+audio+(optional)subtitles, streamed by the LIVE555 Media Server\r\n" \
"i=live/P020101000101191216300001\r\n" \
"t=0 0\r\n" \
"a=tool:LIVE555 Streaming Media v2020.04.24\r\n" \
"a=type:broadcast\r\n" \
"a=control:*\r\n" \
"a=range:npt=0-20.877\r\n" \
"a=x-qt-text-nam:Matroska video+audio+(optional)subtitles, streamed by the LIVE555 Media Server\r\n" \
"a=x-qt-text-inf:live/P020101000101191216300001\r\n" \
"m=video 0 RTP/AVP 96\r\n" \
"c=IN IP4 0.0.0.0\r\n" \
"b=AS:500\r\n" \
"a=rtpmap:96 H264/90000\r\n" \
"a=fmtp:96 packetization-mode=1;profile-level-id=42002A;sprop-parameter-sets=Z0IAKpY1wPAET8s3AQEBAg==,aM48gA==\r\n" \
"a=control:track1\r\n" \
"m=audio 0 RTP/AVP 97\r\n" \
"c=IN IP4 0.0.0.0\r\n" \
"b=AS:96\r\n" \
"a=rtpmap:97 MPEG4-GENERIC/8000\r\n" \
"a=fmtp:97 streamtype=5;profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1588\r\n" \
"a=control:track2\r\n";
int SrsRtspStack::send_data(void* pdata, int len)
{
#ifdef ENABLE_SEND_DATA_FROM_FILE
	static FILE* pwfile = NULL, *prfile = NULL;
    static int num = 0;
	if (NULL == prfile)
	{
#ifdef WIN32
		fopen_s(&prfile, "rtsp_send.data", "rb");
#else
		prfile = fopen("rtsp_send.data", "rb");
#endif
	}
    //srs_rtsp_debug("prfile:%p, pdata:%p, len:%d\n", prfile, pdata, len);
	if (prfile)
	{
		int read_len = 0, pkt_len = 0;
		read_len = fread(&pkt_len, 1, sizeof(pkt_len), prfile);
		if (read_len <= 0)
		{
			return -1;
		}
        if(num++ < 4)
        {
        char buf[1500] ={0};
        fread(buf, 1, pkt_len, prfile);
        //int pos = ftell(prfile);
        //fseek(prfile, pos + pkt_len, SEEK_SET);
        /*struct timeval tv;
        gettimeofday(&tv, NULL);
        sprintf((char*)pdata, desc, tv.tv_sec, tv.tv_usec);
        len = strlen((char*)pdata);*/
        }
        else
        {
            len = fread(pdata, 1, pkt_len, prfile);
        }
	}
#endif
    	
    int ret = 0;
    int offset = 0;
    while(offset < len)
    {
        ssize_t nb_write = 0;
        ret = skt->write((char*)pdata + offset, len - offset, &nb_write);
        if(ret != 0)
        {
            srs_error("ret:%d = skt->write(pdata:%p, len:%d, &nb_write:%"PRId64") failed\n", ret, pdata, len, nb_write);
            return ret;
        }
#ifdef WRITE_RTSP_RTP_DATA
        if(NULL == m_prtsp_file)
        {
            char filename[128] = {0};
            sprintf(filename, "rtsp_%ld.data", get_timestamp());
            m_prtsp_file = fopen(filename, "wb");
            srs_trace("m_prtsp_file:%p = fopen(filename:%s, wb)\n", m_prtsp_file, filename);
        }
        uint8_t* ptmp = (uint8_t*)pdata;
        if(m_prtsp_file)
        {
            fwrite(&len, 1, sizeof(int), m_prtsp_file);
            fwrite(pdata + offset, 1, nb_write, m_prtsp_file);
        }
#endif
        offset += nb_write;
    }
    //srs_rtsp_debug("send data success, bytes:%d\n", offset);
    return ERROR_SUCCESS;
}

int SrsRtspStack::get_fd()
{
    return skt->get_fd();
}

int SrsRtspStack::add_rtp_info(int pt, RTP_INFO* prtp_info)
{
    std::map<int, RTP_INFO*>::iterator it = mrtp_info_list.find(pt);
    if(it != mrtp_info_list.end())
    {
        srs_freep(it->second);
        mrtp_info_list.erase(it);
    }

    if(prtp_info)
    {
        RTP_INFO* prtpinfo = new RTP_INFO();
        LB_ADD_MEM(prtpinfo, sizeof(RTP_INFO));
        *prtpinfo = *prtp_info;
        srs_rtsp_debug("pt:%d, track_name:%s, url:%s, seq_number:%d, rtp_timestamp:%u, rtp_channel_id:%d, rtcp_channel_id:%d\n", 
        prtpinfo->pt, prtpinfo->track_name.c_str(), prtpinfo->url.c_str(), prtpinfo->seq_number, prtpinfo->rtp_timestamp, prtpinfo->rtp_channel_id, prtpinfo->rtcp_channel_id);
        mrtp_info_list[pt] = prtpinfo;
    }

    return 0;
}

int SrsRtspStack::send_report(rtcp_packet* prp)
{
    //CHECK_PARAM_PTR(prp, -1);
    uint8_t buf[1024] = {0};
    if(NULL == prp)
    {
        srs_error("send report failed prp:%p\n", prp);
        return -1;
    }

    int ret = prp->encode(buf, 1024);
    if(ret < 0)
    {
        srs_error("ret:%d = prp->encode(buf, 1024) failed\n", ret);
        return ret;
    }
    //SRS_CHECK_RESULT(ret);
    srs_rtsp_debug("ret:%d = prp->encode(buf:%p, 1024)\n",  ret, buf);
    return send_rtsp_over_tcp_packet(prp->channel_id(), buf, ret);
}

int SrsRtspStack::build_and_send_report()
{
    int ret = 0;
    srs_rtsp_debug("build_and_send_report begin, mrtp_info_list.size():%ld\n", mrtp_info_list.size());
    for(std::map<int, RTP_INFO*>::iterator it = mrtp_info_list.begin(); it != mrtp_info_list.end(); it++)
    //for(std::map<int, SrsRtpPacket*>::iterator it = mpt_map_rtp_packet.begin(); it != mpt_map_rtp_packet.end(); it++)
    {
        int pt = it->first;
        RTP_INFO* pri = it->second;
        rtcp_sender_report* psp = new rtcp_sender_report();
        LB_ADD_MEM(psp, sizeof(rtcp_sender_report));
        //uint32_t timebase = get_random_int();
        int pkt_count = 0;
        int octet_count = 0;
        std::map<int, SrsRtpPacket*>::iterator itp = mpt_map_rtp_packet.find(pri->pt);
        if(mpt_map_rtp_packet.end() != itp)
        {
            pkt_count = itp->second->total_sequence_number - pri->seq_number;
            octet_count = itp->second->total_payload_bytes;
        }
        ret = psp->init(pri->urtcp_ssrc, pri->rtcp_channel_id, pri->rtcp_timestamp, pri->time_scale, pkt_count, octet_count);
        srs_rtsp_debug("ret:%d = psp->init(pri->ussrc:%u, pri->rtcp_channel_id:%u, pri->rtp_timestamp:%u, pri->time_scale:%u, pkt_count:%d, octet_count:%d)\n", ret, pri->ussrc, pri->rtcp_channel_id, pri->rtp_timestamp, pri->time_scale, pkt_count, octet_count);
        //psp->add_report(ssrc, 0, 0, );
        uint8_t buf[1024] = {0};
        int offset = psp->encode(buf, 1024);
        srs_rtsp_debug("offset:%d = psp->encode(buf:%p, 1024)\n", offset, buf);
        //ret = send_report(psp);
        SRS_CHECK_RESULT(offset);
        rtcp_source_description* psd = new rtcp_source_description();
        LB_ADD_MEM(psd, sizeof(rtcp_source_description));
        psd->init(pri->urtcp_ssrc, pri->rtcp_channel_id, pri->rtcp_timestamp, pri->time_scale);
        psd->add_cname();
        offset += psd->encode(buf + offset, 1024 - offset);
        SRS_CHECK_RESULT(offset);
        //ret = send_report(psd);
        send_rtsp_over_tcp_packet(pri->rtcp_channel_id, buf, offset);
        SRS_CHECK_RESULT(ret);
        srs_rtsp_debug_memory((const char*)buf, offset);
        srs_rtsp_debug("build_and_send_report end, ret:%d = send_report(psd), offset:%d\n", ret, offset);
        //return ret;
    }
    //std::map<int, SrsRtpPacket*>    mpt_map_rtp_packet
    return ret;
}

int SrsRtspStack::send_rtsp_over_tcp_packet(int channel_id, void* pdata, int len)
{
    char buf[4] = {0};
    buf[0] = '$';
    buf[1] = channel_id;
    buf[2] = (u_int8_t) ((len&0xFF00)>>8);
    buf[3] = (u_int8_t) (len&0xFF);
    int ret = send_data(buf, 4);
    SRS_CHECK_RESULT(ret);
    ret = send_data(pdata, len);
    SRS_CHECK_RESULT(ret);
    //srs_rtsp_debug_memory((const char*)pdata, len);
    #ifdef WRITE_RTSP_RTP_DATA
        if(NULL == m_pfile)
        {
            char filename[256] = {0};
            sprintf(filename, "rtp_%ld.data", get_timestamp());
            m_pfile = fopen(filename, "wb");
            srs_trace("m_pfile:%p = fopen(filename:%s, wb)\n", m_pfile, filename);
        }

        if(m_pfile && 0 == channel_id)
        {
            fwrite(buf, 1, 4, m_pfile);
            fwrite(pdata, 1, len, m_pfile);
        }
#endif
    return ret > 0 ? ERROR_SUCCESS : 0;
}

int SrsRtspStack::read_rtcp_packet(rtcp_packet* pkt)
{
    int ret = 0;
    uint8_t* psrc = ( uint8_t*)buf->bytes();
    if(/*NULL == pkt || */NULL == buf)
    {
        srs_error("Invalid parameter, pkt:%p, buf:%p\n", pkt, buf);
        return -1;
    }

    if(buf->length() < 4 || 0x24 != psrc[0])
    {
        srs_error("Invalid buffer, size:%d, psrc[0]:%0x\n", buf->length(), (uint8_t)psrc[0]);
        return -1;
    }
    lazy_bitstream bs(psrc, buf->length());
    uint8_t tag = (uint8_t)bs.read_byte(1);
    uint8_t channel_id = (uint8_t)bs.read_byte(1);
    int data_len = (int)bs.read_byte(2);
    
    //srs_rtsp_debug("tag:%d, channel_id:%d, data_len:%d, psrc[0]:%0x, psrc[1]:%0x, psrc[2]:%0x, psrc[3]:%0x\n", tag, channel_id, data_len, psrc[0], psrc[1], psrc[2], psrc[3]);
    //srs_trace_memory(psrc, buf->length());
    //srs_trace_memory((const char*)psrc, buf->length());
    while(data_len > 0 && data_len > buf->length() - 4)
    {
        char buffer[1024] = {0};
        ssize_t readed = 0;
        int read_len = data_len - buf->length() + 4;
        read_len = read_len > 1024 ? 1024 : read_len;
        ret = skt->read_fully(buffer, read_len, &readed);
        if(ret < 0 || readed < read_len)
        {
            srs_error("ret:%d = skt->read_fully(buffer:%p, read_len:%d, &readed:%d) failed or readed < read_len\n", ret, buffer, read_len, readed);
            return ret;
        }
        buf->append((const char*)buffer, (int)readed);
    };
    
    /*ret = pkt->decode((uint8_t*)buf->bytes() + 4, data_len);
    if(ret < 0)
    {
        lberror("ret = pkt->decode(buf->bytes() + 4, data_len) failed\n", ret, buf->bytes() + 4, data_len);
        return -1;
    }*/

    buf->erase(data_len + 4);
    srs_rtsp_debug("read rtcp packet success, buf->length():%d, buf->erase(data_len + 4:%d)\n", buf->length(), data_len + 4);
    if(buf->length() > 0)
    {
        srs_trace_memory(buf->bytes(), buf->length());
    }
    return 0;
}

int SrsRtspStack::do_recv_message(SrsRtspRequest* req)
{
    int ret = ERROR_SUCCESS;

    // parse request line.
    if ((ret = recv_token_normal(req->method)) != ERROR_SUCCESS) {
        if (!srs_is_client_gracefully_close(ret)) {
            if(!req->method.empty())
            {
                srs_trace("rtsp over tcp packet data\n");
                std::string pktdata;
                recv_token_util_eof(pktdata);
                ret = ERROR_SUCCESS;
                return ret;
            }

            srs_error("rtsp: parse method failed. ret=%d", ret);
            return ret;
        }
        // rtsp over tcp packet
    }

    if(SRS_TOKEN_RTCP == req->method)
    {
        srs_rtsp_debug("recv rtcp packet, return now\n");
        return ERROR_SUCCESS;
    }

    if ((ret = recv_token_normal(req->uri)) != ERROR_SUCCESS) {
        if (!srs_is_client_gracefully_close(ret)) {
            srs_error("rtsp: parse uri failed. ret=%d, req->method:%s\n", ret, req->method.c_str());
        }
        return ret;
    }

    if ((ret = recv_token_eof(req->version)) != ERROR_SUCCESS) {
        if (!srs_is_client_gracefully_close(ret)) {
            srs_error("rtsp: parse version failed. ret=%d", ret);
        }
        return ret;
    }

    // parse headers.
    for (;;) {
        // parse the header name
        std::string token;
        if ((ret = recv_token_normal(token)) != ERROR_SUCCESS) {
            if (ret == ERROR_RTSP_REQUEST_HEADER_EOF) {
                ret = ERROR_SUCCESS;
                srs_info("rtsp: message header parsed");
                break;
            }
            if (!srs_is_client_gracefully_close(ret)) {
                srs_error("rtsp: parse token failed. ret=%d", ret);
            }
            return ret;
        }
        //srs_trace("%s", token.c_str());
        // parse the header value according by header name
        if (token == SRS_RTSP_TOKEN_CSEQ) {
            std::string seq;
            if ((ret = recv_token_eof(seq)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: parse %s failed. ret=%d", SRS_RTSP_TOKEN_CSEQ, ret);
                }
                return ret;
            }
            req->seq = ::atol(seq.c_str());
        } else if (token == SRS_RTSP_TOKEN_CONTENT_TYPE) {
            std::string ct;
            if ((ret = recv_token_eof(ct)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: parse %s failed. ret=%d", SRS_RTSP_TOKEN_CONTENT_TYPE, ret);
                }
                return ret;
            }
            req->content_type = ct;
        } else if (token == SRS_RTSP_TOKEN_CONTENT_LENGTH) {
            std::string cl;
            if ((ret = recv_token_eof(cl)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: parse %s failed. ret=%d", SRS_RTSP_TOKEN_CONTENT_LENGTH, ret);
                }
                return ret;
            }
            req->content_length = ::atol(cl.c_str());
        } else if (token == SRS_RTSP_TOKEN_TRANSPORT) {
            std::string transport;
            if ((ret = recv_token_eof(transport)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: parse %s failed. ret=%d", SRS_RTSP_TOKEN_TRANSPORT, ret);
                }
                return ret;
            }
            if (!req->transport) {
                req->transport = new SrsRtspTransport();
                LB_ADD_MEM(req->transport, sizeof(SrsRtspTransport));
            }
            if ((ret = req->transport->parse(transport)) != ERROR_SUCCESS) {
                srs_error("rtsp: parse transport failed, transport=%s. ret=%d", transport.c_str(), ret);
                return ret;
            }
        } else if (token == SRS_RTSP_TOKEN_SESSION) {
            if ((ret = recv_token_eof(req->session)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: parse %s failed. ret=%d", SRS_RTSP_TOKEN_SESSION, ret);
                }
                srs_trace("ret:%d = recv_token_eof(req->session) failed\n", ret);
                return ret;
            }
            //srs_rtsp_debug("after read session, ret:%d\n", ret);
        } else if(token == SRS_RTSP_TOKEN_AUTHORIZATION)
        {
            std::string auth_cmd;
            if ((ret = recv_token_util_eof(auth_cmd)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: parse %s failed. ret=%d", SRS_RTSP_TOKEN_AUTHORIZATION, ret);
                }
                return ret;
            }
           // srs_rtsp_debug("rtsp receive auth cmd:%s\n", auth_cmd.c_str());
            SrsRtspAuthorization* pauth = new SrsRtspAuthorization();
            LB_ADD_MEM(pauth, sizeof(SrsRtspAuthorization));
            ret = pauth->parser(auth_cmd);
            //srs_rtsp_debug("ret:%d = pauth->parser(auth_cmd:%s)\n", ret, auth_cmd.c_str());
            if(ERROR_SUCCESS != ret)
            {
                //delete pauth;
                srs_freep(pauth);
                return ret;
            }
            req->pauthorize = pauth;
            
        } else if(token == SRS_RTSP_TOKEN_RANGE)
        {
            std::string range;
            std::string time_range, start_time;
            if ((ret = recv_token_eof(range)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: parse %s failed. ret=%d", SRS_RTSP_TOKEN_SESSION, ret);
                }
                return ret;
            }
            //srs_rtsp_debug("%s:%s\n", SRS_RTSP_TOKEN_RANGE, range.c_str());
            ret = string_split(range, time_range, "=");
            if(ERROR_SUCCESS != ret)
            {
                srs_error("ret:%d = string_split(range:%s, time_range:%s, =)\n", ret, range.c_str(),time_range.c_str());
                return ret;
            }
            ret = string_split(range, start_time, "-");
            //srs_rtsp_debug("ret:%d = string_split(range%s, start_time:%s, -)", ret, range.c_str(), start_time.c_str());
            if(ERROR_SUCCESS != ret)
            {
                srs_error("ret:%d = string_split(range:%s, time_range:%s, =)\n", ret, range.c_str(), start_time.c_str());
                return ret;
            }

            if(!start_time.empty())
            {
                req->start_range = atof(start_time.c_str());
            }
            else
            {
                req->start_range = 0.0;
            }

            if(!range.empty())
            {
                req->stop_range = atof(range.c_str());
            }
            else
            {
                req->stop_range = 0.0;
            }
        } 
        else if(SRS_RTSP_TOKEN_USER_AGENT == token)
        {
            std::string user_agent;
            if ((ret = recv_token_util_eof(user_agent)) != ERROR_SUCCESS) {
                //if (!srs_is_client_gracefully_close(ret)) {
                srs_error("rtsp: parse user-agent %s failed. ret=%d", user_agent.c_str(), ret);
                //}
                //return ret;
                ret = ERROR_SUCCESS;
            }
        }
        
        else {
            srs_info("unknown token token:%s, len:%d\n", token.c_str(), token.length());
            //srs_trace_memory(token.data(), token.length());
            // unknown header name, parse util EOF.
            SrsRtspTokenState state = SrsRtspTokenStateNormal;
            while (state == SrsRtspTokenStateNormal) {
                std::string value;
                if ((ret = recv_token(value, state)) != ERROR_SUCCESS) {
                    if (!srs_is_client_gracefully_close(ret)) {
                        srs_error("rtsp: parse token failed. ret=%d, value:%s, state:%d", ret, value.c_str(), state);
                    }
                    return ret;
                }
                //srs_trace("rtsp: ignore header %s=%s", token.c_str(), value.c_str());
            }
        }
    }

    // for setup, parse the stream id from uri.
    if (req->is_setup()) {
        size_t pos = string::npos;
        std::string stream_id;
        if ((pos = req->uri.rfind("/")) != string::npos) {
            stream_id = req->uri.substr(pos + 1);
        }
        if ((pos = stream_id.find("=")) != string::npos) {
            stream_id = stream_id.substr(pos + 1);
        }
        req->stream_id = ::atoi(stream_id.c_str());
        srs_info("rtsp: setup stream id=%d", req->stream_id);
    }

    // parse rdp body.
    long consumed = 0;
    while (consumed < req->content_length) {
        if (!req->sdp) {
            req->sdp = new SrsRtspSdp();
            LB_ADD_MEM(req->sdp, sizeof(SrsRtspSdp));
        }

        int nb_token = 0;
        std::string token;
        if ((ret = recv_token_util_eof(token, &nb_token)) != ERROR_SUCCESS) {
            if (!srs_is_client_gracefully_close(ret)) {
                srs_error("rtsp: parse sdp token failed. ret=%d", ret);
            }
            return ret;
        }
        consumed += nb_token;

        if ((ret = req->sdp->parse(token)) != ERROR_SUCCESS) {
            srs_error("rtsp: sdp parse token failed, token=%s. ret=%d", token.c_str(), ret);
            return ret;
        }
        srs_info("rtsp: %s", token.c_str());
    }
    //srs_rtsp_debug("rtsp: sdp parsed, size=%d, ret:%d\n", consumed, ret);

    return ret;
}

int SrsRtspStack::recv_token_normal(std::string& token)
{
    int ret = ERROR_SUCCESS;

    SrsRtspTokenState state;

    if ((ret = recv_token(token, state)) != ERROR_SUCCESS) {
        if (ret == ERROR_RTSP_REQUEST_HEADER_EOF) {
            return ret;
        }
        if (!srs_is_client_gracefully_close(ret)) {
            srs_error("rtsp: parse token failed. ret=%d", ret);
        }
        return ret;
    }

    if (state != SrsRtspTokenStateNormal) {
        ret = ERROR_RTSP_TOKEN_NOT_NORMAL;
        srs_error("rtsp: parse normal token %s failed, state=%d. ret=%d", token.c_str(), state, ret);
        srs_trace_memory(token.data(), token.length());
        return ret;
    }

    return ret;
}

int SrsRtspStack::recv_token_eof(std::string& token)
{
    int ret = ERROR_SUCCESS;

    SrsRtspTokenState state;

    if ((ret = recv_token(token, state)) != ERROR_SUCCESS) {
        if (ret == ERROR_RTSP_REQUEST_HEADER_EOF) {
            return ret;
        }
        if (!srs_is_client_gracefully_close(ret)) {
            srs_error("rtsp: parse token failed. ret=%d", ret);
        }
        return ret;
    }

    if (state != SrsRtspTokenStateEOF) {
        ret = ERROR_RTSP_TOKEN_NOT_NORMAL;
        srs_error("rtsp: parse eof token %s failed, state=%d. ret=%d", token.c_str(), state, ret);
        return ret;
    }

    return ret;
}

int SrsRtspStack::recv_token_util_eof(std::string& token, int* pconsumed)
{
    int ret = ERROR_SUCCESS;

    SrsRtspTokenState state;

    // use 0x00 as ignore the normal token flag.
    if ((ret = recv_token(token, state, 0x00, pconsumed)) != ERROR_SUCCESS) {
        if (ret == ERROR_RTSP_REQUEST_HEADER_EOF) {
            return ret;
        }
        if (!srs_is_client_gracefully_close(ret)) {
            srs_error("rtsp: parse token failed. ret=%d", ret);
        }
        return ret;
    }

    if (state != SrsRtspTokenStateEOF) {
        ret = ERROR_RTSP_TOKEN_NOT_NORMAL;
        srs_error("rtsp: parse eof token failed, state=%d. ret=%d", state, ret);
        return ret;
    }

    return ret;
}

int SrsRtspStack::recv_token(std::string& token, SrsRtspTokenState& state, char normal_ch, int* pconsumed)
{
    int ret = ERROR_SUCCESS;

    // whatever, default to error state.
    state = SrsRtspTokenStateError;

    // when buffer is empty, append bytes first.
    bool append_bytes = buf->length() == 0;

    // parse util token.
    for (;;) {
        // append bytes if required.
        if (append_bytes) {
            append_bytes = false;

            char buffer[SRS_RTSP_BUFFER];
            ssize_t nb_read = 0;
            if ((ret = skt->read(buffer, SRS_RTSP_BUFFER, &nb_read)) != ERROR_SUCCESS) {
                if (!srs_is_client_gracefully_close(ret)) {
                    srs_error("rtsp: io read failed. ret=%d", ret);
                }
                return ret;
            }
            

            buf->append(buffer, nb_read);
            srs_rtsp_debug("rtsp: io read %d bytes, buffer:\n%s, length:%d", nb_read, buffer, buf->length());
            //srs_trace_memory(buf->bytes(), buf->length());
        }
        uint8_t* psrc = (uint8_t*)buf->bytes();
        if(0x24 == psrc[0] && buf->length() >= 4)
        {
            rtsp_over_tcp_packet pkt;
            ret = pkt.decode_header(psrc, buf->length());
            if(ret != 0)
            {
                srs_error("Invalid rtsp over tcp packet, psrc[0]:%0x, psrc[1]:%0x, psrc[2]:%0x, psrc[3]:%0x\n", (uint8_t)psrc[0], (uint8_t)psrc[1], (uint8_t)psrc[2], (uint8_t)psrc[3]);
                return ret;
            }
            /*while(pkt.nlength > 0 && pkt.nlength > buf->length() - 4)
            {
                char bufer[1024] = {0};
                int readed = 0;
                int read_len = pkt.nlength - buf->length() + 4;
                read_len = read_len > 1024 ? 1024 : read_len;
                ret = skt->read_fully(bufer, read_len, &readed);
                if(ret < 0 || readed < read_len)
                {
                    srs_error("ret:%d = skt->read_fully(bufer:%p, read_len:%d, &readed:%d) failed or readed < read_len\n", ret, bufer, read_len, readed);
                    return ret;
                }
                buf->append(buffer, readed);
               
            }
            buf->erase(0, pkt.nlength + 4);*/
            state = SrsRtspTokenStateNormal;
            token = SRS_TOKEN_RTCP;
            srs_rtsp_debug("recv rtcp packet, len:%d\n", pkt.nlength + 4);
            return 0;
        }
        // parse one by one.
        char* start = buf->bytes();
        char* end = start + buf->length();
        char* p = start;

        // find util SP/CR/LF, max 2 EOF, to finger out the EOF of message.
        for (; p < end && p[0] != normal_ch && p[0] != SRS_RTSP_CR && p[0] != SRS_RTSP_LF; p++) {
        }

        // matched.
        if (p < end) {
            // finger out the state.
            if (p[0] == normal_ch) {
                state = SrsRtspTokenStateNormal;
            } else {
                state = SrsRtspTokenStateEOF;
            }
            
            // got the token.
            int nb_token = p - start;
            // trim last ':' character.
            if (nb_token && p[-1] == ':') {
                nb_token--;
            }
            if (nb_token) {
                token.append(start, nb_token);
            } else {
                ret = ERROR_RTSP_REQUEST_HEADER_EOF;
            }

            // ignore SP/CR/LF
            for (int i = 0; i < 2 && p < end && (p[0] == normal_ch || p[0] == SRS_RTSP_CR || p[0] == SRS_RTSP_LF); p++, i++) {
            }

            // consume the token bytes.
            srs_assert(p - start);
            buf->erase(p - start);
            if (pconsumed) {
                *pconsumed = p - start;
            }
            break;
        }

        // append more and parse again.
        append_bytes = true;
    }

    return ret;
}
#endif

#endif

