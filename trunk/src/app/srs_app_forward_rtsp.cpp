/****************************************************************************************************************
 * filename     srs_app_forward_rtsp.cpp
 * describe     Sunvalley forward rtsp classs define
 * author       Created by dawson on 2019/04/25
 * Copyright    ©2007 - 2029 Sunvally. All Rights Reserved.
 ***************************************************************************************************************/

#include <srs_app_forward_rtsp.hpp>
#include <srs_app_source.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_rtmp_msg_array.hpp>
#include <srs_kernel_flv.hpp>
#include <srs_kernel_ts.hpp>
#include <sys/stat.h> 

ForwardRtspQueue::ForwardRtspQueue()
{
    //srs_trace("ForwardRtspQueue begin");
    m_nmax_queue_size = 1000;

    m_pavccodec     = new SrsAvcAacCodec();
    LB_ADD_MEM(m_pavccodec, sizeof(SrsAvcAacCodec));
    m_pavcsample    = new SrsCodecSample();
    LB_ADD_MEM(m_pavcsample, sizeof(SrsCodecSample));
    m_paaccodec     = new SrsAvcAacCodec();
    LB_ADD_MEM(m_paaccodec, sizeof(SrsAvcAacCodec));
    m_paacsample    = new SrsCodecSample();
    LB_ADD_MEM(m_paacsample, sizeof(SrsCodecSample));
    m_bwait_keyframe = true;
    m_bsend_avc_seq_hdr = false;
    m_bsend_aac_seq_hdr = false;
    //srs_trace("ForwardRtspQueue end");
}

ForwardRtspQueue::~ForwardRtspQueue()
{
    //srs_trace("~ForwardRtspQueue begin");
    srs_freep(m_pavccodec);
    srs_freep(m_pavcsample);
    srs_freep(m_paaccodec);
    srs_freep(m_paacsample);
    /*if(m_pavccodec)
    {
        delete m_pavccodec;
        m_pavccodec = NULL;
    }

    if(m_pavcsample)
    {
        delete m_pavcsample;
        m_pavcsample = NULL;
    }

    if(m_paaccodec)
    {
        delete m_paaccodec;
        m_paaccodec = NULL;
    }

    if(m_paacsample)
    {
        delete m_paacsample;
        m_paacsample = NULL;
    }*/
    //srs_trace("~ForwardRtspQueue end");
}

int ForwardRtspQueue::enqueue(SrsSharedPtrMessage* pmsg)
{ 
    int ret;
    
    if(NULL == pmsg)
    {
        srs_trace("Invalid pmsg ptr %p", pmsg);
        m_bwait_keyframe = true;
        return -1;
    }
   
    if((int)m_vFwdMsgList.size() >= m_nmax_queue_size)
    {
        srs_trace("Forward rtsp queue is full, list size %d < max queue size %d", (int)m_vFwdMsgList.size(), m_nmax_queue_size);
        return -1;
    }
    
    if(pmsg->is_video())
    {
        ret = m_pavccodec->video_avc_demux(pmsg->payload, pmsg->size, m_pavcsample);
        //srs_trace("avc enqueue(payload:%p, size:%d, pmsg->pts:%"PRId64"), m_pavcsample->frame_type:%d, m_bwait_keyframe:%d\n", pmsg->payload, pmsg->size, pmsg->timestamp, m_pavcsample->frame_type, (int)m_bwait_keyframe);
        if(ERROR_SUCCESS != ret)
        {
            srs_error("ret:%d = m_pavccodec->video_avc_demux(pmsg->payload:%p, pmsg->size:%d, m_pavcsample:%p) failed", ret, pmsg->payload, pmsg->size, m_pavcsample);
            srs_err_memory(pmsg->payload, 32);
            return ret;
        }
        /*if(m_pavcsample->nb_sample_units <= 0)
        {
            return 0;
        }*/
        if(SrsCodecVideoAVCTypeSequenceHeader == m_pavcsample->avc_packet_type)
        {
            /*srs_rtsp_debug("avc sequence header,  m_pavcsample->nb_sample_units:%d:\n", m_pavcsample->nb_sample_units);
            for(int i = 0; i < m_pavcsample->nb_sample_units; i++)
            {
                srs_trace_memory(m_pavcsample->sample_units[i].bytes, m_pavcsample->sample_units[i].size);
            }*/
            
        }
        else if(m_bwait_keyframe && m_pavcsample->frame_type != SrsCodecVideoAVCFrameKeyFrame)
        {
            //srs_trace("wait for keyframe, not keyframe, drop video\n");
            m_pavcsample->clear();
            return 0;
        }
        else
        {
            if(m_bwait_keyframe)
            {
                srs_trace("key frame come, pts:%"PRId64", m_pavcsample.nb_sample_units:%d", pmsg->timestamp, m_pavcsample->nb_sample_units);
                m_bwait_keyframe = false;
                
            }
            /*if(SrsCodecVideoAVCFrameKeyFrame == m_pavcsample->frame_type)
            {
                m_pavcsample->add_prefix_sample_uint(m_pavccodec->pictureParameterSetNALUnit, m_pavccodec->pictureParameterSetLength);
                m_pavcsample->add_prefix_sample_uint(m_pavccodec->sequenceParameterSetNALUnit, m_pavccodec->sequenceParameterSetLength);
            }*/
            
            ret = enqueue_avc(m_pavccodec, m_pavcsample, pmsg->timestamp);
        }

        m_pavcsample->clear();
    }
    else
    {
         ret = m_paaccodec->audio_aac_demux(pmsg->payload, pmsg->size, m_paacsample);
        if(ERROR_SUCCESS != ret)
        {
            srs_error("ret:%d = m_paaccodec->audio_aac_demux(pmsg->payload:%p, pmsg->size:%d, m_paacsample:%p) failed", ret, pmsg->payload, pmsg->size, m_paacsample);
            srs_err_memory(pmsg->payload, 32);
            return ret;
        }
        if(m_bwait_keyframe)
        {
            //srs_trace("wait for keyframe, not keyframe, drop audio\n");
            m_paacsample->clear();
            return 0;
        }

        /*if(m_pavcsample->nb_sample_units <= 0)
        {
            return 0;
        }

        if(!m_bsend_aac_seq_hdr)
        {
            m_bsend_aac_seq_hdr = true;
            m_pavcsample->add_prefix_sample_uint(m_paaccodec->aac_extra_data, m_pavccodec->aac_extra_size);
        }*/

        if(SrsCodecAudioTypeSequenceHeader == m_paacsample->aac_packet_type)
        {
            //srs_rtsp_debug("aac sequence header, m_pavcsample->nb_sample_units:%d\n", m_paacsample->nb_sample_units);
            for(int i = 0; i < m_paacsample->nb_sample_units; i++)
            {
                srs_trace_memory(m_paacsample->sample_units[i].bytes, m_paacsample->sample_units[i].size);
            }
        }
        else
        {
            //srs_trace("aac enqueue(payload:%p, size:%d, pmsg->pts:%"PRId64")\n", pmsg->payload, pmsg->size, pmsg->timestamp);
            ret = enqueue_aac(m_paaccodec, m_paacsample, pmsg->timestamp);
        }
        m_paacsample->clear();
    }
   
    //srs_trace("enqueue end, ret:%d", ret);
    return ret;
}

int ForwardRtspQueue::enqueue_avc(SrsAvcAacCodec* codec, SrsCodecSample* sample, int64_t pts)
{
    int ret = ERROR_SUCCESS;
    int pt = SRS_RTSP_AVC_PAYLOAD_TYPE;
    // Whether aud inserted.
    //bool aud_inserted = false;
    static u_int8_t fresh_nalu_header[] = { 0x00, 0x00, 0x00, 0x01 };
    //srs_trace("codec:%p, sample:%p, pts:"PRId64"", codec, sample, pts);
    if(SrsCodecVideoHEVC == codec->video_codec_id)
    {
        pt = SRS_RTSP_HEVC_PAYLOAD_TYPE;
    }
    // Insert a default AUD NALU when no AUD in samples.
    if (!sample->has_aud)
    {
        // the aud(access unit delimiter) before each frame.
        // 7.3.2.4 Access unit delimiter RBSP syntax
        // H.264-AVC-ISO_IEC_14496-10-2012.pdf, page 66.
        //
        // primary_pic_type u(3), the first 3bits, primary_pic_type indicates that the slice_type values
        //      for all slices of the primary coded picture are members of the set listed in Table 7-5 for
        //      the given value of primary_pic_type.
        //      0, slice_type 2, 7
        //      1, slice_type 0, 2, 5, 7
        //      2, slice_type 0, 1, 2, 5, 6, 7
        //      3, slice_type 4, 9
        //      4, slice_type 3, 4, 8, 9
        //      5, slice_type 2, 4, 7, 9
        //      6, slice_type 0, 2, 3, 4, 5, 7, 8, 9
        //      7, slice_type 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
        // 7.4.2.4 Access unit delimiter RBSP semantics
        // H.264-AVC-ISO_IEC_14496-10-2012.pdf, page 102.
        //
        // slice_type specifies the coding type of the slice according to Table 7-6.
        //      0, P (P slice)
        //      1, B (B slice)
        //      2, I (I slice)
        //      3, SP (SP slice)
        //      4, SI (SI slice)
        //      5, P (P slice)
        //      6, B (B slice)
        //      7, I (I slice)
        //      8, SP (SP slice)
        //      9, SI (SI slice)
        // H.264-AVC-ISO_IEC_14496-10-2012.pdf, page 105.
        /*static u_int8_t default_aud_nalu[] = { 0x09, 0xf0};
        pfwdmsg->payload->append((const char*)fresh_nalu_header, sizeof(fresh_nalu_header));
        pfwdmsg->payload->append((const char*)default_aud_nalu, 2);*/
    }
    
    bool is_sps_pps_appended = false;
    // all sample use cont nalu header, except the sps-pps before IDR frame.
    for (int i = 0; i < sample->nb_sample_units; i++) {
        SrsCodecSampleUnit* sample_unit = &sample->sample_units[i];
        int32_t size = sample_unit->size;
        //srs_trace("sample_unit:%p, size:%d", sample_unit, size);
        if (!sample_unit->bytes || size <= 0) {
            ret = ERROR_HLS_AVC_SAMPLE_SIZE;
            srs_error("invalid avc sample length=%d, ret=%d", size, ret);
            //delete pfwdmsg;
            return ret;
        }
        ForwardRtspSample* pfwdmsg = new ForwardRtspSample();
        LB_ADD_MEM(pfwdmsg, sizeof(ForwardRtspSample));
        
        pfwdmsg->payloadtype = pt;
        // 5bits, 7.3.1 NAL unit syntax,
        // H.264-AVC-ISO_IEC_14496-10-2012.pdf, page 83.
        SrsAvcNaluType nal_unit_type = (SrsAvcNaluType)(sample_unit->bytes[0] & 0x1f);
        //srs_rtsp_debug("nal_unit_type:%d, sample_unit->size:%d", nal_unit_type, sample_unit->size);
        if(9 == nal_unit_type || 10 == nal_unit_type)
        {
            srs_freep(pfwdmsg);
            continue;
        }
        // Insert sps/pps before IDR when there is no sps/pps in samples.
        // The sps/pps is parsed from sequence header(generally the first flv packet).
        if (nal_unit_type == SrsAvcNaluTypeIDR && !sample->has_sps_pps && !is_sps_pps_appended) {
            if (codec->sequenceParameterSetLength > 0) {
                //srs_avc_insert_aud(pfwdmsg->payload, aud_inserted);
                /*pfwdmsg->payload->append((const char*)fresh_nalu_header, sizeof(fresh_nalu_header));
                pfwdmsg->payload->append(codec->sequenceParameterSetNALUnit, codec->sequenceParameterSetLength);
                srs_trace("codec->sequenceParameterSetNALUnit:%p, codec->sequenceParameterSetLength:%d\n", codec->sequenceParameterSetNALUnit, codec->sequenceParameterSetLength);
                srs_trace_memory(codec->sequenceParameterSetNALUnit, codec->sequenceParameterSetLength > 48 ? 48 : codec->sequenceParameterSetLength);*/
            }
            if (codec->pictureParameterSetLength > 0) {
                //srs_avc_insert_aud(pfwdmsg->payload, aud_inserted);
                /*pfwdmsg->payload->append((const char*)fresh_nalu_header, sizeof(fresh_nalu_header));
                pfwdmsg->payload->append(codec->pictureParameterSetNALUnit, codec->pictureParameterSetLength);
                srs_trace("codec->pictureParameterSetNALUnit:%p, codec->sequenceParameterSetLength:%d\n", codec->pictureParameterSetNALUnit, codec->sequenceParameterSetLength);
                srs_trace_memory(codec->pictureParameterSetNALUnit, codec->pictureParameterSetLength > 48 ? 48 : codec->pictureParameterSetLength);*/
            }
            is_sps_pps_appended = true;
            // Insert the NALU to video in annexb.
        } 
        pfwdmsg->payload->append((const char*)fresh_nalu_header, sizeof(fresh_nalu_header));
        //srs_avc_insert_aud(pfwdmsg->payload, aud_inserted);
        pfwdmsg->payload->append(sample_unit->bytes, sample_unit->size);
        pfwdmsg->pts = pts;
        pfwdmsg->dts = pts;
        pfwdmsg->mediatype = 0;
        m_vFwdMsgList.push(pfwdmsg);
        //srs_rtsp_debug("pfwdmsg:%p, length:%d, pt:%d, list size:%ld, pts:%"PRId64"\n", pfwdmsg, pfwdmsg->payload->length(), pfwdmsg->payloadtype, m_vFwdMsgList.size(), pfwdmsg->pts);
    }

    
    //srs_trace("pfwdmsg:%p, length:%d, pt:%d, list size:%ld, pts:%"PRId64"\n", pfwdmsg, pfwdmsg->payload->length(), pfwdmsg->payloadtype, m_vFwdMsgList.size(), pfwdmsg->pts);
    return ret;
}

int ForwardRtspQueue::enqueue_aac(SrsAvcAacCodec* codec, SrsCodecSample* sample, int64_t pts)
{
    int ret = ERROR_SUCCESS;
    ForwardRtspSample* pfwdmsg = new ForwardRtspSample();
    LB_ADD_MEM(pfwdmsg, sizeof(ForwardRtspSample));
    pfwdmsg->payloadtype = SRS_RTSP_AAC_PAYLOAD_TYPE;
    //srs_trace("(codec:%p, sample:%p) begin", codec, sample);
    for (int i = 0; i < sample->nb_sample_units; i++)
    {
        SrsCodecSampleUnit* sample_unit = &sample->sample_units[i];
        int32_t size = sample_unit->size;
        if (!sample_unit->bytes || size <= 0 || size > 0x1fff)
        {
            ret = ERROR_HLS_AAC_FRAME_LENGTH;
            srs_error("invalid aac frame length=%d, ret=%d, pt:%d, audio_codec_id:%d", size, ret, pfwdmsg->payloadtype, codec->audio_codec_id);
            //delete pfwdmsg;
            srs_freep(pfwdmsg);
            return ret;
        }
        // the frame length is the AAC raw data plus the adts header size.
        int32_t frame_length = size + 7;
        
        // AAC-ADTS
        // 6.2 Audio Data Transport Stream, ADTS
        // in aac-iso-13818-7.pdf, page 26.
        // fixed 7bytes header
        u_int8_t adts_header[7] = {0xff, 0xf9, 0x00, 0x00, 0x00, 0x0f, 0xfc};
        /*
        // adts_fixed_header
        // 2B, 16bits
        int16_t syncword; //12bits, '1111 1111 1111'
        int8_t protection_absent; //1bit, can be '1'
        // 12bits
        int8_t profile; //2bit, 7.1 Profiles, page 40
        TSAacSampleFrequency sampling_frequency_index; //4bits, Table 35, page 46
        int8_t private_bit; //1bit, can be '0'
        int8_t channel_configuration; //3bits, Table 8
        int8_t original_or_copy; //1bit, can be '0'
        int8_t home; //1bit, can be '0'
        
        // adts_variable_header
        // 28bits
        int8_t copyright_identification_bit; //1bit, can be '0'
        int8_t copyright_identification_start; //1bit, can be '0'
        int16_t frame_length; //13bits
        int16_t adts_buffer_fullness; //11bits, 7FF signals that the bitstream is a variable rate bitstream.
        int8_t number_of_raw_data_blocks_in_frame; //2bits, 0 indicating 1 raw_data_block()
        */
        // profile, 2bits
        SrsAacProfile aac_profile = srs_codec_aac_rtmp2ts(codec->aac_object);
        adts_header[2] = (aac_profile << 6) & 0xc0;
        // sampling_frequency_index 4bits
        adts_header[2] |= (codec->aac_sample_rate << 2) & 0x3c;
        // channel_configuration 3bits
        adts_header[2] |= (codec->aac_channels >> 2) & 0x01;
        adts_header[3] = (codec->aac_channels << 6) & 0xc0;
        // frame_length 13bits
        adts_header[3] |= (frame_length >> 11) & 0x03;
        adts_header[4] = (frame_length >> 3) & 0xff;
        adts_header[5] = ((frame_length << 5) & 0xe0);
        // adts_buffer_fullness; //11bits
        adts_header[5] |= 0x1f;
        //srs_verbose("codec->aac_sample_rate:%d, codec->aac_channels:%d, codec->aac_object:%d", codec->aac_sample_rate, codec->aac_channels, codec->aac_object);
        // copy to audio buffer
        pfwdmsg->payload->append((const char*)adts_header, sizeof(adts_header));
        pfwdmsg->payload->append(sample_unit->bytes, sample_unit->size);
    }

    pfwdmsg->pts = pts;
    pfwdmsg->dts = pts;
    pfwdmsg->mediatype = 1;
    m_vFwdMsgList.push(pfwdmsg);
    //srs_trace("pfwdmsg:%p, length:%d, pfwdmsg->payloadtype:%d, list_size:%ld, pts:%"PRId64"\n", pfwdmsg, pfwdmsg->payload->length(), pfwdmsg->payloadtype, m_vFwdMsgList.size(), pfwdmsg->pts);
    return ret;
}

int ForwardRtspQueue::push_back(ForwardRtspSample* psample)
{
    if(NULL == psample)
    {
        lberror("Invalid parameter, psample:%p\n", psample);
        return -1;
    }
    if(m_bwait_keyframe && 0 == psample->mediatype && psample->keyflag)
    {
        m_bwait_keyframe = false;
    }
    else if(m_bwait_keyframe)
    {
        srs_trace("wait for key frame, drop frame, mt:%d, pts:%" PRId64 " keyflag:%d, size:%d\n", psample->mediatype, psample->pts, psample->keyflag, psample->payload->length());
        return -1;
    }
    m_vFwdMsgList.push(psample);

    return 0;
}

int ForwardRtspQueue::get_queue_size()
{
    return (int)m_vFwdMsgList.size();
}

ForwardRtspSample* ForwardRtspQueue::dump_packet()
{
    ForwardRtspSample* pfwdmsg = NULL;
    if(m_vFwdMsgList.size() > 0)
    {
        pfwdmsg = m_vFwdMsgList.front();
        m_vFwdMsgList.pop();
    }

    return pfwdmsg;
}

int ForwardRtspQueue::get_sps_pps(std::string& sps, std::string& pps)
{
    if(m_pavccodec && m_pavccodec->sequenceParameterSetLength > 0 && m_pavccodec->pictureParameterSetLength > 0)
    {
        sps.clear();
        pps.clear();
        sps.append(m_pavccodec->sequenceParameterSetNALUnit, m_pavccodec->sequenceParameterSetLength);
        pps.append(m_pavccodec->pictureParameterSetNALUnit, m_pavccodec->pictureParameterSetLength);
        return 0;
    }

    return -1;
}

int ForwardRtspQueue::get_aac_sequence_hdr(std::string& audio_cfg)
{
    if(m_paaccodec && m_paaccodec->aac_extra_size > 0)
    {
        audio_cfg.clear();
        audio_cfg.append(m_paaccodec->aac_extra_data, m_paaccodec->aac_extra_size);
        return 0;
    }

    return -1;
}

 bool ForwardRtspQueue::is_codec_ok()
 {

     if(m_pavccodec) return m_pavccodec->is_avc_codec_ok();

     return false;
 }
bool SrsForwardRtsp::m_bInit(false);

SrsForwardRtsp::SrsForwardRtsp(SrsRequest* req):rtsp_forward_thread("fwdrtsp", this, SRS_RTSP_FORWARD_SLEEP_US)
{
    m_lConnectID = -1;
    m_pReq = req->copy();
    srs_debug(" m_pReq:%p = req->copy()\n", m_pReq);
    m_pvideofile    = NULL;
    m_paudiofile    = NULL;
}

SrsForwardRtsp::~SrsForwardRtsp()
{
    srs_trace("~SrsForwardRtsp begin");
    stop();
    srs_trace("~SrsForwardRtsp after stop");
    srs_freep(m_pReq);
    /*if(m_pReq)
    {
        delete m_pReq;
        m_pReq = NULL;
    }*/

    srs_trace("~SrsForwardRtsp after m_pSrsMsgArry");
    if(m_pvideofile)
    {
        fclose(m_pvideofile);
        m_pvideofile =NULL;
    }

    if(m_paudiofile)
    {
        fclose(m_paudiofile);
        m_paudiofile =NULL;
    }
    
    srs_trace("~SrsForwardRtsp end");
}

int SrsForwardRtsp::initialize(const char* prtsp_url, const char* prtsp_log_url)
{
    srs_trace("initialize(prtsp_url:%s, prtsp_log_url:%s)", prtsp_url, prtsp_log_url);
    if(!prtsp_url)
    {
        srs_error("initialize failed, invalid url prtsp_url:%s", prtsp_url);
        return ERROR_FORWARD_RTSP_INVALID_URL;
    }

    m_sRtspUrl = prtsp_url;
    if(!m_bInit)
    {
        if(prtsp_log_url)
        {
            m_sFwdRtspLogUrl = prtsp_log_url;
        }

        int ret = SVRtspPush_API_Initialize();
        if(ret < 0)
        {
            srs_error("ret:%d = SVRtspPush_API_Initialize() faield", ret);
            return ret;
        }

        ret = SVRtspPush_API_Init_log(m_sFwdRtspLogUrl.c_str(), 3, 2);
        srs_trace("initialize end, ret:%d", ret);
        m_bInit = true;
    }

    return ERROR_SUCCESS;
}

int SrsForwardRtsp::set_raw_data_path(const char* prawpath)
{
    srs_trace("prawpath:%s", prawpath);
    if(prawpath)
    {
        if(access(prawpath, F_OK) != 0)
        {
            mkdir(prawpath, 0777);
        }
        m_sFwdRtspRawDataDir = prawpath;
        return ERROR_SUCCESS;
    }

    return -1;
}

int SrsForwardRtsp::publish()
{
    int ret = start();
    srs_trace("Forward rtsp publish ret:%d", ret);
    return ret;
}

int SrsForwardRtsp::unpublish()
{
    stop();
    srs_trace("Forward rtsp unpublish end");
    return ERROR_SUCCESS;
}

int SrsForwardRtsp::start()
{
    srs_trace("start begin, m_bInit:%d", (int)m_bInit);
    int ret = ERROR_FORWARD_RTSP_NOT_INIT;
    if(m_bInit)
    {
         stop();

        ret = rtsp_forward_thread.start();
        srs_trace("start end ret:%d, m_bInit:%d", ret, (int)m_bInit);
        return ret;
    }
   
    return ret;
}

void SrsForwardRtsp::on_thread_start()
{
    srs_trace(" begin, m_bInit:%d", (int)m_bInit);
    
    if(m_bInit)
    {
        m_lConnectID = SVRtspPush_API_Connect(m_sRtspUrl.c_str(), SrsForwardRtsp::RtspCallback);
        srs_trace("m_lConnectID:%ld = SVRtspPush_API_Connect(m_sRtspUrl.c_str():%s, SrsForwardRtsp::RtspCallback:%p)", m_lConnectID, m_sRtspUrl.c_str(), SrsForwardRtsp::RtspCallback);
        //m_pvideofile    = fopen("avc.data", "wb");
        //m_paudiofile    = fopen("aac.data", "wb");
        if(!m_sFwdRtspRawDataDir.empty())
        {
            char path[256] = {0};
            sprintf(path, "%s/rtspfwd.h264", m_sFwdRtspRawDataDir.c_str());
            m_pvideofile = fopen(path, "wb");
            sprintf(path, "%s/rtspfwd.aac", m_sFwdRtspRawDataDir.c_str());
            m_paudiofile = fopen(path, "wb");
        }
        
        srs_trace("m_pvideofile:%p, m_paudiofile:%p", m_pvideofile, m_paudiofile);
        m_bRuning = true;
    }
    srs_trace(" end");
}

int SrsForwardRtsp::cycle()
{
    int ret = -1;
    //srs_trace("Forward rtsp cycle begin, m_vFwdMsgList.size():%d", (int)m_vFwdMsgList.size());
    while(m_vFwdMsgList.size() > 0 && m_bRuning)
    {
        int writed = 0;
        ForwardRtspSample* pfrs = dump_packet();
        if(pfrs)
        {
            //srs_trace("Forward rtsp cycle, send packetg, m_lConnectID:%ld, pfrs->mediatype:%d, size:%d, pts:%"PRId64"", m_lConnectID, pfrs->mediatype, pfrs->payload->length());
            if(pfrs->mediatype == 0)
            {
                ret = SVRtspPush_API_Send_VideoPacket(m_lConnectID, pfrs->payload->bytes(), pfrs->payload->length(), pfrs->pts);
                
                if(m_pvideofile && 0 == ret)
                {
                    writed = fwrite(pfrs->payload->bytes(), 1, pfrs->payload->length(), m_pvideofile);
                    //srs_trace("writed:%d = fwrite(pfrs->payload->bytes():%p, 1, pfrs->payload->length():%d, m_pvideofile:%p)", writed, pfrs->payload->bytes(), pfrs->payload->length(), m_pvideofile);
                }
                srs_trace("ret:%d = SVRtspPush_API_Send_VideoPacket, writed:%d", ret, writed);
                //srs_trace("ret:%d = SVRtspPush_API_Send_VideoPacket(m_lConnectID:%ld, pfrs->payload->bytes():%p, pfrs->payload->length():%d, pfrs->pts:%"PRId64")", ret, m_lConnectID, pfrs->payload->bytes(), pfrs->payload->length(), pfrs->pts);
            }
            else
            {
                ret = SVRtspPush_API_Send_AudioPacket(m_lConnectID, pfrs->payload->bytes(), pfrs->payload->length(), pfrs->pts);
                
                if(m_paudiofile && 0 == ret)
                {
                    writed = fwrite(pfrs->payload->bytes(), 1, pfrs->payload->length(), m_paudiofile);
                    //srs_trace("writed:%d = fwrite(pfrs->payload->bytes():%p, 1, pfrs->payload->length():%d, m_paudiofile:%p)", writed, pfrs->payload->bytes(), pfrs->payload->length(), m_paudiofile);
                }
                srs_trace("ret:%d = SVRtspPush_API_Send_AudioPacket, writed:%d", ret, writed);
                //srs_trace("ret:%d = SVRtspPush_API_Send_AudioPacket(m_lConnectID:%ld, pfrs->payload->bytes():%p, pfrs->payload->length():%d, pfrs->pts:%"PRId64")", ret, m_lConnectID, pfrs->payload->bytes(), pfrs->payload->length(), pfrs->pts);
            }
            srs_freep(pfrs);
            //delete pfrs;
            //pfrs = NULL;
            srs_trace("after delete pfrs");
        }
    }

    return ret;
}

void SrsForwardRtsp::on_thread_stop()
{
    
}

void SrsForwardRtsp::stop()
{
    srs_trace(" begin");
    m_bRuning = false;
    rtsp_forward_thread.stop();

    if(m_bInit && m_lConnectID >= 0)
    {
        int ret = SVRtspPush_API_Close(m_lConnectID);
        srs_trace("ret:%d = SVRtspPush_API_Close(m_lConnectID:%ld)", ret, m_lConnectID);
    }

    if(m_pvideofile)
    {
        fclose(m_pvideofile);
        m_pvideofile = NULL;
    }

    if(m_paudiofile)
    {
        fclose(m_paudiofile);
        m_paudiofile = NULL;
    }
}
    

bool SrsForwardRtsp::is_forward_rtsp_enable()
{
    return !m_sForwardRtspUrl.empty();
}

int SrsForwardRtsp::RtspCallback(int nUserID, E_Event_Code eHeaderEventCode)
{
    srs_trace("nUserID:%ld, eHeaderEventCode:%d\n", nUserID, eHeaderEventCode);
    return ERROR_SUCCESS;
}
