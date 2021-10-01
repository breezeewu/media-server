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

#include <srs_kernel_codec.hpp>

#include <string.h>
#include <stdlib.h>
using namespace std;

#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_kernel_stream.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_core_autofree.hpp>

string srs_codec_video2str(SrsCodecVideo codec)
{
    switch (codec) {
        case SrsCodecVideoAVC: 
            return "H264";
        case SrsCodecVideoOn2VP6:
        case SrsCodecVideoOn2VP6WithAlphaChannel:
            return "VP6";
        case SrsCodecVideoReserved:
        case SrsCodecVideoReserved1:
        case SrsCodecVideoReserved2:
        case SrsCodecVideoDisabled:
        case SrsCodecVideoSorensonH263:
        case SrsCodecVideoScreenVideo:
        case SrsCodecVideoScreenVideoVersion2:
        default:
            return "Other";
    }
}

string srs_codec_audio2str(SrsCodecAudio codec)
{
    switch (codec) {
        case SrsCodecAudioAAC:
            return "AAC";
        case SrsCodecAudioMP3:
            return "MP3";
        case SrsCodecAudioReserved1:
        case SrsCodecAudioLinearPCMPlatformEndian:
        case SrsCodecAudioADPCM:
        case SrsCodecAudioLinearPCMLittleEndian:
        case SrsCodecAudioNellymoser16kHzMono:
        case SrsCodecAudioNellymoser8kHzMono:
        case SrsCodecAudioNellymoser:
        case SrsCodecAudioReservedG711AlawLogarithmicPCM:
        case SrsCodecAudioReservedG711MuLawLogarithmicPCM:
        case SrsCodecAudioReserved:
        case SrsCodecAudioSpeex:
        case SrsCodecAudioReservedMP3_8kHz:
        case SrsCodecAudioReservedDeviceSpecificSound:
        default:
            return "Other";
    }
}

string srs_codec_aac_profile2str(SrsAacProfile aac_profile)
{
    switch (aac_profile) {
        case SrsAacProfileMain: return "Main";
        case SrsAacProfileLC: return "LC";
        case SrsAacProfileSSR: return "SSR";
        default: return "Other";
    }
}

string srs_codec_aac_object2str(SrsAacObjectType aac_object)
{
    switch (aac_object) {
        case SrsAacObjectTypeAacMain: return "Main";
        case SrsAacObjectTypeAacHE: return "HE";
        case SrsAacObjectTypeAacHEV2: return "HEv2";
        case SrsAacObjectTypeAacLC: return "LC";
        case SrsAacObjectTypeAacSSR: return "SSR";
        default: return "Other";
    }
}

SrsAacObjectType srs_codec_aac_ts2rtmp(SrsAacProfile profile)
{
    switch (profile) {
        case SrsAacProfileMain: return SrsAacObjectTypeAacMain;
        case SrsAacProfileLC: return SrsAacObjectTypeAacLC;
        case SrsAacProfileSSR: return SrsAacObjectTypeAacSSR;
        default: return SrsAacObjectTypeReserved;
    }
}

SrsAacProfile srs_codec_aac_rtmp2ts(SrsAacObjectType object_type)
{
    switch (object_type) {
        case SrsAacObjectTypeAacMain: return SrsAacProfileMain;
        case SrsAacObjectTypeAacHE:
        case SrsAacObjectTypeAacHEV2:
        case SrsAacObjectTypeAacLC: return SrsAacProfileLC;
        case SrsAacObjectTypeAacSSR: return SrsAacProfileSSR;
        default: return SrsAacProfileReserved;
    }
}

string srs_codec_avc_profile2str(SrsAvcProfile profile)
{
    switch (profile) {
        case SrsAvcProfileBaseline: return "Baseline";
        case SrsAvcProfileConstrainedBaseline: return "Baseline(Constrained)";
        case SrsAvcProfileMain: return "Main";
        case SrsAvcProfileExtended: return "Extended";
        case SrsAvcProfileHigh: return "High";
        case SrsAvcProfileHigh10: return "High(10)";
        case SrsAvcProfileHigh10Intra: return "High(10+Intra)";
        case SrsAvcProfileHigh422: return "High(422)";
        case SrsAvcProfileHigh422Intra: return "High(422+Intra)";
        case SrsAvcProfileHigh444: return "High(444)";
        case SrsAvcProfileHigh444Predictive: return "High(444+Predictive)";
        case SrsAvcProfileHigh444Intra: return "High(444+Intra)";
        default: return "Other";
    }
}

string srs_codec_avc_level2str(SrsAvcLevel level)
{
    switch (level) {
        case SrsAvcLevel_1: return "1";
        case SrsAvcLevel_11: return "1.1";
        case SrsAvcLevel_12: return "1.2";
        case SrsAvcLevel_13: return "1.3";
        case SrsAvcLevel_2: return "2";
        case SrsAvcLevel_21: return "2.1";
        case SrsAvcLevel_22: return "2.2";
        case SrsAvcLevel_3: return "3";
        case SrsAvcLevel_31: return "3.1";
        case SrsAvcLevel_32: return "3.2";
        case SrsAvcLevel_4: return "4";
        case SrsAvcLevel_41: return "4.1";
        case SrsAvcLevel_5: return "5";
        case SrsAvcLevel_51: return "5.1";
        default: return "Other";
    }
}

/**
* the public data, event HLS disable, others can use it.
*/
// 0 = 5.5 kHz = 5512 Hz
// 1 = 11 kHz = 11025 Hz
// 2 = 22 kHz = 22050 Hz
// 3 = 44 kHz = 44100 Hz
int flv_sample_rates[] = {5512, 11025, 22050, 44100, 0};

// the sample rates in the codec,
// in the sequence header.
int aac_sample_rates[] = 
{
    96000, 88200, 64000, 48000,
    44100, 32000, 24000, 22050,
    16000, 12000, 11025,  8000,
    7350,     0,     0,    0
};

SrsFlvCodec::SrsFlvCodec()
{
}

SrsFlvCodec::~SrsFlvCodec()
{
}

bool SrsFlvCodec::video_is_keyframe(char* data, int size)
{
    // 2bytes required.
    if (size < 1) {
        return false;
    }

    char frame_type = data[0];
    frame_type = (frame_type >> 4) & 0x0F;
    
    return frame_type == SrsCodecVideoAVCFrameKeyFrame;
}

bool SrsFlvCodec::video_is_sequence_header(char* data, int size)
{
    // sequence header only for h264
    if (!video_is_h26x(data, size)) {
        return false;
    }
    
    // 6 bytes required.
    if (size < 6) {
        return false;
    }

    char frame_type = data[0];
    frame_type = (frame_type >> 4) & 0x0F;

    char avc_packet_type = data[1];
    char xvcc_ver = data[5];
    return frame_type == SrsCodecVideoAVCFrameKeyFrame 
        && avc_packet_type == SrsCodecVideoAVCTypeSequenceHeader &&  1 == xvcc_ver;
}

bool SrsFlvCodec::audio_is_sequence_header(char* data, int size)
{
    // sequence header only for aac
    if (!audio_is_aac(data, size)) {
        return false;
    }
    
    // 2bytes required.
    if (size < 2) {
        return false;
    }
    
    char aac_packet_type = data[1];
    
    return aac_packet_type == SrsCodecAudioTypeSequenceHeader;
}

bool SrsFlvCodec::video_is_h26x(char* data, int size)
{
    // 1bytes required.
    if (size < 1) {
        return false;
    }

    char codec_id = data[0];
    codec_id = codec_id & 0x0F;
    //srs_trace("codec_id:%d, data[0]:%0x", (uint8_t)codec_id, (uint8_t)data[0]);
    return SrsCodecVideoAVC == codec_id || SrsCodecVideoHEVC == codec_id;
}

SrsCodecVideo SrsFlvCodec::video_codec_type(char* data, int size)
{
    // 1bytes required.
    if (size < 1) {
        return SrsCodecVideoReserved;
    }

    char codec_id = data[0];
    codec_id = codec_id & 0x0F;
    
    return (SrsCodecVideo)codec_id;
}

bool SrsFlvCodec::audio_is_aac(char* data, int size)
{
    // 1bytes required.
    if (size < 1) {
        return false;
    }
    
    char sound_format = data[0];
    sound_format = (sound_format >> 4) & 0x0F;
    
    return sound_format == SrsCodecAudioAAC;
}

bool SrsFlvCodec::video_is_acceptable(char* data, int size)
{
    // 1bytes required.
    if (size < 1) {
        return false;
    }
    
    char frame_type = data[0];
    char codec_id = frame_type & 0x0f;
    frame_type = (frame_type >> 4) & 0x0f;
    
    if (frame_type < 1 || frame_type > 5) {
        return false;
    }
    
    if (codec_id < 2 || codec_id > 12) {
        return false;
    }
    
    return true;
}

string srs_codec_avc_nalu2str(SrsAvcNaluType nalu_type)
{
    switch (nalu_type) {
        case SrsAvcNaluTypeNonIDR: return "NonIDR";
        case SrsAvcNaluTypeDataPartitionA: return "DataPartitionA";
        case SrsAvcNaluTypeDataPartitionB: return "DataPartitionB";
        case SrsAvcNaluTypeDataPartitionC: return "DataPartitionC";
        case SrsAvcNaluTypeIDR: return "IDR";
        case SrsAvcNaluTypeSEI: return "SEI";
        case SrsAvcNaluTypeSPS: return "SPS";
        case SrsAvcNaluTypePPS: return "PPS";
        case SrsAvcNaluTypeAccessUnitDelimiter: return "AccessUnitDelimiter";
        case SrsAvcNaluTypeEOSequence: return "EOSequence";
        case SrsAvcNaluTypeEOStream: return "EOStream";
        case SrsAvcNaluTypeFilterData: return "FilterData";
        case SrsAvcNaluTypeSPSExt: return "SPSExt";
        case SrsAvcNaluTypePrefixNALU: return "PrefixNALU";
        case SrsAvcNaluTypeSubsetSPS: return "SubsetSPS";
        case SrsAvcNaluTypeLayerWithoutPartition: return "LayerWithoutPartition";
        case SrsAvcNaluTypeCodedSliceExt: return "CodedSliceExt";
        case SrsAvcNaluTypeReserved: default: return "Other";
    }
}

SrsCodecSampleUnit::SrsCodecSampleUnit()
{
    size = 0;
    bytes = NULL;
}

SrsCodecSampleUnit::~SrsCodecSampleUnit()
{
}

SrsCodecSample::SrsCodecSample()
{
    clear();
}

SrsCodecSample::~SrsCodecSample()
{
}

void SrsCodecSample::clear()
{
    is_video = false;
    nb_sample_units = 0;

    cts = 0;
    frame_type = SrsCodecVideoAVCFrameReserved;
    avc_packet_type = SrsCodecVideoAVCTypeReserved;
    has_sps_pps = has_aud = has_idr = false;
    first_nalu_type = SrsAvcNaluTypeReserved;
    
    acodec = SrsCodecAudioReserved1;
    sound_rate = SrsCodecAudioSampleRateReserved;
    sound_size = SrsCodecAudioSampleSizeReserved;
    sound_type = SrsCodecAudioSoundTypeReserved;
    aac_packet_type = SrsCodecAudioTypeReserved;
}

int SrsCodecSample::add_sample_unit(char* bytes, int size)
{
    int ret = ERROR_SUCCESS;
    
    if (nb_sample_units >= SRS_SRS_MAX_CODEC_SAMPLE) {
        ret = ERROR_HLS_DECODE_ERROR;
        srs_error("hls decode samples error, "
            "exceed the max count: %d, ret=%d", SRS_SRS_MAX_CODEC_SAMPLE, ret);
        return ret;
    }
    
    SrsCodecSampleUnit* sample_unit = &sample_units[nb_sample_units++];
    sample_unit->bytes = bytes;
    sample_unit->size = size;
    
    // for video, parse the nalu type, set the IDR flag.
    if (is_video) {
        SrsAvcNaluType nal_unit_type = (SrsAvcNaluType)(bytes[0] & 0x1f);
        
        if (nal_unit_type == SrsAvcNaluTypeIDR) {
            has_idr = true;
        } else if (nal_unit_type == SrsAvcNaluTypeSPS || nal_unit_type == SrsAvcNaluTypePPS) {
            has_sps_pps = true;
        } else if (nal_unit_type == SrsAvcNaluTypeAccessUnitDelimiter) {
            has_aud = true;
        }
    
        if (first_nalu_type == SrsAvcNaluTypeReserved) {
            first_nalu_type = nal_unit_type;
        }
    }
    
    return ret;
}

int SrsCodecSample::add_prefix_sample_uint(char* bytes, int size)
{
     int ret = ERROR_SUCCESS;
    
    if (nb_sample_units >= SRS_SRS_MAX_CODEC_SAMPLE) {
        ret = ERROR_HLS_DECODE_ERROR;
        srs_error("hls decode samples error, "
            "exceed the max count: %d, ret=%d", SRS_SRS_MAX_CODEC_SAMPLE, ret);
        return ret;
    }
    for(int i = nb_sample_units; i > 0; i--)
    {
        sample_units[i] = sample_units[i-1];
    }
    nb_sample_units++;
    SrsCodecSampleUnit* sample_unit = &sample_units[0];
    sample_unit->bytes = bytes;
    sample_unit->size = size;

}
#if !defined(SRS_EXPORT_LIBRTMP)

SrsAvcAacCodec::SrsAvcAacCodec()
{
    avc_parse_sps               = true;
    
    width                       = 0;
    height                      = 0;
    duration                    = 0;
    NAL_unit_length             = 0;
    frame_rate                  = 0;

    video_data_rate             = 0;
    video_codec_id              = 0;

    audio_data_rate             = 0;
    audio_codec_id              = 0;

    avc_profile                 = SrsAvcProfileReserved;
    avc_level                   = SrsAvcLevelReserved;
    aac_object                  = SrsAacObjectTypeReserved;
    aac_sample_rate             = SRS_AAC_SAMPLE_RATE_UNSET; // sample rate ignored
    aac_channels                = 0;
    avc_extra_size              = 0;
    avc_extra_data              = NULL;
    aac_extra_size              = 0;
    aac_extra_data              = NULL;

    vidoeParameterSetLength     = 0;
    vidoeParameterSetNALUnit    = NULL;
    sequenceParameterSetLength  = 0;
    sequenceParameterSetNALUnit = NULL;
    pictureParameterSetLength   = 0;
    pictureParameterSetNALUnit  = NULL;

    payload_format = SrsAvcPayloadFormatGuess;
    stream = new SrsStream();
    LB_ADD_MEM(stream, sizeof(SrsStream));
}

SrsAvcAacCodec::~SrsAvcAacCodec()
{
    srs_freepa(avc_extra_data);
    srs_freepa(aac_extra_data);

    srs_freep(stream);
    srs_freepa(sequenceParameterSetNALUnit);
    srs_freepa(pictureParameterSetNALUnit);
}

bool SrsAvcAacCodec::is_avc_codec_ok()
{
    return avc_extra_size > 0 && avc_extra_data;
}

bool SrsAvcAacCodec::is_aac_codec_ok()
{
    return aac_extra_size > 0 && aac_extra_data;
}

bool SrsAvcAacCodec::is_idr_frame(const char* pframe)
{
    int nal_type = 0;
    if(SrsCodecVideoAVC == video_codec_id)
    {
        nal_type = pframe[0] & 0x1f;
        return 5 == nal_type;
    }
    else if(SrsCodecVideoHEVC == video_codec_id)
    {
        nal_type = (pframe[0]&0x7e) >> 1;;
        return nal_type >= 16 && nal_type <= 21;
    }
    return false;
    
}

int SrsAvcAacCodec::audio_aac_demux(char* data, int size, SrsCodecSample* sample)
{
    int ret = ERROR_SUCCESS;
    
    sample->is_video = false;
    
    if (!data || size <= 0) {
        srs_trace("no audio present, ignore it.");
        return ret;
    }
    
    if ((ret = stream->initialize(data, size)) != ERROR_SUCCESS) {
        return ret;
    }

    // audio decode
    if (!stream->require(1)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "aac decode sound_format failed. ret=%d", ret);
        return ret;
    }
    
    // @see: E.4.2 Audio Tags, video_file_format_spec_v10_1.pdf, page 76
    int8_t sound_format = stream->read_1bytes();
    
    int8_t sound_type = sound_format & 0x01;
    int8_t sound_size = (sound_format >> 1) & 0x01;
    int8_t sound_rate = (sound_format >> 2) & 0x03;
    sound_format = (sound_format >> 4) & 0x0f;
    
    audio_codec_id = sound_format;
    sample->acodec = (SrsCodecAudio)audio_codec_id;

    sample->sound_type = (SrsCodecAudioSoundType)sound_type;
    sample->sound_rate = (SrsCodecAudioSampleRate)sound_rate;
    sample->sound_size = (SrsCodecAudioSampleSize)sound_size;

    // we support h.264+mp3 for hls.
    if (audio_codec_id == SrsCodecAudioMP3) {
        return ERROR_HLS_TRY_MP3;
    }
    
    // only support aac
    if (audio_codec_id != SrsCodecAudioAAC) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "aac only support mp3/aac codec. actual codec id=%d, ret=%d", audio_codec_id, ret);
        //srs_trace_memory(stream->data(), 32);
        srs_err_memory(stream->data(), 16);
        return ret;
    }

    if (!stream->require(1)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "aac decode aac_packet_type failed. ret=%d", ret);
        return ret;
    }
    
    int8_t aac_packet_type = stream->read_1bytes();
    sample->aac_packet_type = (SrsCodecAudioType)aac_packet_type;
    
    if (aac_packet_type == SrsCodecAudioTypeSequenceHeader) {
        // AudioSpecificConfig
        // 1.6.2.1 AudioSpecificConfig, in aac-mp4a-format-ISO_IEC_14496-3+2001.pdf, page 33.
        aac_extra_size = stream->size() - stream->pos();
        if (aac_extra_size > 0) {
            srs_freepa(aac_extra_data);
            aac_extra_data = new char[aac_extra_size];
            LB_ADD_MEM(aac_extra_data, aac_extra_size);
            memcpy(aac_extra_data, stream->data() + stream->pos(), aac_extra_size);

            // demux the sequence header.
            if ((ret = audio_aac_sequence_header_demux(aac_extra_data, aac_extra_size)) != ERROR_SUCCESS) {
                return ret;
            }
        }
    } else if (aac_packet_type == SrsCodecAudioTypeRawData) {
        // ensure the sequence header demuxed
        if (!is_aac_codec_ok()) {
            tag_error(get_device_sn(), "aac ignore type=%d for no sequence header. ret=%d", aac_packet_type, ret);
            return ret;
        }
        
        // Raw AAC frame data in UI8 []
        // 6.3 Raw Data, aac-iso-13818-7.pdf, page 28
        if ((ret = sample->add_sample_unit(stream->data() + stream->pos(), stream->size() - stream->pos())) != ERROR_SUCCESS) {
            tag_error(get_device_sn(), "aac add sample failed. ret=%d", ret);
            return ret;
        }
    } else {
        // ignored.
    }
    
    // reset the sample rate by sequence header
    if (aac_sample_rate != SRS_AAC_SAMPLE_RATE_UNSET) {
        static int aac_sample_rates[] = {
            96000, 88200, 64000, 48000,
            44100, 32000, 24000, 22050,
            16000, 12000, 11025,  8000,
            7350,     0,     0,    0
        };
        switch (aac_sample_rates[aac_sample_rate]) {
            case 11025:
                sample->sound_rate = SrsCodecAudioSampleRate11025;
                break;
            case 22050:
                sample->sound_rate = SrsCodecAudioSampleRate22050;
                break;
            case 44100:
                sample->sound_rate = SrsCodecAudioSampleRate44100;
                break;
            default:
                break;
        };
    }
    
    srs_info("aac decoded, type=%d, codec=%d, asize=%d, rate=%d, format=%d, size=%d",
        sound_type, audio_codec_id, sound_size, sound_rate, sound_format, size);
    
    return ret;
}

int SrsAvcAacCodec::audio_mp3_demux(char* data, int size, SrsCodecSample* sample)
{
    int ret = ERROR_SUCCESS;

    // we always decode aac then mp3.
    srs_assert(sample->acodec == SrsCodecAudioMP3);
    
    // @see: E.4.2 Audio Tags, video_file_format_spec_v10_1.pdf, page 76
    if (!data || size <= 1) {
        srs_trace("no mp3 audio present, ignore it.");
        return ret;
    }

    // mp3 payload.
    if ((ret = sample->add_sample_unit(data + 1, size - 1)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(), "audio codec add mp3 sample failed. ret=%d", ret);
        return ret;
    }
    
    srs_info("audio decoded, type=%d, codec=%d, asize=%d, rate=%d, format=%d, size=%d", 
        sample->sound_type, audio_codec_id, sample->sound_size, sample->sound_rate, sample->acodec, size);
    
    return ret;
}

int SrsAvcAacCodec::audio_aac_sequence_header_demux(char* data, int size)
{
    int ret = ERROR_SUCCESS;
    //srs_trace("aac seq demux, data:%p, size:%d\n", data, size);
    //srs_trace_memory(data, size > 16 ? 16 : size);
    if ((ret = stream->initialize(data, size)) != ERROR_SUCCESS) {
        return ret;
    }
        
    // only need to decode the first 2bytes:
    //      audioObjectType, aac_profile, 5bits.
    //      samplingFrequencyIndex, aac_sample_rate, 4bits.
    //      channelConfiguration, aac_channels, 4bits
    if (!stream->require(2)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "audio codec decode aac sequence header failed. ret=%d", ret);
        return ret;
    }
    u_int8_t profile_ObjectType = stream->read_1bytes();
    u_int8_t samplingFrequencyIndex = stream->read_1bytes();
        
    aac_channels = (samplingFrequencyIndex >> 3) & 0x0f;
    samplingFrequencyIndex = ((profile_ObjectType << 1) & 0x0e) | ((samplingFrequencyIndex >> 7) & 0x01);
    profile_ObjectType = (profile_ObjectType >> 3) & 0x1f;

    // set the aac sample rate.
    aac_sample_rate = samplingFrequencyIndex;

    // convert the object type in sequence header to aac profile of ADTS.
    aac_object = (SrsAacObjectType)profile_ObjectType;
    if (aac_object == SrsAacObjectTypeReserved) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "audio codec decode aac sequence header failed, "
            "adts object=%d invalid. ret=%d", profile_ObjectType, ret);
        return ret;
    }
        
    // TODO: FIXME: to support aac he/he-v2, see: ngx_rtmp_codec_parse_aac_header
    // @see: https://github.com/winlinvip/nginx-rtmp-module/commit/3a5f9eea78fc8d11e8be922aea9ac349b9dcbfc2
    // 
    // donot force to LC, @see: https://github.com/ossrs/srs/issues/81
    // the source will print the sequence header info.
    //if (aac_profile > 3) {
        // Mark all extended profiles as LC
        // to make Android as happy as possible.
        // @see: ngx_rtmp_hls_parse_aac_header
        //aac_profile = 1;
    //}

    return ret;
}

int SrsAvcAacCodec::video_avc_demux(char* data, int size, SrsCodecSample* sample)
{
    int ret = ERROR_SUCCESS;
    
    sample->is_video = true;
    
    if (!data || size <= 0) {
        srs_trace("no video present, ignore it.");
        return ret;
    }
    
    if ((ret = stream->initialize(data, size)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(), "ret:%d = stream->initialize(data:%p, size:%d) failed", ret, data, size);
        return ret;
    }

    // video decode
    if (!stream->require(1)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode frame_type failed. ret=%d", ret);
        return ret;
    }
    
    // @see: E.4.3 Video Tags, video_file_format_spec_v10_1.pdf, page 78
    int8_t frame_type = stream->read_1bytes();
    int8_t codec_id = frame_type & 0x0f;
    frame_type = (frame_type >> 4) & 0x0f;
    
    sample->frame_type = (SrsCodecVideoAVCFrame)frame_type;
    
    // ignore info frame without error,
    // @see https://github.com/ossrs/srs/issues/288#issuecomment-69863909
    if (sample->frame_type == SrsCodecVideoAVCFrameVideoInfoFrame) {
        srs_warn("avc igone the info frame, ret=%d", ret);
        return ret;
    }
    
    // only support h.264/avc
    /*if (codec_id != SrsCodecVideoAVC) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc only support video h.264/avc codec. actual=%d, ret=%d", codec_id, ret);
        return ret;
    }*/
    video_codec_id = codec_id;
    if (!stream->require(4)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode avc_packet_type failed. ret=%d", ret);
        return ret;
    }
    int8_t avc_packet_type = stream->read_1bytes();
    int32_t composition_time = stream->read_3bytes();
    
    // pts = dts + cts.
    sample->cts = composition_time;
    sample->avc_packet_type = (SrsCodecVideoAVCType)avc_packet_type;
    //srs_trace("video_codec_id:%d, avc_packet_type:%d\n", video_codec_id, avc_packet_type);
    //srs_trace_memory(stream->data() + stream->pos(), 16);
    /*if(SrsCodecVideoAVCFrameKeyFrame == frame_type)
    {
        // add by zwu
        if(sequenceParameterSetLength > 0 && pictureParameterSetLength > 0)
        {
            sample->add_sample_unit(sequenceParameterSetNALUnit, sequenceParameterSetLength);
            sample->add_sample_unit(pictureParameterSetNALUnit, pictureParameterSetLength);
            srs_rtsp_debug("add sps and pps sequenceParameterSetLength:%d, pictureParameterSetLength:%d\n", sequenceParameterSetLength, pictureParameterSetLength);
        }
        // add end
    }*/
    if (avc_packet_type == SrsCodecVideoAVCTypeSequenceHeader) {
        if(SrsCodecVideoAVC == codec_id)
        {
            if ((ret = avc_demux_sps_pps(stream)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(), "ret:%d = avc_demux_sps_pps(stream) failed", ret);
            return ret;
            }
        }
        else
        {
            ret = hevc_demux_hvcc(stream);
            srs_trace("ret:%d = hevc_demux_hvcc(stream:%p)\n", ret, stream);
            if (ret != ERROR_SUCCESS) {
            tag_error(get_device_sn(), "ret:%d = hevc_demux_hvcc(stream) failed", ret);
            return ret;
            }
        }
    } else if (avc_packet_type == SrsCodecVideoAVCTypeNALU){
        if ((ret = video_nalu_demux(stream, sample)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(), "ret:%d = video_nalu_demux(stream, sample) failed, codec_id:%d, frame_type:%d, avc_packet_type:%d, composition_time:%d\n", ret, codec_id, frame_type, avc_packet_type, composition_time);
            return ret;
        }
    } else {
        // ignored.
    }
    
    srs_info("avc decoded, type=%d, codec=%d, avc=%d, cts=%d, size=%d",
        frame_type, video_codec_id, avc_packet_type, composition_time, size);
    
    return ret;
}

int SrsAvcAacCodec::video_nalu_demux(SrsStream* stream, SrsCodecSample* sample)
{
    int ret = ERROR_SUCCESS;
    
    // ensure the sequence header demuxed
    if (!is_avc_codec_ok()) {
        srs_warn("avc ignore type=%d for no sequence header. ret=%d", SrsCodecVideoAVCTypeNALU, ret);
        return ret;
    }
    //srs_trace_memory(stream->data(), 32);
    // guess for the first time.
    if (payload_format == SrsAvcPayloadFormatGuess) {
        // One or more NALUs (Full frames are required)
        // try  "AnnexB" from H.264-AVC-ISO_IEC_14496-10.pdf, page 211.
        if ((ret = avc_demux_annexb_format(stream, sample)) != ERROR_SUCCESS) {
            // stop try when system error.
            if (ret != ERROR_HLS_AVC_TRY_OTHERS) {
                tag_error(get_device_sn(), "avc demux for annexb failed. ret=%d", ret);
                return ret;
            }
            
            // try "ISO Base Media File Format" from H.264-AVC-ISO_IEC_14496-15.pdf, page 20
            if ((ret = avc_demux_ibmf_format(stream, sample)) != ERROR_SUCCESS) {
                srs_error("ret:%d = avc_demux_ibmf_format(stream, sample) failed\n", ret);
                return ret;
            } else {
                payload_format = SrsAvcPayloadFormatIbmf;
                srs_info("hls guess avc payload is ibmf format.");
            }
        } else {
            payload_format = SrsAvcPayloadFormatAnnexb;
            srs_info("hls guess avc payload is annexb format.");
        }
    } else if (payload_format == SrsAvcPayloadFormatIbmf) {
        // try "ISO Base Media File Format" from H.264-AVC-ISO_IEC_14496-15.pdf, page 20
        if ((ret = avc_demux_ibmf_format(stream, sample)) != ERROR_SUCCESS) {
            srs_error("ret:%d = avc_demux_ibmf_format(stream, sample) failed, payload_format:%d\n", ret, payload_format);
            return ret;
        }
        srs_info("hls decode avc payload in ibmf format.");
    } else {
        // One or more NALUs (Full frames are required)
        // try  "AnnexB" from H.264-AVC-ISO_IEC_14496-10.pdf, page 211.
        if ((ret = avc_demux_annexb_format(stream, sample)) != ERROR_SUCCESS) {
            // ok, we guess out the payload is annexb, but maybe changed to ibmf.
            if (ret != ERROR_HLS_AVC_TRY_OTHERS) {
                tag_error(get_device_sn(), "avc demux for annexb failed. ret=%d", ret);
                return ret;
            }
            
            // try "ISO Base Media File Format" from H.264-AVC-ISO_IEC_14496-15.pdf, page 20
            if ((ret = avc_demux_ibmf_format(stream, sample)) != ERROR_SUCCESS) {
                return ret;
            } else {
                payload_format = SrsAvcPayloadFormatIbmf;
                srs_warn("hls avc payload change from annexb to ibmf format.");
            }
        }
        srs_info("hls decode avc payload in annexb format.");
    }
    
    return ret;
}

int SrsAvcAacCodec::avc_demux_sps_pps(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
	//dump_memory("avcc", stream->data(), stream->size());
    // AVCDecoderConfigurationRecord
    // 5.2.4.1.1 Syntax, H.264-AVC-ISO_IEC_14496-15.pdf, page 16
    avc_extra_size = stream->size() - stream->pos();
    //srs_trace("avc seq demux, stream->data():%p, avc_extra_size:%d\n", stream->data(), avc_extra_size);
    //srs_trace_memory(stream->data(), avc_extra_size > 48 ? 48 : avc_extra_size);
    if (avc_extra_size > 0) {
        srs_freepa(avc_extra_data);
        avc_extra_data = new char[avc_extra_size];
        LB_ADD_MEM(avc_extra_data, avc_extra_size);
        memcpy(avc_extra_data, stream->data() + stream->pos(), avc_extra_size);
    }
    
    if (!stream->require(6)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode sequenc header failed. ret=%d", ret);
        dump_memory("avcc", stream->data(), stream->size());
        return ret;
    }
    //int8_t configurationVersion = stream->read_1bytes();
    stream->read_1bytes();
    //int8_t AVCProfileIndication = stream->read_1bytes();
    avc_profile = (SrsAvcProfile)stream->read_1bytes();
    //int8_t profile_compatibility = stream->read_1bytes();
    stream->read_1bytes();
    //int8_t AVCLevelIndication = stream->read_1bytes();
    avc_level = (SrsAvcLevel)stream->read_1bytes();
    
    // parse the NALU size.
    int8_t lengthSizeMinusOne = stream->read_1bytes();
    lengthSizeMinusOne &= 0x03;
    NAL_unit_length = lengthSizeMinusOne;
    
    // 5.3.4.2.1 Syntax, H.264-AVC-ISO_IEC_14496-15.pdf, page 16
    // 5.2.4.1 AVC decoder configuration record
    // 5.2.4.1.2 Semantics
    // The value of this field shall be one of 0, 1, or 3 corresponding to a
    // length encoded with 1, 2, or 4 bytes, respectively.
    if (NAL_unit_length == 2) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "sps lengthSizeMinusOne should never be 2. ret=%d", ret);
        dump_memory("avcc", stream->data(), stream->size());
        return ret;
    }
    
    // 1 sps, 7.3.2.1 Sequence parameter set RBSP syntax
    // H.264-AVC-ISO_IEC_14496-10.pdf, page 45.
    if (!stream->require(1)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode sequenc header sps failed. ret=%d", ret);
        return ret;
    }
    int8_t numOfSequenceParameterSets = stream->read_1bytes();
    numOfSequenceParameterSets &= 0x1f;
    if (numOfSequenceParameterSets != 1) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode sequenc header sps failed. ret=%d, numOfSequenceParameterSets:%0x, stream->pos():%d, stream->size():%d", ret, (int)numOfSequenceParameterSets, stream->pos(), stream->size());
        dump_memory("avcc", stream->data(), stream->size());;
        return ret;
    }
    if (!stream->require(2)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode sequenc header sps size failed. ret=%d", ret);
        return ret;
    }
    sequenceParameterSetLength = stream->read_2bytes();
    if (!stream->require(sequenceParameterSetLength)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode sequenc header sps data failed. ret=%d", ret);
        dump_memory("avcc", stream->data(), stream->size());
        return ret;
    }
    if (sequenceParameterSetLength > 0) {
        srs_freepa(sequenceParameterSetNALUnit);
        sequenceParameterSetNALUnit = new char[sequenceParameterSetLength];
        LB_ADD_MEM(sequenceParameterSetNALUnit, sequenceParameterSetLength);
        stream->read_bytes(sequenceParameterSetNALUnit, sequenceParameterSetLength);
        //srs_trace("stream->read_bytes(sequenceParameterSetNALUnit:%p, sequenceParameterSetLength:%d)", sequenceParameterSetNALUnit, sequenceParameterSetLength);
        //srs_trace_memory(sequenceParameterSetNALUnit, sequenceParameterSetLength);
    }
    // 1 pps
    if (!stream->require(1)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode sequenc header pps failed. ret=%d", ret);
        dump_memory("avcc", stream->data(), stream->size());
        return ret;
    }
    int8_t numOfPictureParameterSets = stream->read_1bytes();
    numOfPictureParameterSets &= 0x1f;
    if (numOfPictureParameterSets != 1) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode sequenc header pps failed. ret=%d", ret);
        dump_memory("avcc", stream->data(), stream->size());
        return ret;
    }
    if (!stream->require(2)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode sequenc header pps size failed. ret=%d", ret);
        dump_memory("avcc", stream->data(), stream->size());
        return ret;
    }
    pictureParameterSetLength = stream->read_2bytes();
    if (!stream->require(pictureParameterSetLength)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode sequenc header pps data failed. ret=%d", ret);
        dump_memory("avcc", stream->data(), stream->size());
        return ret;
    }
    if (pictureParameterSetLength > 0) {
        srs_freepa(pictureParameterSetNALUnit);
        pictureParameterSetNALUnit = new char[pictureParameterSetLength];
        LB_ADD_MEM(pictureParameterSetNALUnit, pictureParameterSetLength);
        stream->read_bytes(pictureParameterSetNALUnit, pictureParameterSetLength);
        //srs_trace("stream->read_bytes(pictureParameterSetNALUnit:%p, pictureParameterSetLength:%d)", sequenceParameterSetNALUnit, pictureParameterSetLength);
        //srs_trace_memory(pictureParameterSetNALUnit, pictureParameterSetLength);
    }
    
    return avc_demux_sps();
}

int SrsAvcAacCodec::hevc_demux_hvcc(SrsStream* stream)
{
    int ret = ERROR_SUCCESS;
    if(NULL == stream)
    {
        srs_error("hevc_demux_hvcc failed, NULL == stream\n");
        return ret;
    }

    avc_extra_size = stream->size() - stream->pos();
    //srs_trace("avc seq demux, stream->data():%p, avc_extra_size:%d\n", stream->data(), avc_extra_size);
    //srs_trace_memory(stream->data(), avc_extra_size > 48 ? 48 : avc_extra_size);
    if (avc_extra_size > 0) {
        srs_freepa(avc_extra_data);
        avc_extra_data = new char[avc_extra_size];
        LB_ADD_MEM(avc_extra_data, avc_extra_size);
        memcpy(avc_extra_data, stream->data() + stream->pos(), avc_extra_size);
    }
    // skip hvcc fixed header, add by dawson
    stream->skip(19);
    frame_rate = stream->read_2bytes();
    //stream->read_bits(6);
    NAL_unit_length = stream->read_1bytes() & 0x03;
    srs_info("hevc_demux_hvcc frame_rate:%d, NAL_unit_length:%d\n", frame_rate, NAL_unit_length);
    //stream->skip(1);
    int numOfArrays = stream->read_1bytes();
    while (numOfArrays > 0)
    {
        uint8_t nal_type = stream->read_1bytes()&0x3f;
        uint8_t nal_num = stream->read_2bytes();
        for (int i = 0; i < nal_num; i++)
        {
            int nal_size = stream->read_2bytes();
            if(32 == nal_type)
            {
                srs_freepa(vidoeParameterSetNALUnit);
                vidoeParameterSetLength = nal_size;
                vidoeParameterSetNALUnit = new char[vidoeParameterSetLength];
                LB_ADD_MEM(vidoeParameterSetNALUnit, vidoeParameterSetLength);
                stream->read_bytes(vidoeParameterSetNALUnit, vidoeParameterSetLength);
                //srs_trace("hevc vps update, len:%d\n", vidoeParameterSetLength);
                //srs_trace_memory(vidoeParameterSetNALUnit, vidoeParameterSetLength);
            }
            else if(33 == nal_type)
            {

                srs_freepa(sequenceParameterSetNALUnit);
                sequenceParameterSetLength = nal_size;
                sequenceParameterSetNALUnit = new char[sequenceParameterSetLength];
                LB_ADD_MEM(sequenceParameterSetNALUnit, sequenceParameterSetLength);
                stream->read_bytes(sequenceParameterSetNALUnit, sequenceParameterSetLength);
                ret = hevc_demux_sps(sequenceParameterSetNALUnit, sequenceParameterSetLength);
                SRS_CHECK_RESULT(ret);
                //srs_trace("hevc sps update, len:%d\n", sequenceParameterSetLength);
                //srs_trace_memory(sequenceParameterSetNALUnit, sequenceParameterSetLength);
            }
            else if(34 == nal_type)
            {
                srs_freepa(pictureParameterSetNALUnit);
                pictureParameterSetLength = nal_size;
                pictureParameterSetNALUnit = new char[pictureParameterSetLength];
                LB_ADD_MEM(pictureParameterSetNALUnit, pictureParameterSetLength);
                stream->read_bytes(pictureParameterSetNALUnit, pictureParameterSetLength);
                //srs_trace("hevc sps update, len:%d\n", pictureParameterSetLength);
                //srs_trace_memory(pictureParameterSetNALUnit, pictureParameterSetLength);
            }
            else
            {
                stream->skip(nal_size);
            }
            
        }

        numOfArrays--;
    };
    return ret;
}

int SrsAvcAacCodec::avc_demux_sps()
{
    int ret = ERROR_SUCCESS;
    
    if (!sequenceParameterSetLength) {
        return ret;
    }
    
    SrsStream stream;
    if ((ret = stream.initialize(sequenceParameterSetNALUnit, sequenceParameterSetLength)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // for NALU, 7.3.1 NAL unit syntax
    // H.264-AVC-ISO_IEC_14496-10-2012.pdf, page 61.
    if (!stream.require(1)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "avc decode sps failed. ret=%d", ret);
        return ret;
    }
    int8_t nutv = stream.read_1bytes();
    
    // forbidden_zero_bit shall be equal to 0.
    int8_t forbidden_zero_bit = (nutv >> 7) & 0x01;
    if (forbidden_zero_bit) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "forbidden_zero_bit shall be equal to 0. ret=%d, nutv:%0x", ret, nutv);
        srs_err_memory(sequenceParameterSetNALUnit, sequenceParameterSetLength);
        return ret;
    }
    
    // nal_ref_idc not equal to 0 specifies that the content of the NAL unit contains a sequence parameter set or a picture
    // parameter set or a slice of a reference picture or a slice data partition of a reference picture.
    int8_t nal_ref_idc = (nutv >> 5) & 0x03;
    if (!nal_ref_idc) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "for sps, nal_ref_idc shall be not be equal to 0. ret=%d", ret);
        return ret;
    }
    
    // 7.4.1 NAL unit semantics
    // H.264-AVC-ISO_IEC_14496-10-2012.pdf, page 61.
    // nal_unit_type specifies the type of RBSP data structure contained in the NAL unit as specified in Table 7-1.
    SrsAvcNaluType nal_unit_type = (SrsAvcNaluType)(nutv & 0x1f);
    if (nal_unit_type != 7) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "for sps, nal_unit_type shall be equal to 7. ret=%d", ret);
        return ret;
    }
    
    // decode the rbsp from sps.
    // rbsp[ i ] a raw byte sequence payload is specified as an ordered sequence of bytes.
    int8_t* rbsp = new int8_t[sequenceParameterSetLength];
    LB_ADD_MEM(rbsp, sequenceParameterSetLength);
    SrsAutoFreeA(int8_t, rbsp);
    
    int nb_rbsp = 0;
    while (!stream.empty()) {
        rbsp[nb_rbsp] = stream.read_1bytes();
        
        // XX 00 00 03 XX, the 03 byte should be drop.
        if (nb_rbsp > 2 && rbsp[nb_rbsp - 2] == 0 && rbsp[nb_rbsp - 1] == 0 && rbsp[nb_rbsp] == 3) {
            // read 1byte more.
            if (stream.empty()) {
                break;
            }
            rbsp[nb_rbsp] = stream.read_1bytes();
            nb_rbsp++;
            
            continue;
        }
        
        nb_rbsp++;
    }
    
    return avc_demux_sps_rbsp((char*)rbsp, nb_rbsp);
}
int SrsAvcAacCodec::decode_rbsp_from_nalu(char* pnalu, int nalu_len, char* prbsp, int rbsp_len)
{
    if(NULL == pnalu || NULL == prbsp || nalu_len <= 0 || rbsp_len < nalu_len)
    {
        srs_error("Invalid parameter, pnalu:%p, prbsp:%p, nalu_len:%d, rbsp_len:%d\n", pnalu, prbsp, nalu_len, rbsp_len);
        return -1;
    }

    int nb_rbsp = 0;
    int offset = 0;
    while (offset < nalu_len) {
        prbsp[nb_rbsp] = pnalu[offset++];
        
        // XX 00 00 03 XX, the 03 byte should be drop.
        if (nb_rbsp > 2 && prbsp[nb_rbsp - 2] == 0 && prbsp[nb_rbsp - 1] == 0 && prbsp[nb_rbsp] == 3) {
            // read 1byte more.
            if (offset >= nalu_len) {
                break;
            }
            prbsp[nb_rbsp] = pnalu[offset++];
            nb_rbsp++;
            
            continue;
        }
        
        nb_rbsp++;
    }
    /*srs_trace("nalu sps len:%d\n", nalu_len);
    srs_trace_memory(pnalu, nalu_len);
    srs_trace("rbsp sps len:%d\n", nb_rbsp);
    srs_trace_memory(prbsp, nb_rbsp);*/
    return nb_rbsp;
}

int SrsAvcAacCodec::hevc_demux_sps_rbsp(char* rbsp, int nb_rbsp)
{
    int ret = ERROR_SUCCESS;
    // reparse the rbsp.
    CBitStream bs;
    if ((ret = bs.initialize(rbsp, nb_rbsp)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // for SPS, 7.3.2.1.1 Sequence parameter set data syntax
    // H.264-AVC-ISO_IEC_14496-10-2012.pdf, page 62.
    if (!bs.require(5)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "sps shall atleast 3bytes. ret=%d", ret);
        return ret;
    }

    bs.read_bits(1);
    int nal_type = bs.read_bits(6);
    if(33 != nal_type)
    {
        srs_error("Invalid sps nal type %d\n", nal_type);
        return ERROR_RTMP_HEVC_SPS;
    }
    int i = 0;
    bs.read_bits(6);    // layerid
    bs.read_bits(3);    // tid
    bs.read_bits(4);
    int sps_max_sub_layers_minus1 = bs.read_bits(3);
    bs.read_bits(1);
    bs.read_bits(2);    // profile_space
    bs.read_bits(1);    // tier_flag
    bs.read_bits(5);    // profile_idc
    bs.skip(10);
    uint8_t sub_layer_profile_present_flag[8] = {0};
    uint8_t sub_layer_level_present_flag[8] = {0};
    bs.read_bits(8);    // level_idc
    //srs_debug("sps_max_sub_layers_minus1:%d, profile_idc:%d, level_idc:%d\n", sps_max_sub_layers_minus1, profile_idc, level_idc);
    for (i = 0; i < sps_max_sub_layers_minus1; i++) {
				sub_layer_profile_present_flag[i] = (uint8_t)bs.read_bits(1);
				sub_layer_level_present_flag[i] = (uint8_t)bs.read_bits(1);
			}

    if (sps_max_sub_layers_minus1 > 0)
        for (i = sps_max_sub_layers_minus1; i < 8; i++)
            bs.read_bits(2); // reserved_zero_2bits[i]

    for (i = 0; i < sps_max_sub_layers_minus1; i++) {
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
            bs.read_bits(32);
            bs.read_bits(32);
            bs.read_bits(24);
        }

        if (sub_layer_level_present_flag[i])
            bs.read_bits(8);
    }
    int separate_colour_plane_flag= 0;
    bs.read_uev();   // sps_seq_parameter_set_id
    int chromaFormat = bs.read_uev(); // pitcure color space, 1 indicate 4:2:0(yuv420)
    if (3 == chromaFormat)
    {
        separate_colour_plane_flag = bs.read_bits(1); // separate_colour_plane_flag, specity for solor space 4:4:4
    }
    width = bs.read_uev(); // pic_width_in_luma_samples
    height = bs.read_uev(); // pic_height_in_luma_samples

    if (bs.read_bits(1)) // conformance_window_flag
    {
        int conf_win_left_offset = 0, conf_win_right_offset = 0, conf_win_top_offset = 0, conf_win_bottom_offset = 0;
        int sub_width_c = ((1 == chromaFormat) || (2 == chromaFormat)) && (0 == separate_colour_plane_flag) ? 2 : 1;
        int sub_height_c = (1 == chromaFormat) && (0 == separate_colour_plane_flag) ? 2 : 1;

        conf_win_left_offset = bs.read_uev();	// conf_win_left_offset
        conf_win_right_offset = bs.read_uev();	// conf_win_right_offset
        conf_win_top_offset = bs.read_uev();	// conf_win_top_offset
        conf_win_bottom_offset = bs.read_uev();	// conf_win_bottom_offset
        width -= (sub_width_c*conf_win_right_offset + sub_width_c*conf_win_left_offset);
        height -= (sub_height_c*conf_win_bottom_offset + sub_height_c*conf_win_top_offset);
        
    }
    srs_info("parser sps width:%d, height:%d, chromaFormat:%d\n", width, height, chromaFormat);
    return 0;
}

int SrsAvcAacCodec::avc_demux_sps_rbsp(char* rbsp, int nb_rbsp)
{
    int ret = ERROR_SUCCESS;
    
    // we donot parse the detail of sps.
    // @see https://github.com/ossrs/srs/issues/474
    if (!avc_parse_sps) {
        return ret;
    }
    
    // reparse the rbsp.
    SrsStream stream;
    if ((ret = stream.initialize(rbsp, nb_rbsp)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // for SPS, 7.3.2.1.1 Sequence parameter set data syntax
    // H.264-AVC-ISO_IEC_14496-10-2012.pdf, page 62.
    if (!stream.require(3)) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "sps shall atleast 3bytes. ret=%d", ret);
        return ret;
    }
    u_int8_t profile_idc = stream.read_1bytes();
    if (!profile_idc) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "sps the profile_idc invalid. ret=%d", ret);
        return ret;
    }
    //avc_profile = profile_idc;
    int8_t flags = stream.read_1bytes();
    if (flags & 0x03) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "sps the flags invalid. ret=%d", ret);
        return ret;
    }
    
    u_int8_t level_idc = stream.read_1bytes();
    if (!level_idc) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "sps the level_idc invalid. ret=%d", ret);
        return ret;
    }
    //avc_level = level_idc;
    SrsBitStream bs;
    if ((ret = bs.initialize(&stream)) != ERROR_SUCCESS) {
        return ret;
    }
    
    int32_t seq_parameter_set_id = -1;
    if ((ret = srs_avc_nalu_read_uev(&bs, seq_parameter_set_id)) != ERROR_SUCCESS) {
        return ret;
    }
    if (seq_parameter_set_id < 0) {
        ret = ERROR_HLS_DECODE_ERROR;
        tag_error(get_device_sn(), "sps the seq_parameter_set_id invalid. ret=%d", ret);
        return ret;
    }
    srs_info("sps parse profile=%d, level=%d, sps_id=%d", profile_idc, level_idc, seq_parameter_set_id);
    
    int32_t chroma_format_idc = -1;
    if (profile_idc == 100 || profile_idc == 110 || profile_idc == 122 || profile_idc == 244
        || profile_idc == 44 || profile_idc == 83 || profile_idc == 86 || profile_idc == 118
        || profile_idc == 128
    ) {
        if ((ret = srs_avc_nalu_read_uev(&bs, chroma_format_idc)) != ERROR_SUCCESS) {
            return ret;
        }
        if (chroma_format_idc == 3) {
            int8_t separate_colour_plane_flag = -1;
            if ((ret = srs_avc_nalu_read_bit(&bs, separate_colour_plane_flag)) != ERROR_SUCCESS) {
                return ret;
            }
        }
        
        int32_t bit_depth_luma_minus8 = -1;
        if ((ret = srs_avc_nalu_read_uev(&bs, bit_depth_luma_minus8)) != ERROR_SUCCESS) {
            return ret;
        }
        
        int32_t bit_depth_chroma_minus8 = -1;
        if ((ret = srs_avc_nalu_read_uev(&bs, bit_depth_chroma_minus8)) != ERROR_SUCCESS) {
            return ret;
        }
        
        int8_t qpprime_y_zero_transform_bypass_flag = -1;
        if ((ret = srs_avc_nalu_read_bit(&bs, qpprime_y_zero_transform_bypass_flag)) != ERROR_SUCCESS) {
            return ret;
        }
        
        int8_t seq_scaling_matrix_present_flag = -1;
        if ((ret = srs_avc_nalu_read_bit(&bs, seq_scaling_matrix_present_flag)) != ERROR_SUCCESS) {
            return ret;
        }
        if (seq_scaling_matrix_present_flag) {
            int nb_scmpfs = ((chroma_format_idc != 3)? 8:12);
            for (int i = 0; i < nb_scmpfs; i++) {
                int8_t seq_scaling_matrix_present_flag_i = -1;
                if ((ret = srs_avc_nalu_read_bit(&bs, seq_scaling_matrix_present_flag_i)) != ERROR_SUCCESS) {
                    return ret;
                }
            }
        }
    }
    
    int32_t log2_max_frame_num_minus4 = -1;
    if ((ret = srs_avc_nalu_read_uev(&bs, log2_max_frame_num_minus4)) != ERROR_SUCCESS) {
        return ret;
    }
    
    int32_t pic_order_cnt_type = -1;
    if ((ret = srs_avc_nalu_read_uev(&bs, pic_order_cnt_type)) != ERROR_SUCCESS) {
        return ret;
    }
    
    if (pic_order_cnt_type == 0) {
        int32_t log2_max_pic_order_cnt_lsb_minus4 = -1;
        if ((ret = srs_avc_nalu_read_uev(&bs, log2_max_pic_order_cnt_lsb_minus4)) != ERROR_SUCCESS) {
            return ret;
        }
    } else if (pic_order_cnt_type == 1) {
        int8_t delta_pic_order_always_zero_flag = -1;
        if ((ret = srs_avc_nalu_read_bit(&bs, delta_pic_order_always_zero_flag)) != ERROR_SUCCESS) {
            return ret;
        }
        
        int32_t offset_for_non_ref_pic = -1;
        if ((ret = srs_avc_nalu_read_uev(&bs, offset_for_non_ref_pic)) != ERROR_SUCCESS) {
            return ret;
        }
        
        int32_t offset_for_top_to_bottom_field = -1;
        if ((ret = srs_avc_nalu_read_uev(&bs, offset_for_top_to_bottom_field)) != ERROR_SUCCESS) {
            return ret;
        }
        
        int32_t num_ref_frames_in_pic_order_cnt_cycle = -1;
        if ((ret = srs_avc_nalu_read_uev(&bs, num_ref_frames_in_pic_order_cnt_cycle)) != ERROR_SUCCESS) {
            return ret;
        }
        if (num_ref_frames_in_pic_order_cnt_cycle < 0) {
            ret = ERROR_HLS_DECODE_ERROR;
            tag_error(get_device_sn(), "sps the num_ref_frames_in_pic_order_cnt_cycle invalid. ret=%d", ret);
            return ret;
        }
        for (int i = 0; i < num_ref_frames_in_pic_order_cnt_cycle; i++) {
            int32_t offset_for_ref_frame_i = -1;
            if ((ret = srs_avc_nalu_read_uev(&bs, offset_for_ref_frame_i)) != ERROR_SUCCESS) {
                return ret;
            }
        }
    }
    
    int32_t max_num_ref_frames = -1;
    if ((ret = srs_avc_nalu_read_uev(&bs, max_num_ref_frames)) != ERROR_SUCCESS) {
        return ret;
    }
    
    int8_t gaps_in_frame_num_value_allowed_flag = -1;
    if ((ret = srs_avc_nalu_read_bit(&bs, gaps_in_frame_num_value_allowed_flag)) != ERROR_SUCCESS) {
        return ret;
    }
    
    int32_t pic_width_in_mbs_minus1 = -1;
    if ((ret = srs_avc_nalu_read_uev(&bs, pic_width_in_mbs_minus1)) != ERROR_SUCCESS) {
        return ret;
    }
    
    int32_t pic_height_in_map_units_minus1 = -1;
    if ((ret = srs_avc_nalu_read_uev(&bs, pic_height_in_map_units_minus1)) != ERROR_SUCCESS) {
        return ret;
    }
    
    width = (int)(pic_width_in_mbs_minus1 + 1) * 16;
    height = (int)(pic_height_in_map_units_minus1 + 1) * 16;
    
    return ret;
}

int SrsAvcAacCodec::hevc_demux_sps(char* pnalu, int nalu_len)
{
    //srs_trace("hevc_demux_sps(pnalu:%p, nalu_len:%d)\n", pnalu, nalu_len);
    char* prbsp = new char[nalu_len];
    LB_ADD_MEM(prbsp, nalu_len);
    memset(prbsp, 0, nalu_len);
    int rbsp_len = decode_rbsp_from_nalu(pnalu, nalu_len, prbsp, nalu_len);
    //srs_trace("rbsp_len:%d = decode_rbsp_from_nalu(pnalu:%p, nalu_len:%d, prbsp:%p, nalu_len:%d)\n", rbsp_len, pnalu, nalu_len, prbsp, nalu_len);
    SRS_CHECK_RESULT(rbsp_len);
    /*if(rbsp_len <= 0)
    {
        lberror("rbsp_len:%d = decode_rbsp_from_nalu(pnalu:%p, nalu_len:%d, prbsp:%p, nalu_len:%d) failed\n", rbsp_len, pnalu, nalu_len, prbsp, nalu_len);
        return rbsp_len;
    }*/
    int ret = hevc_demux_sps_rbsp(prbsp, rbsp_len);
    //srs_trace("ret:%d = hevc_demux_sps_rbsp(prbsp:%p, rbsp_len:%d)\n", ret, prbsp, rbsp_len);
    SRS_CHECK_RESULT(ret);
    srs_freepa(prbsp);

    return ret;
}

int SrsAvcAacCodec::avc_demux_annexb_format(SrsStream* stream, SrsCodecSample* sample)
{
    int ret = ERROR_SUCCESS;
    
    // not annexb, try others
    if (!srs_avc_startswith_annexb(stream, NULL)) {
        //srs_trace("srs_avc_startswith_annexb(stream, NULL) failed, pos:%d\n", stream->pos());
        
        return ERROR_HLS_AVC_TRY_OTHERS;
    }
    
    // AnnexB
    // B.1.1 Byte stream NAL unit syntax,
    // H.264-AVC-ISO_IEC_14496-10.pdf, page 211.
    while (!stream->empty()) {
        // find start code
        int nb_start_code = 0;
        if (!srs_avc_startswith_annexb(stream, &nb_start_code)) {
            return ret;
        }

        // skip the start code.
        if (nb_start_code > 0) {
            stream->skip(nb_start_code);
        }
        
        // the NALU start bytes.
        char* p = stream->data() + stream->pos();
        
        // get the last matched NALU
        while (!stream->empty()) {
            if (srs_avc_startswith_annexb(stream, NULL)) {
                break;
            }
            
            stream->skip(1);
        }
        
        char* pp = stream->data() + stream->pos();
        
        // skip the empty.
        if (pp - p <= 0) {
            continue;
        }
        
        // got the NALU.
        if ((ret = sample->add_sample_unit(p, pp - p)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(), "annexb add video sample failed. ret=%d", ret);
            return ret;
        }
    }
    
    return ret;
}

int SrsAvcAacCodec::avc_demux_ibmf_format(SrsStream* stream, SrsCodecSample* sample)
{
    int ret = ERROR_SUCCESS;
    
    int PictureLength = stream->size() - stream->pos();
    
    // 5.3.4.2.1 Syntax, H.264-AVC-ISO_IEC_14496-15.pdf, page 16
    // 5.2.4.1 AVC decoder configuration record
    // 5.2.4.1.2 Semantics
    // The value of this field shall be one of 0, 1, or 3 corresponding to a
    // length encoded with 1, 2, or 4 bytes, respectively.
    srs_assert(NAL_unit_length != 2);
    
    // 5.3.4.2.1 Syntax, H.264-AVC-ISO_IEC_14496-15.pdf, page 20
    for (int i = 0; i < PictureLength;) {
        // unsigned int((NAL_unit_length+1)*8) NALUnitLength;
        if (!stream->require(NAL_unit_length + 1)) {
            ret = ERROR_HLS_DECODE_ERROR;
            tag_error(get_device_sn(), "avc decode NALU size failed. ret=%d", ret);
            dump_memory("demux ibmf format failed:", stream->data(), 32);
            return ret;
        }
        int32_t NALUnitLength = 0;
        if (NAL_unit_length == 3) {
            NALUnitLength = stream->read_4bytes();
        } else if (NAL_unit_length == 1) {
            NALUnitLength = stream->read_2bytes();
        } else {
            NALUnitLength = stream->read_1bytes();
        }
        
        // maybe stream is invalid format.
        // see: https://github.com/ossrs/srs/issues/183
        if (NALUnitLength < 0) {
            ret = ERROR_HLS_DECODE_ERROR;
            tag_error(get_device_sn(), "maybe stream is AnnexB format. ret=%d, NAL_unit_length:%d, NALUnitLength:%d, size:%d\n", ret, NAL_unit_length, NALUnitLength, stream->size());
            dump_memory("demux ibmf format failed:", stream->data(), 32);
            return ret;
        }
        //srs_trace("NALUnitLength:%d, NAL_unit_length:%d, remain:%d", NALUnitLength, NAL_unit_length, stream->size() - stream->pos());
        // NALUnit
        if (!stream->require(NALUnitLength)) {
            ret = ERROR_HLS_DECODE_ERROR;
            tag_error(get_device_sn(), "avc decode NALU data failed. ret=%d, NAL_unit_length:%d, NALUnitLength:%d, pos:%d, size:%d\n", ret, NAL_unit_length, NALUnitLength,  stream->pos(), stream->size());
            //srs_trace_memory(stream->data(), 32);
            dump_memory("demux ibmf format failed:", stream->data(), 32);
            return ret;
        }
        // 7.3.1 NAL unit syntax, H.264-AVC-ISO_IEC_14496-10.pdf, page 44.
        if ((ret = sample->add_sample_unit(stream->data() + stream->pos(), NALUnitLength)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(), "avc add video sample failed. ret=%d, NAL_unit_length:%d, NALUnitLength:%d", ret, NAL_unit_length, NALUnitLength);
            dump_memory("demux ibmf format failed:", stream->data(), 32);
            return ret;
        }
        stream->skip(NALUnitLength);
        
        i += NAL_unit_length + 1 + NALUnitLength;
    }
    
    return ret;
}

int SrsAvcAacCodec::nal_type(const char* pframe)
{
    int nal_type = 0;
    if(SrsCodecVideoAVC == video_codec_id)
    {
        nal_type = pframe[0] & 0x1f;
        //return 5 == nal_type;
    }
    else if(SrsCodecVideoHEVC == video_codec_id)
    {
        nal_type = (pframe[0]&0x7e) >> 1;;
        //return nal_type >= 16 && nal_type <= 21;
    }
    return nal_type;
}

#endif

