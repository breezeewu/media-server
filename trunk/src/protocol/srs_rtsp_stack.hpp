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

#ifndef SRS_PROTOCOL_RTSP_STACK_HPP
#define SRS_PROTOCOL_RTSP_STACK_HPP

/*
#include <srs_rtsp_stack.hpp>
*/
//#define ENABLE_SEND_DATA_FROM_FILE
#include <srs_core.hpp>

#if !defined(SRS_EXPORT_LIBRTMP)

#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <srs_kernel_consts.hpp>
#include <srs_kernel_stream.hpp>
#include <lbsp_media_bitstream.hpp>
#include <lbsp_media_rtcp.hpp>
//#include <lbsp_media_rtp.hpp>
//#include <lbsp_media_sdp.hpp>
#define MAX_RTP_PACKET_SIZE     1442
#define SRS_MAX_MTU_SIZE             1500
//#define WRITE_RTSP_RTP_DATA
#define FIX_RTP_HEADER_SIZE        12

#define SRS_RTSP_AVC_PAYLOAD_TYPE       96
#define SRS_RTSP_AAC_PAYLOAD_TYPE       97
#define SRS_RTSP_HEVC_PAYLOAD_TYPE      98

#ifdef SRS_AUTO_STREAM_CASTER
#define SRS_RTSP_PTS_TIME_BASE      90000
#define SRS_RTMP_PTS_TIME_BASE      1000
#define SRS_RTSP_RTP_PACKET_TYPE_STAP_A         24
#define SRS_RTSP_RTP_PACKET_TYPE_STAP_B         25
#define SRS_RTSP_RTP_PACKET_TYPE_MATP           26
#define SRS_RTSP_RTP_PACKET_TYPE_FU_A           28
#define SRS_RTSP_RTP_PACKET_TYPE_FU_B           29
#define SRS_RTSP_RTP_PACKET_TYPE_HEVC           0x31
class SrsStream;
class SrsSimpleBuffer;
class SrsCodecSample;
class ISrsProtocolReaderWriter;
using namespace lbsp_util;
// rtsp specification
// CR             = <US-ASCII CR, carriage return (13)>
#define SRS_RTSP_CR SRS_CONSTS_CR // 0x0D
// LF             = <US-ASCII LF, linefeed (10)>
#define SRS_RTSP_LF SRS_CONSTS_LF // 0x0A
// SP             = <US-ASCII SP, space (32)>
#define SRS_RTSP_SP ' ' // 0x20
#define SRS_RTSP_COMMA ';'

// 4 RTSP Message, @see rtsp-rfc2326-1998.pdf, page 37
// Lines are terminated by CRLF, but
// receivers should be prepared to also interpret CR and LF by
// themselves as line terminators.
#define SRS_RTSP_CRLF "\r\n" // 0x0D0A
#define SRS_RTSP_CRLFCRLF "\r\n\r\n" // 0x0D0A0D0A

// RTSP token
#define SRS_RTSP_TOKEN_CSEQ                 "CSeq"
#define SRS_RTSP_TOKEN_PUBLIC               "Public"
#define SRS_RTSP_TOKEN_CONTENT_TYPE         "Content-Type"
#define SRS_RTSP_TOKEN_CONTENT_LENGTH       "Content-Length"
#define SRS_RTSP_TOKEN_TRANSPORT            "Transport"
#define SRS_RTSP_TOKEN_SESSION              "Session"
#define SRS_RTSP_TOKEN_AUTHORIZATION        "Authorization"
#define SRS_RTSP_TOKEN_USER_AGENT           "User-Agent"
#define SRS_RTSP_TOKEN_ACCEPT               "Accept"
#define SRS_RTSP_TOKEN_RANGE                "Range"
#define SRS_RTSP_TOKEN_DATE                 "Date"
#define SRS_RTSP_TOKEN_RTP_INFO             "RTP-Info"

// RTSP authorization attribute
#define SRS_RTSP_AUTH_USER_NAME             "username"
#define SRS_RTSP_AUTH_REALM                 "realm"
#define SRS_RTSP_AUTH_NONCE                 "nonce"
#define SRS_RTSP_AUTH_URI                   "uri"
#define SRS_RTSP_AUTH_RESPONSE              "response"

// RTSP methods
#define SRS_METHOD_OPTIONS            "OPTIONS"
#define SRS_METHOD_DESCRIBE           "DESCRIBE"
#define SRS_METHOD_ANNOUNCE           "ANNOUNCE"
#define SRS_METHOD_SETUP              "SETUP"
#define SRS_METHOD_PLAY               "PLAY"
#define SRS_METHOD_PAUSE              "PAUSE"
#define SRS_METHOD_TEARDOWN           "TEARDOWN"
#define SRS_METHOD_GET_PARAMETER      "GET_PARAMETER"
#define SRS_METHOD_SET_PARAMETER      "SET_PARAMETER"
#define SRS_METHOD_REDIRECT           "REDIRECT"
#define SRS_METHOD_RECORD             "RECORD"
#define SRS_TOKEN_RTCP                "RTCP"
// Embedded (Interleaved) Binary Data

// RTSP-Version
#define SRS_RTSP_VERSION "RTSP/1.0"

#define SRS_RTSP_SERVER_NAME        "SRS Streaming Media "//"SRS Steaming Media v"
#define SRS_RTSP_SERVER_VERSION_STRING  "v2020.04.24"
// micro for rtcp 
// SDES tags
#define SRS_RTCP_SDES_END       0
#define SRS_RTCP_SDES_CNAME     1
#define SRS_RTCP_SDES_NAME      2
#define SRS_RTCP_SDES_EMAIL     3
#define SRS_RTCP_SDES_PHONE     4
#define SRS_RTCP_SDES_LOC       5
#define SRS_RTCP_SDES_TOOL      6
#define SRS_RTCP_SDES_NOTE      7
#define SRS_RTCP_SDES_PRIV      8
enum SrsRtspStreamingType
{
    SrsRtspStreamingTypeUnknown = -1,
    SrsRtspStreamingTypeUDP,
    SrsRtspStreamingTypeTCP,
};
/**
* the rtsp sdp parse state.
*/
enum SrsRtspSdpState
{
    /**
    * other sdp properties.
    */
    SrsRtspSdpStateOthers,
    /**
    * parse sdp audio state.
    */
    SrsRtspSdpStateAudio,
    /**
    * parse sdp video state.
    */
    SrsRtspSdpStateVideo,
};
/**
* 10 Method Definitions, @see rtsp-rfc2326-1998.pdf, page 57
* The method token indicates the method to be performed on the resource
* identified by the Request-URI. The method is case-sensitive. New
* methods may be defined in the future. Method names may not start with
* a $ character (decimal 24) and must be a token. Methods are
* summarized in Table 2.
* Notes on Table 2: PAUSE is recommended, but not required in that a
* fully functional server can be built that does not support this
* method, for example, for live feeds. If a server does not support a
* particular method, it MUST return "501 Not Implemented" and a client
* SHOULD not try this method again for this server.
*/
enum SrsRtspMethod
{
    SrsRtspMethodDescribe           = 0x0001,
    SrsRtspMethodAnnounce           = 0x0002,
    SrsRtspMethodGetParameter       = 0x0004,
    SrsRtspMethodOptions            = 0x0008,
    SrsRtspMethodPause              = 0x0010,
    SrsRtspMethodPlay               = 0x0020,
    SrsRtspMethodRecord             = 0x0040,
    SrsRtspMethodRedirect           = 0x0080,
    SrsRtspMethodSetup              = 0x0100,
    SrsRtspMethodSetParameter       = 0x0200,
    SrsRtspMethodTeardown           = 0x0400,
};

/**
* the state of rtsp token.
*/
enum SrsRtspTokenState
{
    /**
    * parse token failed, default state.
    */
    SrsRtspTokenStateError = 100,
    /**
    * when SP follow the token.
    */
    SrsRtspTokenStateNormal = 101,
    /**
    * when CRLF follow the token.
    */
    SrsRtspTokenStateEOF = 102,
};
#define RTCP_PACKET_HEADER_SIZE  8
#define SRS_RTCP_PAYLOAD_TYPE_SR        200
#define SRS_RTCP_PAYLOAD_TYPE_RR        201
#define SRS_RTCP_PAYLOAD_TYPE_SDES      202
#define SRS_RTCP_PAYLOAD_TYPE_BYE       203

class SrsRtcpPacket
{
public:
    SrsRtcpPacket();
    ~SrsRtcpPacket();

    uint8_t version; // 2 bits
    uint8_t padding; // 1 bit
    uint8_t recv_count; // 5 bits
    uint8_t payload_type; // 8 bits
    uint16_t length; // 16 bits
    uint32_t ussrc;

    std::vector<uint32_t> csrc_list;

    // the payload.
    SrsSimpleBuffer* payload;

    CBitStream* m_pstream;

    virtual int write(char* pdata, int len);

    int encode(char* pdata, int len);

    virtual int set_ssrc(uint32_t ssrc);

    virtual int add_csrc(uint32_t csrc);

    virtual int remove_csrc(uint32_t csrc);

protected:
    virtual int get_sc_rc_count();
    virtual int get_length();
};
#define MAX_SDES_ITEM_DATA_SIZE 257
class SrsRtcpSDESItem
{
protected:
    uint8_t item_tag;
    uint8_t data_buf[MAX_SDES_ITEM_DATA_SIZE];
public:
    SrsRtcpSDESItem(unsigned char tag, char const* pval);
    ~SrsRtcpSDESItem();

    int write(SrsStream* stream);

    char const* data();

    int size();

protected:
    int init(unsigned char tag, char const* pval);
};

class SrsSDESPacket:public SrsRtcpPacket
{
protected:
    std::vector<SrsRtcpSDESItem*>    sdes_item_list;

public:
    SrsSDESPacket();
    ~SrsSDESPacket();

    virtual int encode(char* pdata, int len);

protected:
    int add_sdes_item(uint8_t tag, SrsRtcpSDESItem* pitem);
    virtual int get_sc_rc_count();
    virtual int get_length();
};

class SrsRtcpSenderReport
{
protected:
    int num_of_report_source;
    uint32_t    ntp_mts;
    uint32_t    ntp_lts;
    uint32_t    rtp_ts;
    uint32_t    senders_packet_num;
    uint32_t    senders_octet_num;

public:
    SrsRtcpSenderReport();
    ~SrsRtcpSenderReport();

    virtual int encode(char* pdata, int len);
protected:
    virtual int get_sc_rc_count();
    virtual int get_length();
};

/**
* the rtp packet.
* 5. RTP Data Transfer Protocol, @see rtp-rfc3550-2003.pdf, page 12
*/
class SrsRtpPacket
{
public:
    /**
    * version (V): 2 bits
    * This eld identies the version of RTP. The version dened by this specication is two (2).
    * (The value 1 is used by the rst draft version of RTP and the value 0 is used by the protocol
    * initially implemented in the \vat" audio tool.)
    */
    int8_t version; //2bits
    /**
    * padding (P): 1 bit
    * If the padding bit is set, the packet contains one or more additional padding octets at the
    * end which are not part of the payload. The last octet of the padding contains a count of
    * how many padding octets should be ignored, including itself. Padding may be needed by
    * some encryption algorithms with xed block sizes or for carrying several RTP packets in a
    * lower-layer protocol data unit.
    */
    int8_t padding; //1bit
    /**
    * extension (X): 1 bit
    * If the extension bit is set, the xed header must be followed by exactly one header extension,
    * with a format dened in Section 5.3.1.
    */
    int8_t extension; //1bit
    /**
    * CSRC count (CC): 4 bits
    * The CSRC count contains the number of CSRC identiers that follow the xed header.
    */
    int8_t csrc_count; //4bits
    /**
    * marker (M): 1 bit
    * The interpretation of the marker is dened by a prole. It is intended to allow signicant
    * events such as frame boundaries to be marked in the packet stream. A prole may dene
    * additional marker bits or specify that there is no marker bit by changing the number of bits
    * in the payload type eld (see Section 5.3).
    */
    int8_t marker; //1bit
    /**
    * payload type (PT): 7 bits
    * This eld identies the format of the RTP payload and determines its interpretation by the
    * application. A prole may specify a default static mapping of payload type codes to payload
    * formats. Additional payload type codes may be dened dynamically through non-RTP means
    * (see Section 3). A set of default mappings for audio and video is specied in the companion
    * RFC 3551 [1]. An RTP source may change the payload type during a session, but this eld
    * should not be used for multiplexing separate media streams (see Section 5.2).
    * A receiver must ignore packets with payload types that it does not understand.
    */
    int8_t payload_type; //7bits
    /**
    * sequence number: 16 bits
    * The sequence number increments by one for each RTP data packet sent, and may be used
    * by the receiver to detect packet loss and to restore packet sequence. The initial value of the
    * sequence number should be random (unpredictable) to make known-plaintext attacks on
    * encryption more dicult, even if the source itself does not encrypt according to the method
    * in Section 9.1, because the packets may flow through a translator that does. Techniques for
    * choosing unpredictable numbers are discussed in [17].
    */
    u_int32_t sequence_number; //16bits
    /**
    * timestamp: 32 bits
    * The timestamp reflects the sampling instant of the rst octet in the RTP data packet. The
    * sampling instant must be derived from a clock that increments monotonically and linearly
    * in time to allow synchronization and jitter calculations (see Section 6.4.1). The resolution
    * of the clock must be sucient for the desired synchronization accuracy and for measuring
    * packet arrival jitter (one tick per video frame is typically not sucient). The clock frequency
    * is dependent on the format of data carried as payload and is specied statically in the prole
    * or payload format specication that denes the format, or may be specied dynamically for
    * payload formats dened through non-RTP means. If RTP packets are generated periodically,
    * the nominal sampling instant as determined from the sampling clock is to be used, not a
    * reading of the system clock. As an example, for xed-rate audio the timestamp clock would
    * likely increment by one for each sampling period. If an audio application reads blocks covering
    * 160 sampling periods from the input device, the timestamp would be increased by 160 for
    * each such block, regardless of whether the block is transmitted in a packet or dropped as
    * silent.
    *
    * The initial value of the timestamp should be random, as for the sequence number. Several
    * consecutive RTP packets will have equal timestamps if they are (logically) generated at once,
    * e.g., belong to the same video frame. Consecutive RTP packets may contain timestamps that
    * are not monotonic if the data is not transmitted in the order it was sampled, as in the case
    * of MPEG interpolated video frames. (The sequence numbers of the packets as transmitted
    * will still be monotonic.)
    * 
    * RTP timestamps from dierent media streams may advance at dierent rates and usually
    * have independent, random osets. Therefore, although these timestamps are sucient to
    * reconstruct the timing of a single stream, directly comparing RTP timestamps from dierent
    * media is not eective for synchronization. Instead, for each medium the RTP timestamp
    * is related to the sampling instant by pairing it with a timestamp from a reference clock
    * (wallclock) that represents the time when the data corresponding to the RTP timestamp was
    * sampled. The reference clock is shared by all media to be synchronized. The timestamp
    * pairs are not transmitted in every data packet, but at a lower rate in RTCP SR packets as
    * described in Section 6.4.
    * 
    * The sampling instant is chosen as the point of reference for the RTP timestamp because it is
    * known to the transmitting endpoint and has a common denition for all media, independent
    * of encoding delays or other processing. The purpose is to allow synchronized presentation of
    * all media sampled at the same time.
    * 
    * Applications transmitting stored data rather than data sampled in real time typically use a
    * virtual presentation timeline derived from wallclock time to determine when the next frame
    * or other unit of each medium in the stored data should be presented. In this case, the RTP
    * timestamp would reflect the presentation time for each unit. That is, the RTP timestamp for
    * each unit would be related to the wallclock time at which the unit becomes current on the
    * virtual presentation timeline. Actual presentation occurs some time later as determined by
    * the receiver.
    * 
    * An example describing live audio narration of prerecorded video illustrates the signicance
    * of choosing the sampling instant as the reference point. In this scenario, the video would
    * be presented locally for the narrator to view and would be simultaneously transmitted using
    * RTP. The \sampling instant" of a video frame transmitted in RTP would be established by
    * referencing its timestamp to the wallclock time when that video frame was presented to the
    * narrator. The sampling instant for the audio RTP packets containing the narrator's speech
    * would be established by referencing the same wallclock time when the audio was sampled.
    * The audio and video may even be transmitted by dierent hosts if the reference clocks on
    * the two hosts are synchronized by some means such as NTP. A receiver can then synchronize
    * presentation of the audio and video packets by relating their RTP timestamps using the
    * timestamp pairs in RTCP SR packets.
    */
    u_int32_t timestamp; //32bits
    /**
    * SSRC: 32 bits
    * The SSRC eld identies the synchronization source. This identier should be chosen
    * randomly, with the intent that no two synchronization sources within the same RTP session
    * will have the same SSRC identier. An example algorithm for generating a random identier
    * is presented in Appendix A.6. Although the probability of multiple sources choosing the same
    * identier is low, all RTP implementations must be prepared to detect and resolve collisions.
    * Section 8 describes the probability of collision along with a mechanism for resolving collisions
    * and detecting RTP-level forwarding loops based on the uniqueness of the SSRC identier. If
    * a source changes its source transport address, it must also choose a new SSRC identier to
    * avoid being interpreted as a looped source (see Section 8.2).
    */
    u_int32_t ssrc; //32bits

    uint32_t    time_scale;
    int32_t     npts_offset;
    uint32_t total_sequence_number;
    uint32_t total_payload_bytes;
    // the payload.
    std::vector<SrsSimpleBuffer*>   vrtp_packet_list;
    
    SrsSimpleBuffer* get_payload();
    SrsSimpleBuffer* next_payload();
    // whether transport in chunked payload.
    bool chunked;
    // whether message is completed.
    // normal message always completed.
    // while chunked completed when the last chunk arriaved.
    bool completed;

    uint8_t*        m_prtp_packet;
    int             m_nmax_rtp_packet_size;
    /**
    * the audio samples, one rtp packets may contains multiple audio samples.
    */
    SrsCodecSample* audio_samples;

    lazy_bitstream*     m_pbitstream;
#ifdef WRITE_RTSP_RTP_DATA
    FILE*               m_pfile;
#endif
    SrsRtspStreamingType    m_estreaming_type;
    int                 m_nchannel_id;
public:
    SrsRtpPacket();
    virtual ~SrsRtpPacket();
public:
    /**
    * copy the header from src.
    */
    virtual void copy(SrsRtpPacket* src);
    /**
    * reap the src to this packet, reap the payload.
    */
    virtual void reap(SrsRtpPacket* src);
    /**
    * decode rtp packet from stream.
    */
    virtual int decode(lazy_bitstream* stream);
    /**
    * encode rtp packet from data.
    */
    virtual int encode(uint32_t ssrc, int payloadtype, int channel_id, char* pdata, int len, uint32_t& sequence_num, int64_t pts);

    virtual int encode(uint32_t ssrc, int payloadtype, char* pdata, int len, uint32_t& sequence_num, int64_t pts);
private:
    virtual int decode_97(lazy_bitstream* stream);
    virtual int decode_96(lazy_bitstream* stream);
#if 1
    virtual int encode_97(uint8_t* pdata, int len, uint8_t* pout, int* poutlen);
    virtual int encode_96(uint8_t* pdata, int len, int start, int end, int nri, int nalu_type, uint8_t* pout, int* poutlen);

    virtual int encode_packet(int pt, uint32_t ssrc, uint32_t& sequence_num, int64_t pts, uint8_t* pdata, int len);
#else
    virtual int encode_97(uint8_t* pdata, int len, uint8_t* pout = NULL, int* poutlen = NULL);
    virtual int encode_96(uint8_t* pdata, int len, int start, int end, int nri, int nalu_type, uint8_t* pout = NULL, int* poutlen = NULL);
    #endif

    virtual void clear();

    //virtual int rtp_packet(char* pdata, int len, uint16_t& sequence_num, int64_t pts);

    virtual void load_default_param();
};

class SrsRtspSdpMediaDesc
{
public:
    int     npayload_type;
    int     nrtsp_time_base;
    int     nport;
    int     nsample_rate;
    int     nchannel;
    int     nbit_rate;//kbps
    int     ntrack_num;
    int     npacketization_mode;
    int     nbitrate;

    std::string     media_type;
    std::string     local_ip;
    std::string     track_id;
    std::string     media_desc;

    std::string trans_proto;
    char*    SrsRtspSdp;
    
public:
    SrsRtspSdpMediaDesc();
    ~SrsRtspSdpMediaDesc();

    int init_media_desc(std::string mt, int pt, int port, std::string ip, int bitrate, std::string track_name);

    std::string gen_h264_media_desc(uint8_t* sps, int sps_len, uint8_t* pps, int pps_len);

    std::string gen_h265_media_desc(uint8_t* vps, int vps_len, uint8_t* sps, int sps_len, uint8_t* pps, int pps_len);

    std::string gen_mpeg4_generic_media_desc(uint8_t* pcfg, int len);


};
/**
* the sdp in announce, @see rtsp-rfc2326-1998.pdf, page 159
* Appendix C: Use of SDP for RTSP Session Descriptions
* The Session Description Protocol (SDP, RFC 2327 [6]) may be used to
* describe streams or presentations in RTSP.
*/
class SrsRtspSdp
{
private:
    SrsRtspSdpState state;
public:
    /**
    * the version of sdp.
    */
    std::string version;
    /**
    * the owner/creator of sdp.
    */
    std::string owner_username;
    std::string owner_session_id;
    std::string owner_session_version;
    std::string owner_network_type;
    std::string owner_address_type;
    std::string owner_address;
    /**
    * the session name of sdp.
    */
    std::string session_name;
    /**
    * the media title.
    */
    std::string media_title;
    /**
    * the connection info of sdp.
    */
    std::string connection_network_type;
    std::string connection_address_type;
    std::string connection_address;
    /**
    * the tool attribute of sdp.
    */
    std::string tool;
    /**
    * the video attribute of sdp.
    */
    std::string video_port;
    std::string video_protocol;
    std::string video_transport_format;
    std::string video_bandwidth_kbps;
    std::string video_codec;
    std::string video_sample_rate;
    std::string video_stream_id;
    // fmtp
    std::string video_packetization_mode;
    std::string video_sps; // sequence header: sps.
    std::string video_pps; // sequence header: pps.
    /**
    * the audio attribute of sdp.
    */
    std::string audio_port;
    std::string audio_protocol;
    std::string audio_transport_format;
    std::string audio_bandwidth_kbps;
    std::string audio_codec;
    std::string audio_sample_rate;
    std::string audio_channel;
    std::string audio_stream_id;
    // fmtp
    std::string audio_profile_level_id;
    std::string audio_mode;
    std::string audio_size_length;
    std::string audio_index_length;
    std::string audio_index_delta_length;
    std::string audio_sh; // sequence header.

    std::string m_sdp_desc;

    std::string m_sdp_media_video;
    std::string m_sdp_media_audio;

    std::vector<SrsRtspSdpMediaDesc*>   m_vsdp_media_list;
public:
    SrsRtspSdp();
    virtual ~SrsRtspSdp();
public:
    /**
    * parse a line of token for sdp.
    */
    virtual int parse(std::string token);

    virtual int init_sdp(std::string address, std::string sessionname, std::string mediatitle);

    virtual int encode(std::stringstream* ss);

    virtual int length();

    virtual int add_media_video(std::string mt, int port, int pt,  std::string track_name, uint8_t* vps, int vps_len, uint8_t* psp, int sps_len, uint8_t* pps, int pps_len);

    virtual int add_media_audio(std::string mt, int port, int pt, std::string track_name, uint8_t* pcfg, int cfg_len);
private:
    /**
    * generally, the fmtp is the sequence header for video or audio.
    */
    virtual int parse_fmtp_attribute(std::string attr);
    /**
    * generally, the control is the stream info for video or audio.
    */
    virtual int parse_control_attribute(std::string attr);
    /**
    * decode the string by base64.
    */
    virtual std::string base64_decode(std::string value);
};

/**
* the rtsp transport.
* 12.39 Transport, @see rtsp-rfc2326-1998.pdf, page 115
* This request header indicates which transport protocol is to be used
* and configures its parameters such as destination address,
* compression, multicast time-to-live and destination port for a single
* stream. It sets those values not already determined by a presentation
* description.
*/
class SrsRtspTransport
{
public:
    // The syntax for the transport specifier is
    //      transport/profile/lower-transport
    std::string transport;
    std::string profile;
    std::string lower_transport;
    // unicast | multicast
    // mutually exclusive indication of whether unicast or multicast
    // delivery will be attempted. Default value is multicast.
    // Clients that are capable of handling both unicast and
    // multicast transmission MUST indicate such capability by
    // including two full transport-specs with separate parameters
    // for each.
    std::string cast_type;
    // The mode parameter indicates the methods to be supported for
    // this session. Valid values are PLAY and RECORD. If not
    // provided, the default is PLAY.
    std::string mode;
    // This parameter provides the unicast RTP/RTCP port pair on
    // which the client has chosen to receive media data and control
    // information. It is specified as a range, e.g.,
    //      client_port=3456-3457.
    // where client will use port in:
    //      [client_port_min, client_port_max)
    int client_port_min;
    int client_port_max;

    uint32_t rtp_channel_id;
    uint32_t rtcp_channel_id;
public:
    SrsRtspTransport();

    virtual ~SrsRtspTransport();
public:
    /**
    * parse a line of token for transport.
    */
    virtual int parse(std::string attr);
};

class SrsRtspAuthorization
{
public:
    /*std::string     m_suser_name;
    std::string     m_srealm;
    std::string     m_snonce;
    std::string     m_suri;
    std::string     m_sresponse;*/

    std::map<std::string, std::string>  m_mkey_val_list;

public:
    int parser(std::string attr);

    std::string get_attribute(std::string attr_name);
    std::string gen_response_by_pwd(const std::string& cmd, const std::string& url, const std::string& username, const std::string& pwd);
protected:

    int read_key_value_pair(std::string attr);
};

/**
* the rtsp request message.
* 6 Request, @see rtsp-rfc2326-1998.pdf, page 39
* A request message from a client to a server or vice versa includes,
* within the first line of that message, the method to be applied to
* the resource, the identifier of the resource, and the protocol
* version in use.
* Request = Request-Line ; Section 6.1
*           *( general-header ; Section 5
*           | request-header ; Section 6.2
*           | entity-header ) ; Section 8.1
*           CRLF
*           [ message-body ] ; Section 4.3
*/
class SrsRtspRequest
{
public:
    /**
    * 6.1 Request Line
    * Request-Line = Method SP Request-URI SP RTSP-Version CRLF
    */
    std::string method;
    std::string uri;
    std::string version;
    /**
    * 12.17 CSeq
    * The CSeq field specifies the sequence number for an RTSP requestresponse
    * pair. This field MUST be present in all requests and
    * responses. For every RTSP request containing the given sequence
    * number, there will be a corresponding response having the same
    * number. Any retransmitted request must contain the same sequence
    * number as the original (i.e. the sequence number is not incremented
    * for retransmissions of the same request).
    */
    long seq;
    /**
    * 12.16 Content-Type, @see rtsp-rfc2326-1998.pdf, page 99
    * See [H14.18]. Note that the content types suitable for RTSP are
    * likely to be restricted in practice to presentation descriptions and
    * parameter-value types.
    */
    std::string content_type;

    /**
     * rtsp play range
     **/
    double      start_range;
    double      stop_range;

    //std::string range;

    /**
    * 12.14 Content-Length, @see rtsp-rfc2326-1998.pdf, page 99
    * This field contains the length of the content of the method (i.e.
    * after the double CRLF following the last header). Unlike HTTP, it
    * MUST be included in all messages that carry content beyond the header
    * portion of the message. If it is missing, a default value of zero is
    * assumed. It is interpreted according to [H14.14].
    */
    /**
    * datetime message send date and time
    **/
    std::string  date;

    long content_length;
    /**
    * the session id.
    */
    std::string session;

    /**
    * the sdp in announce, NULL for no sdp.
    */
    SrsRtspSdp* sdp;
    /**
    * the transport in setup, NULL for no transport.
    */
    SrsRtspTransport* transport;
    /**
    * the authorize in describe, NULL for no authorize.
    */
    SrsRtspAuthorization* pauthorize;

    /**
    * for setup message, parse the stream id from uri.
    */

   
    int stream_id;
public:
    SrsRtspRequest();
    virtual ~SrsRtspRequest();
public:
    virtual bool is_options();
    virtual bool is_announce();
    virtual bool is_setup();
    virtual bool is_record();

    virtual bool is_describe();
    virtual bool is_play();

    virtual bool is_shutdown();

    virtual bool is_rtcp();
};

class RTP_INFO
{
public:
    int         pt;
    std::string track_name;
    std::string url;
    uint16_t    seq_number;
    uint32_t    rtp_timestamp;
    uint32_t    rtcp_timestamp;
    uint16_t    rtp_channel_id;
    uint16_t    rtcp_channel_id;
    uint32_t    time_scale;
    uint32_t    ussrc;
    uint32_t    urtcp_ssrc;

    RTP_INFO()
    {
        pt = -1;
        seq_number = -1;
        rtp_timestamp = -1;
        rtp_channel_id = -1;
        rtcp_channel_id = -1;
        time_scale = -1;
        ussrc = 0;
        urtcp_ssrc = 0;
    }
};
/**
* the rtsp response message.
* 7 Response, @see rtsp-rfc2326-1998.pdf, page 43
* [H6] applies except that HTTP-Version is replaced by RTSP-Version.
* Also, RTSP defines additional status codes and does not define some
* HTTP codes. The valid response codes and the methods they can be used
* with are defined in Table 1.
* After receiving and interpreting a request message, the recipient
* responds with an RTSP response message.
*       Response = Status-Line ; Section 7.1
*                   *( general-header ; Section 5
*                   | response-header ; Section 7.1.2
*                   | entity-header ) ; Section 8.1
*                   CRLF
*                   [ message-body ] ; Section 4.3
*/
class SrsRtspResponse
{
public:
    /**
    * 7.1 Status-Line
    * The first line of a Response message is the Status-Line, consisting
    * of the protocol version followed by a numeric status code, and the
    * textual phrase associated with the status code, with each element
    * separated by SP characters. No CR or LF is allowed except in the
    * final CRLF sequence.
    *       Status-Line = RTSP-Version SP Status-Code SP Reason-Phrase CRLF
    */
    // @see about the version of rtsp, see SRS_RTSP_VERSION
    // @see about the status of rtsp, see SRS_CONSTS_RTSP_OK
    int status;
    /**
    * 12.17 CSeq, @see rtsp-rfc2326-1998.pdf, page 99
    * The CSeq field specifies the sequence number for an RTSP requestresponse
    * pair. This field MUST be present in all requests and
    * responses. For every RTSP request containing the given sequence
    * number, there will be a corresponding response having the same
    * number. Any retransmitted request must contain the same sequence
    * number as the original (i.e. the sequence number is not incremented
    * for retransmissions of the same request).
    */
    long seq;
    /**
    * the session id.
    */
    std::string session;
    uint32_t   session_timeout;

    std::string ext_hdr;

    /**
    * start range and stop range.
    */
   double start_range;
   double stop_range;

    std::string date;
    //std::string range;
    //std::string rtp_info;
	std::vector<RTP_INFO>   vrtp_info_list;
	SrsRtspSdp* sdp;
public:
    SrsRtspResponse(int cseq);
    virtual ~SrsRtspResponse();
public:
    /**
    * encode message to string.
    */
    virtual int encode(std::stringstream& ss);
protected:
    /**
    * sub classes override this to encode the headers.
    */
    virtual int encode_header(std::stringstream& ss);
};

/**
* 10.1 OPTIONS, @see rtsp-rfc2326-1998.pdf, page 59
* The behavior is equivalent to that described in [H9.2]. An OPTIONS
* request may be issued at any time, e.g., if the client is about to
* try a nonstandard request. It does not influence server state.
*/
class SrsRtspOptionsResponse : public SrsRtspResponse
{
public:
    /**
    * join of SrsRtspMethod
    */
    SrsRtspMethod methods;
public:
    SrsRtspOptionsResponse(int cseq);
    virtual ~SrsRtspOptionsResponse();
protected:
    virtual int encode_header(std::stringstream& ss);
};

/**
* 10.4 SETUP, @see rtsp-rfc2326-1998.pdf, page 65
* The SETUP request for a URI specifies the transport mechanism to be
* used for the streamed media. A client can issue a SETUP request for a
* stream that is already playing to change transport parameters, which
* a server MAY allow. If it does not allow this, it MUST respond with
* error "455 Method Not Valid In This State". For the benefit of any
* intervening firewalls, a client must indicate the transport
* parameters even if it has no influence over these parameters, for
* example, where the server advertises a fixed multicast address.
*/
class SrsRtspSetupResponse : public SrsRtspResponse
{
public:
    // the client specified port.
    int client_port_min;
    int client_port_max;
    // client will use the port in:
    //      [local_port_min, local_port_max)
    int local_port_min;
    int local_port_max;
    std::string     session_info;

    std::string     lower_trasport;
    std::string     destination_ip;
    std::string     source_ip;
    int     rtp_channel_id;
    int     rtcp_channel_id;

    // session.
    //std::string session;
public:
    SrsRtspSetupResponse(int cseq);
    virtual ~SrsRtspSetupResponse();

    int set_transport_protocol(std::string protocol, std::string dst_ip, std::string src_ip, int rtp_id, int rtcp_id, uint32_t sess_timeout);
//    int set_transport_protocol(std::string protocol, std::string dst_ip, std::string source_ip, int rtp_channel_id, int rtcp_channel_id, uint32_t session_timeout);
protected:
    virtual int encode_header(std::stringstream& ss);
};

class SrsRtspDescribeResponse : public SrsRtspResponse
{
public:
    SrsRtspDescribeResponse(int seq);


    std::string     content_base;

    virtual int init_sdp(std::string address, std::string sessionname, std::string mediatitle);

    virtual int add_media_video(std::string mt, int port, int pt,  std::string track_name, uint8_t* vps, int vps_len, uint8_t* psp, int sps_len, uint8_t* pps, int pps_len);

    virtual int add_media_audio(std::string mt, int port, int pt, std::string track_name, uint8_t* pcfg, int cfg_len);
    
    virtual int encode(std::stringstream& ss);

    virtual int encode_header(std::stringstream& ss);


};

class rtsp_over_tcp_packet
{
public:
    int     nchannel_id;
    int     nlength;

public:
    rtsp_over_tcp_packet();
    ~rtsp_over_tcp_packet();


    int encode_header(int channel_id, int in_len, void* pout, int& out_len);

    int decode_header(const void* pin, int in_len);

    int encode(int channel_id, const void* pin, int in_len, void* pout, int& out_len);

    int decode(const void* pin, int in_len, void* pout, int& out_len);
};
/**
* the rtsp protocol stack to parse the rtsp packets.
*/
class SrsRtspStack
{
private:
    /**
    * cached bytes buffer.
    */
    SrsSimpleBuffer* buf;
    /**
    * underlayer socket object, send/recv bytes.
    */
    ISrsProtocolReaderWriter* skt;

    std::map<int, SrsRtpPacket*>    mpt_map_rtp_packet;
    std::map<int, RTP_INFO*>        mrtp_info_list;
    int64_t                         lpts_offset;
#ifdef WRITE_RTSP_RTP_DATA
    FILE*                           m_pfile;
    FILE*                           m_prtsp_file;
    FILE*                           m_pprotocol_file;
#endif
public:
    SrsRtspStack(ISrsProtocolReaderWriter* s);
    virtual ~SrsRtspStack();
public:
    /**
    * recv rtsp message from underlayer io.
    * @param preq the output rtsp request message, which user must free it.
    * @return an int error code. 
    *       ERROR_RTSP_REQUEST_HEADER_EOF indicates request header EOF.
    */
    virtual int recv_message(SrsRtspRequest** preq);
    /**
    * send rtsp message over underlayer io.
    * @param res the rtsp response message, which user should never free it.
    * @return an int error code.
    */
    virtual int send_message(SrsRtspResponse* res);

    virtual int send_packet(uint32_t ssrc, int pt, char* pdata, int len, int64_t pts);

    virtual int send_data(void* pdata, int len);

    virtual int get_fd();

    int add_rtp_info(int pt, RTP_INFO* prtp_info);

    virtual int build_and_send_report();

    virtual int send_report(rtcp_packet* prp);

    virtual int send_rtsp_over_tcp_packet(int channel_id, void* pdata, int len);

    virtual int read_rtcp_packet(rtcp_packet* pkt);

private:
    /**
    * recv the rtsp message.
    */
    virtual int do_recv_message(SrsRtspRequest* req);
    /**
    * read a normal token from io, error when token state is not normal.
    */
    virtual int recv_token_normal(std::string& token);
    /**
    * read a normal token from io, error when token state is not eof.
    */
    virtual int recv_token_eof(std::string& token);
    /**
    * read the token util got eof, for example, to read the response status Reason-Phrase
    * @param pconsumed, output the token parsed length. NULL to ignore.
    */
    virtual int recv_token_util_eof(std::string& token, int* pconsumed = NULL);
    /**
    * read a token from io, split by SP, endswith CRLF:
    *       token1 SP token2 SP ... tokenN CRLF
    * @param token, output the read token.
    * @param state, output the token parse state.
    * @param normal_ch, the char to indicates the normal token. 
    *       the SP use to indicates the normal token, @see SRS_RTSP_SP
    *       the 0x00 use to ignore normal token flag. @see recv_token_util_eof
    * @param pconsumed, output the token parsed length. NULL to ignore.
    */
    virtual int recv_token(std::string& token, SrsRtspTokenState& state, char normal_ch = SRS_RTSP_SP, int* pconsumed = NULL);
};

#endif

#endif

#endif

