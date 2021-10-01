#pragma once
#include <string>
#include <sstream>
#include <map>
#include "lbsp_utility_thread.hpp"
#include "../common/lbsp_media_bitstream.hxx"
#include "lbsp_media_rtp.hpp"
#include "lbsp_media_sdp.hpp"

#define CHECK_RESULT(ret) if(0 > ret) {lberror("%s:%d, %s check result failed, ret:%d\n", __FILE__, __LINE__, __FUNCTION__, ret); return ret;}
#define CHECK_VALUE(val, ret) if(!(val)) {lberror("%s:%d, %s check value failed, ret:%d\n", __FILE__, __LINE__, __FUNCTION__, ret); return ret;}
#define CHECK_PARAM_PTR(ptr, ret) if(NULL == ptr) { lberror("%s:%d, %s, Invalid ptr:%p\n", __FILE__, __LINE__, __FUNCTION__, ptr); return ret;}

// const string
#define LAZY_CONST_CR	'/r'
#define LAZY_CONST_LF	'/n'
#define LAZY_CONST_CRLF "/r/n"
#define LAZY_CONST_CRLFCRLF "/r/n/r/n"
#define LAZY_CONST_SP	' '
#define LAZY_CONST_COSP	": "
#define LAZY_CONST_comma ";"

// RTSP token
#define LAZY_RTSP_TOKEN_CSEQ                 "CSeq"
#define LAZY_RTSP_TOKEN_PUBLIC               "Public"
#define LAZY_RTSP_TOKEN_CONTENT_TYPE         "Content-Type"
#define LAZY_RTSP_TOKEN_CONTENT_LENGTH       "Content-Length"
#define LAZY_RTSP_TOKEN_CONTENT_BASE		 "Content-Base"
#define LAZY_RTSP_TOKEN_TRANSPORT            "Transport"
#define LAZY_RTSP_TOKEN_SESSION              "Session"
#define LAZY_RTSP_TOKEN_AUTHORIZATION        "Authorization"
#define LAZY_RTSP_TOKEN_USER_AGENT           "User-Agent"
#define LAZY_RTSP_TOKEN_ACCEPT               "Accept"
#define LAZY_RTSP_TOKEN_RANGE                "Range"
#define LAZY_RTSP_TOKEN_DATE                 "Date"
#define LAZY_RTSP_TOKEN_RTP_INFO             "RTP-Info"

// RTSP authorization attribute
#define LAZY_RTSP_AUTH_USER_NAME             "username"
#define LAZY_RTSP_AUTH_REALM                 "realm"
#define LAZY_RTSP_AUTH_NONCE                 "nonce"
#define LAZY_RTSP_AUTH_URI                   "uri"
#define LAZY_RTSP_AUTH_RESPONSE              "response"

// RTSP methods
#define LAZY_METHOD_OPTIONS            "OPTIONS"
#define LAZY_METHOD_DESCRIBE           "DESCRIBE"
#define LAZY_METHOD_ANNOUNCE           "ANNOUNCE"
#define LAZY_METHOD_SETUP              "SETUP"
#define LAZY_METHOD_PLAY               "PLAY"
#define LAZY_METHOD_PAUSE              "PAUSE"
#define LAZY_METHOD_TEARDOWN           "TEARDOWN"
#define LAZY_METHOD_GET_PARAMETER      "GET_PARAMETER"
#define LAZY_METHOD_SET_PARAMETER      "SET_PARAMETER"
#define LAZY_METHOD_REDIRECT           "REDIRECT"
#define LAZY_METHOD_RECORD             "RECORD"
#define LAZY_METHOD_RESPONSE		   "RESPONSE"
// Embedded (Interleaved) Binary Data

// codec name
#define LAZY_RTSP_H264_CODEC_NAME		"H264"
#define LAZY_RTSP_AAC_CODEC_NAME		"MPEG4-GENERIC"

// RTSP-Version
#define LAZY_RTSP_VERSION "RTSP/1.0"

#define LAZY_RTSP_SERVER_NAME        "SRS Steaming Media v"
#define LAZY_RTSP_SERVER_VERSION_STRING  "2020.04.02"
using namespace std;
enum ecommon_type
{
	e_common_type_unknown = -1,
	e_common_type_request = 0,
	e_common_type_response,
};

namespace lbsp_util
{
class lazybitstream;
class irtsp_token_codec
{
public:
	const string	m_stoken;

public:
	irtsp_token_codec(string token):m_stoken(token){}

	virtual ~irtsp_token_codec(){}

	virtual int encode(stringstream& ss);

	virtual int decode(string token);

	virtual int encode_token_value(stringstream& ss){return -1;}

	virtual int decode_token_value(string value){return -1;}

	virtual string get_token();

	virtual string get_string_attribute(string key);

	virtual int get_int_attribute(string key);
};

class rtp_channel_info
{
public:
	int			m_npt;
	string		m_smedia_type;
	string		m_scodec_name;
	string		m_strack_name;
	string		m_surl;
	uint16_t	m_nseq_num;
	uint32_t	m_urtp_timestamp;
	uint32_t	m_ussrc;
	uint32_t	m_nbitrate;
	int			m_nrtp_channe_id;
	int			m_nrtcp_channel_id;
	int			m_nrtp_client_port;
	int			m_nrtcp_client_port;

	rtp_channel_info()
	{
		m_npt				= 0;
		m_nseq_num			= 0;
		m_urtp_timestamp	= 0;
		m_ussrc				= 0;
		m_nbitrate			= 0;
		m_nrtp_channe_id	= -1;
		m_nrtcp_channel_id	= -1;
		m_nrtp_client_port	= -1;
		m_nrtcp_client_port	= -1;
	}

	rtp_channel_info* copy()
	{
		rtp_channel_info* prci = new rtp_channel_info();
		prci->m_npt				= m_npt;
		prci->m_smedia_type		= m_smedia_type;
		prci->m_scodec_name		= m_scodec_name;

		prci->m_strack_name		= m_strack_name;
		prci->m_surl			= m_surl;
		prci->m_nseq_num		= m_nseq_num;
		prci->m_urtp_timestamp	= m_urtp_timestamp;
	
		prci->m_ussrc			= m_ussrc;
		prci->m_nbitrate		= m_nbitrate;

		prci->m_nrtp_channe_id		= m_nrtp_channe_id;
		prci->m_nrtcp_channel_id	= m_nrtcp_channel_id;

		prci->m_nrtp_client_port	= m_nrtp_client_port;
		prci->m_nrtcp_client_port	= m_nrtcp_client_port;

		return prci;
	}
};

class rtp_play_info:public irtsp_token_codec
{
public:
	struct play_track_info
	{
		string 			m_surl;
		uint16_t		m_useq_num;
		uint32_t		m_urtp_timestamp;

		play_track_info()
		{
			m_useq_num = 0;
			m_urtp_timestamp = 0;
		}
	};

	map<string, play_track_info*>	m_mtrack_info_list;

public:
	rtp_play_info();

	virtual int add_track(string url, uint16_t seq_num, uint32_t rtp_timestamp);

	virtual int remove_track(string url);

	virtual int track_count();

	virtual int get_track_info(int index, string& url, uint16_t& seq_num, uint32_t& rtp_timestamp);

	virtual int encode_token_value(stringstream& ss);

	virtual int decode_token_value(string token);
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
class lazy_rtsp_transport:public irtsp_token_codec
{
public:
    // The syntax for the transport specifier is
    //      transport/profile/lower-transport
    string m_stransport;
    string m_sprofile;
    string m_slower_transport;
    // unicast | multicast
    // mutually exclusive indication of whether unicast or multicast
    // delivery will be attempted. Default value is multicast.
    // Clients that are capable of handling both unicast and
    // multicast transmission MUST indicate such capability by
    // including two full transport-specs with separate parameters
    // for each.
    string m_sscast_type;
    // The mode parameter indicates the methods to be supported for
    // this session. Valid values are PLAY and RECORD. If not
    // provided, the default is PLAY.
    string m_smode;

	// for rtsp over udp
    // This parameter provides the unicast RTP/RTCP port pair on
    // which the client has chosen to receive media data and control
    // information. It is specified as a range, e.g.,
    //      client_port=3456-3457.
    // where client will use port in:
    //      [client_port_min, client_port_max)
    int m_nclient_port_min;
    int m_nclient_port_max;

	// for rtsp overt tcp
    int m_nrtp_channel_id;
    int m_nrtcp_channel_id;

public:
    lazy_rtsp_transport();

    virtual ~lazy_rtsp_transport();
public:

	int init(string protocol, int rtp_channel, int rtcp_channel);
	/**
	 * encode a rtsp transport token
	 */
	virtual int encode(stringstream& ss);

    /**
    * decode a line of token for transport.
    */
    virtual int decode(string attr);
};

class lazy_rtsp_authorization:public irtsp_token_codec{
public:
	string		m_smethod;
	string 		m_sauth_type;
    string     	m_suser_name;
    string     	m_srealm;
    string     	m_snonce;
    string     	m_suri;
	string		m_spassword;
    string     	m_sresponse;

    std::map<string, string>  m_mpair_list;

public:

	int init(string method, string user_name, string pwd, string uri);

	// encode a rtsp authorization token

	virtual int encode(stringstream& ss);

 
    // decode rtsp authorization token
    virtual int decode(string attr);

    string get_attribute(string attr);

	bool authorize();

    string gen_response_by_pwd(const string& cmd, const string& url, const string& username, const string& pwd);

protected:
    int read_key_value_pair(string attr);
};

class rtsp_public_option:irtsp_token_codec
{
public:
	vector<string> m_vmethod_list;

public:
	rtsp_public_option();

	virtual int init(const vector<string>& vmethod_list);

	virtual int add_method(string method);

	virtual void clear();
	/**
	 * encode a rtsp public token
	 */
	virtual int encode_token_value(stringstream& ss);

    /**
    * decode rtsp public token
    */
    virtual int decode_token_value(string cmd_str);
};

class lazy_rtsp_command
{
public:
	ecommon_type		m_ecommon_type;
	string				m_smethod;
	string				m_sprotocol_version;

	// CSeq token format:CSeq: $(m_nseq)
	int					m_nseq;

	// User_Agent token format:User_Agent: $(m_suser_agent)
	string				m_suser_agent;

	// content body type
	string				m_scontent_type;

	// accept type
	string				m_saccept_type;

	// content description length
	int					m_ncontent_len;

	// token format:Content-Base: $(m_scontent_base)
	string				m_scontent_base;

	// date time
	string				m_sdate_time;

	// token format:Range: npt=$(m_dstart_range)-$(m_dstop_range)
	double				m_dstart_range;
	double				m_dstop_range;

	// token format:Session: $(m_ssession)
	string				m_ssession;

	int					m_nsession_time;

	vector<irtsp_token_codec*>		m_vtoken_list;
	map<string, string>				m_mtoken_list;

	session_description_protocol*	m_psdp;

	//lazy_rtsp_transport*		m_ptransport;
	//lazy_rtsp_authorization*	m_pauthorization;

public:
	lazy_rtsp_command(ecommon_type com_type, int seq);

	virtual ~lazy_rtsp_command();

	string Date();

	virtual int encode(void* pdata, int len);

	virtual int on_encode_header(stringstream& ss);

	virtual int on_encode_tokens(stringstream& ss);

	virtual int on_encode_extra_tokens(stringstream& ss);

	virtual int on_encode_content(stringstream& ss);

	static lazy_rtsp_command* parser_command(string com_str);

	virtual int decode(string com_str);

	virtual int on_decode_header(string& com_str) = 0;
	//virtual int decode_tokens(string& com_str);

	virtual int decode_content(string& content);

	virtual int on_decode_token(string token, string value);

	virtual int create_transport(string lower_transport, int rtp_channel_id, int rtcp_channel_id);

	virtual int create_play_rtp_info();

	virtual int add_token(irtsp_token_codec* prtc);

};

class lazy_rtsp_request_command : public lazy_rtsp_command
{
public:
	// rtsp method format:$(m_smethod) $(m_surl) $(m_sprotocol)/$(m_sversion)
	string		m_surl;

public:
	lazy_rtsp_request_command(string method, string url);
	virtual ~lazy_rtsp_request_command();

	virtual int on_encode_header(stringstream& ss);

	virtual int on_decode_header(string& com_str);
};

class lazy_rtsp_response_command :public lazy_rtsp_command
{
public:
	int			m_nstatus_code;
	string		m_sstatus_msg;

public:
	lazy_rtsp_response_command();
	lazy_rtsp_response_command(int status_code, string status_msg, int seq);
	virtual ~lazy_rtsp_response_command();

	virtual int encode_header(stringstream& ss);

	virtual int on_decode_token(string token, string value);
};

class lazy_rtsp_response_option :public lazy_rtsp_response_command
{
public:
	//string	m_spublic_method;
	vector<string>		m_vmethod_option;
public:
	lazy_rtsp_response_option(int status_code, string status_msg, int seq);
	~lazy_rtsp_response_option();

	int encode_extra_body(stringstream& ss);
};

class lazy_rtsp_describe_response :public lazy_rtsp_response_command
{
public:
	string			m_slocal_address;
	string			m_ssession_name;
	string			m_smedia_title;
public:
	lazy_rtsp_describe_response(int status_code, string status_msg, int seq);

	~lazy_rtsp_describe_response();

	virtual int init_sdp(string address, string session_name, string media_title);

    virtual int add_media_description(string mt, int pt, int port, int bitrate, string track_name);

	virtual int set_sequence_header(int pt, uint8_t* pcfg1, int cfg1_len, uint8_t* pcfg2 = NULL, int cfg2_len = 0);

	virtual int on_encode_content(stringstream& ss);

	virtual int on_decode_content(string sdp);

};

class iread_write_handle
{
public:
	virtual ~iread_write_handle(){}

	virtual int write(void* pdata, int len) = 0;

	virtual int read(void* pdata, int len) = 0;

	virtual int get_socket() = 0;
};

class iprotocol_stack
{
public:
	virtual int init_socket(iread_write_handle* pskt) = 0;

	virtual int start() = 0;
	
	virtual int stop() = 0;

	virtual void close() = 0;
	};

class lazy_rtsp_stack:public iprotocol_stack, public lazy_thread
{
protected:
	iread_write_handle*				m_pread_write_handle;
	map<int, rtp_channel_info*>		m_mchannel_list;
	string							m_ssession;
	lbsp_buffer_socket*				m_pbuf_skt;

	char* 							m_pbuf;
	int								m_nbuf_size;
public:
	lazy_rtsp_stack();

	~lazy_rtsp_stack();

	virtual int init_socket(iread_write_handle* pskt);

	virtual int start();
	
	virtual int stop();

	virtual void close();

	virtual int on_cycle();

	virtual int send_message(lazy_rtsp_command* pcommon);

	virtual int send_rtp_packet(packet_buffer* pkt);

	virtual int send_data(void* pdata, int len);

	virtual int recv_data(void* pdata, int len);

	//virtual int on_cycle();

protected:
	virtual int parser_common(char* pcmd);

	virtual rtp_channel_info* find_channel_info_by_track_name(string track_name);

	virtual string get_track_name_from_url(string url);
};
};


