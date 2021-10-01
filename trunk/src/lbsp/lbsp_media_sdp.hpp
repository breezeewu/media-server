#include <string>
#include <sstream>
#include <memory>
#include <lbsp_utility_string.hpp>
#include <lbsp_utility_common.hpp>
#include "lbsc_const_micro.h"

#define	LBSP_CONST_CRLF			"/r/n"
#define LBSP_TOOL_LIB_VERSION	"2020.04.24"

#define LAZY_RTSP_H264_PAYLOAD_TYPE		96
#define LAZY_RTSP_AAC_PAYLOAD_TYPE		97
using namespace std;
//#define LBSP_SDP_ATTR_TOKEN		"v"
namespace lbsp_util
{
class sdp_media_description
{
public:
	// media description format:m=$(m_smedia_type) $(m_nport) $(m_stransport_protocol) $(m_npayload_type)
	string		m_smedia_type;
	int			m_nport;
	string		m_stransport_protocol;
	int			m_npayload_type;

	// connect info format:c=$(m_snetwork_type) $(m_saddress_type) $(m_saddress)
	string		m_snetwork_type;
	string		m_saddress_type;
	string		m_saddress;

	// bitrate info format: b=$(m_nbitrate)
	int			m_nbitrate;

	// rtp map info fromat: a=rtpmap:$(m_npayload_type) $(m_scodec_info) $(m_nmedia_time_base)
	string		m_scodec_info;
	int			m_nmedia_time_base;

	// fmtp for h264 a=fmtp:$(m_npayload_type);packetization-mode=$(m_npacketization_mode);profile-level-id=$(m_nprofile_level_id);sprop-parameter-sets=$(base64(m_ssps)),$(base64(m_spps))
	// fmtp for aac a=fmtp:$(m_npayload_type);streamtype=5;profile-level-id=$(m_nprofile_level_id);mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=$(m_saudio_config)
	int			m_nprofile_level_id;// for h264 sps[1-3], for aac is 1
	int			m_npacketization_mode; // 1:frame split to mutil rtp packet transport, 0, not split
	int			m_nstream_type;
	string		m_smode;
	double		m_dmedia_duration;
	// track id format:a=control:$(m_strack_id)
	string		m_strack_id;

	// sps pps
	string		m_ssps;
	string		m_spps;

	// media codec sequence header data
	string		m_sextra_data;

public:
	sdp_media_description();

	virtual ~sdp_media_description();

	int init(string media_type, int port, int pt, string codec_name,  int bitrate, string track_name, uint8_t* extradata, int len);

	int set_codec_config(int pt, char* pcodec_cfg1, int codec_cfg1_len, char* pcodec_cfg2, int codec_cfg2_len);

	int ecnode(stringstream& ss);

	int decode(string& media_desc);

	int on_decode_token(const string token, string value);

	int on_decode_attribut(string key, string value);

	int on_decode_fmtp_key(const string& key, const string& val);
};

class session_description_protocol
{
public:
	//  format:v=$(m_nversion), the version of sdp,
	const int 		m_nversion;

	// format o=$m_sowner_user_name $(m_sowner_session_id) $(m_sowner_session_version) $(m_sowner_network_type) $(m_sowner_address_type) $(m_sowner_address)
	// the owner/creater and session flags
	string		m_sowner_user_name;
	string		m_sowner_session_id;
	int			m_nowner_session_version;
	string		m_sowner_network_type;
	string		m_sowner_address_type;
	string		m_sowner_address;

	// format:s=$(m_ssession_name),session name 
	string		m_ssession_name;

	// format:i=$(m_ssession_info), session information, 
	string		m_ssession_info;

	// format:t=$(m_nstart_time) $(m_nstop_time)
	int			m_nstart_time;
	int			m_nstop_time;

	// format:a=tool:$(m_stool_name)$(m_stool_version)
	string		m_stool_name;
	string		m_stool_version;

	// format:a=type:$(m_sconference_type)
	string		m_sconference_type;

	// medis streaming time range in second
	double 		m_dstreaming_time_range;

	vector<shared_ptr<sdp_media_description>>	m_vsdp_media_desc;
	map<string, string>			m_mattribut_list;

public:
	session_description_protocol();

	~session_description_protocol();

	int init(string session_name, string session_info, string ip);

	int add_media_description(string mediatype, int pt, int port, string codec_name,  int bitrate, string track_name);

	int encode(stringstream& ss);

	int decode(string sdp);

	int on_decode_token(string token, string val);

	int on_decode_session_attribute(string key, string val);
};
};
