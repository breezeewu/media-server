/***********************************************************************************************************
 * SDP(session description protocol) format:
 * v=<*version_num>; //* sdp version number unusually is 0
 * o=<username, - indicate none> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>; //* session origin name identify and network info
 * s=<session-name>; //* every sdp only has one session name
 * i=<session-info>; // session description info, every sdp only has one session info
 * c=<nettype> <addrtype> <unicast-address>; // connection info, including network type, address type, address
 * t=<start-time> <stop-time>; // session start time and stop time in second
 * a=tool:<name and version of tool>; // tool name and version of which create sdp
 * a=type:<conference type>; // suggest value is "broadcast", "meeting", "moderated", "test", "H332"
 * a=control:*; // video/audio connection info
 * a=range:npt=<starttime-stoptime>; // media stream time range
 * a=x-qt-text-nam:<streaming tools>; // media streaming tool name
 * a=x-qt-text-inf:<media source name>; // media source name
 * m=<mediatype> <port> <transport protocol> <payload type>; // media description info
 * c=<network type> <address type> <address>; // media connection info
 * b=AS:<bitrate>; // media stream bitrate in kbps
 * a=control:<track-id>; // media stream track id
 * *********************************************************************************************************/
#include <string>
#include <sstream>
#include <memory>
//#include "lbsp_media_sdp.hpp"
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
	sdp_media_description():m_stransport_protocol("RTP/AVP"), m_snetwork_type("IN"), m_saddress_type("IP4"), m_saddress("0.0.0.0")
	{
		m_nport 			= -1;
		m_npayload_type 	= -1;
		m_nbitrate			= 0;
		m_nmedia_time_base	= 90000;
		m_nprofile_level_id = 0;
		m_npacketization_mode = 0;
		m_nstream_type		= 5;
	}

	virtual ~sdp_media_description()
	{

	}

	int init(string media_type, int port, int pt, string codec_name,  int bitrate, string track_name, uint8_t* extradata, int len)
	{
		m_smedia_type 	= media_type;
		m_nport 		= port;
		m_npayload_type = pt;
		m_scodec_info	= codec_name;
		m_strack_id		= track_name;
		m_nbitrate		= bitrate;

		if(extradata && len > 0)
		{
			m_sextra_data.append((char*)extradata, len);
		}

		return 0;
	}

	int set_codec_config(int pt, char* pcodec_cfg1, int codec_cfg1_len, char* pcodec_cfg2, int codec_cfg2_len)
	{
		CHECK_PARAM_PTR(pcodec_cfg1, -1);
		if(LAZY_RTSP_H264_PAYLOAD_TYPE == pt)
		{
			CHECK_PARAM_PTR(pcodec_cfg2, -1);
			m_ssps.clear();
			m_spps.clear();
			if(pcodec_cfg1)
			{
				m_ssps.append(pcodec_cfg1, codec_cfg1_len);
			}

			if(pcodec_cfg2)
			{
				m_spps.append(pcodec_cfg2, codec_cfg2_len);
			}
		}
		else if(LAZY_RTSP_AAC_PAYLOAD_TYPE == pt)
		{
			m_sextra_data.clear();
			if(pcodec_cfg1)
			{
				m_sextra_data.append(pcodec_cfg1, codec_cfg1_len);
			}
		}

		return 0;
	}

	int ecnode(stringstream& ss)
	{
		// media description info
		ss << "m=" << m_smedia_type << " " << m_nport << " " << m_stransport_protocol << m_npayload_type << LBSP_CONST_CRLF;
		// media connection info
		ss << "c=" << m_snetwork_type << " " << m_saddress_type << " " << m_saddress << LBSP_CONST_CRLF;
		// media bitrate info
		ss << "b=AS:" << m_nbitrate << LBSP_CONST_CRLF;
		ss << "a=rtpmap:" << m_npayload_type << " " << m_scodec_info << "/" << m_nmedia_time_base << LBSP_CONST_CRLF;
		char pli[32] = {0};
		sprintf(pli, "%0x", m_nprofile_level_id);
		if(m_scodec_info == "H264")
		{
			ss << "a=fmtp:" << m_npayload_type << " packetization-mode=" << m_npacketization_mode << ";profile-level-id=" << pli;
			if(!m_ssps.empty() && !m_spps.empty())
			{
				char b64_sps[256] = {0};
				char b64_pps[256] = {0};

				//b64_enc(m_ssps.c_str(), m_ssps.length(), b64_sps, 256);
				//b64_enc(m_spps.c_str(), m_spps.length(), b64_pps, 256);
				ss << ";sprop-parameter-sets=" << b64_sps << "," << b64_pps;
			}
			ss << LBSP_CONST_CRLF;
		}
		else if(m_scodec_info == "MPEG4-GENERIC")
		{
			ss << "a=fmtp:" << m_npayload_type << " streamtype=" << m_nstream_type << ";profile-level-id=" << pli << "mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3";
			if(!m_sextra_data.empty())
			{
				ss << ";config=" << m_sextra_data << LBSP_CONST_CRLF;
			}
			
		}

		// media track id
		ss << "a=control:" << m_strack_id << LBSP_CONST_CRLF;
		lbdump(3, "sdp encode %s\n", ss.str().c_str());

		return 0;
	}

	int decode(string& media_desc)
	{
		int ret = 0;
		if(0 != memcmp(media_desc.c_str(), "m=", 2))
		{
			return -1;
		}
		while(!media_desc.empty() && media_desc[0] != 'm')
		{
			string value;
			string md_line;
			ret = read_line(media_desc, md_line);
			CHECK_RESULT(ret);
			ret = string_split(md_line, value, "=");
			CHECK_RESULT(ret);
			ret = on_decode_token(md_line, value);
			CHECK_RESULT(ret);
		}
		
	}

	int on_decode_token(const string token, string value)
	{
		int ret = 0;
		if("m" == token)
		{
			vector<string> vlist = string_splits(value, " ");
			if(vlist.size() < 4)
			{
				lbdump(5, "Invalid media desc %s\n", value.c_str());
				return -1;
			}
			m_smedia_type = vlist[0];
			m_nport			= stoi(vlist[1].c_str());
			m_stransport_protocol	= vlist[2];
			m_npayload_type			= stoi(vlist[4].c_str());
		}
		else if("c" == token)// connection info
		{
			vector<string> vlist = string_splits(value, " ");
			if(vlist.size() < 3)
			{
				lbdump(5, "Invalid media desc %s\n", value.c_str());
				return -1;
			}
			m_snetwork_type 		= vlist[0];
			m_saddress_type			= vlist[1];
			m_saddress				= vlist[2];

		}
		else if("b" ==  token)
		{
			string br_str;
			ret = string_split(value, br_str, ":");
			CHECK_RESULT(ret);
			m_nbitrate = stoi(br_str.c_str());
		}
		else if("a" == token)
		{
			string attr_key;
			string attr_val;
			ret = string_split(value, attr_key, ":");
			CHECK_RESULT(ret);
			ret = on_decode_attribut(attr_key, value);
			CHECK_RESULT(ret);
		}
		else
		{
			lbdump(5, "Unknown token key:%s val:%s\n", token.c_str(), value.c_str());
			ret = -1;
		}
		return ret;
	}

	int on_decode_attribut(string key, string value)
	{
		int ret = 0;
		if("control" == key)
		{
			m_strack_id = value;
		}
		else if("range" ==  key)
		{
			string tag;
			string start_time;
			ret = string_split(value, tag, "npt=");
			CHECK_RESULT(ret);
			ret = string_split(value, start_time, "-");
			CHECK_RESULT(ret);
			m_dmedia_duration =  atof(value.c_str());
		}
		else if("length" ==  key)
		{
			string tag;
			ret = string_split(value, tag, "npt=");
			CHECK_RESULT(ret);
			m_dmedia_duration =  atof(value.c_str());
			
		}
		else if("rtpmap" ==  key)
		{
			int pt = 0;
			string subval;
			ret = string_split(value, subval, " ");
			CHECK_RESULT(ret);
			pt =  atoi(subval.c_str());
			ret = string_split(value, subval, "/");
			CHECK_RESULT(ret);
			m_scodec_info = subval;
			m_nmedia_time_base = atoi(value.c_str());
		}
		else if("fmtp" ==  key)
		{
			int pt = 0;
			string subval;
			ret = string_split(value, subval, " ");
			CHECK_RESULT(ret);
			pt =  atoi(subval.c_str());
			map<string, string> key_val_pair;
			ret = read_key_val_pair_from_line(value, ";", "=", key_val_pair);
			CHECK_RESULT(ret);

			for(map<string, string>::iterator it = key_val_pair.begin(); it != key_val_pair.end(); it++)
			{
				on_decode_fmtp_key(it->first, it->second);
			}
		}
	}

	int on_decode_fmtp_key(const string& key, const string& val)
	{
		if("packetization-mode" == key)
		{
			m_npacketization_mode = atoi(val.c_str());
		}
		else if("profile-level-id" == key)
		{
			m_nprofile_level_id = atoi(val.c_str());
		}
		else if("sprop-parameter-sets" == key)
		{
			string b64_sps, b64_pps = val;
			int ret = string_split(b64_pps, b64_sps, ",");
			CHECK_RESULT(ret);
			m_ssps = b64_dec(b64_sps.c_str(), b64_sps.length());
			if(m_ssps.length() < 0)
			{
				lbdump(5, "base 64 decode sps failed, m_ssps:%s, m_ssps.length():%d\n", m_ssps.c_str(), m_ssps.length());
				return -1;
			}

			m_spps = b64_dec(b64_pps.c_str(), b64_pps.length());
			if(m_spps.length() <= 0)
			{
				lbdump(5, "base 64 decode sps failed, m_spps.length():%d, m_spps:%s\n", m_spps.length(), m_spps.c_str());
				return -1;
			}

			return 0;
		}
		else if("streamtype" == key)
		{
			m_nstream_type = stoi(val.c_str());
		}
		else if("mode" == key)
		{
			m_smode = val;
		}
		else if("config" == key)
		{
			m_sextra_data = val;
		}
		else
		{
			lbdump(3, "fmtp key:%s val:%s\n", key.c_str(), val.c_str());
		}
		
		return 0;
	}
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
	session_description_protocol():m_nversion(0), m_stool_name("Lazy Rtsp Server Streaming Media"), m_stool_version(LBSP_TOOL_LIB_VERSION), m_sconference_type("broadcast")
	{
		m_sowner_user_name = "-";
		m_nowner_session_version = 1;
		m_nstart_time = 0;
		m_nstop_time = 0;
		m_dstreaming_time_range = 0;
		m_sowner_address = "0.0.0.0";

	}

	~session_description_protocol()
	{
	}

	int init(string session_name, string session_info, string ip)
	{
		m_ssession_name = session_name;
		m_ssession_info = session_info;
		m_sowner_address = ip;

		return 0;
	}

	int add_media_description(string mediatype, int pt, int port, string codec_name,  int bitrate, string track_name)
	{
		shared_ptr<sdp_media_description> psmd(new sdp_media_description());

		int ret = psmd->init(mediatype, port, pt, codec_name, bitrate, track_name, NULL, 0);
		CHECK_RESULT(ret);
		m_vsdp_media_desc.push_back(psmd);
		return ret;
	}

	int encode(stringstream& ss)
	{
		int ret = 0;
		m_sowner_session_id  = string_format("%u", get_system_time());
		ss << "v=" << m_nversion << LBSP_CONST_CRLF \
		<< "o=" << m_sowner_user_name << " " << m_sowner_session_id << " " << m_nowner_session_version <<" " \
		<< m_sowner_network_type << " " << m_sowner_address_type << " " << m_sowner_address << LBSP_CONST_CRLF \
		<< "s=" << m_ssession_name << LBSP_CONST_CRLF \
		<< "i=" << m_ssession_info << LBSP_CONST_CRLF \
		<< "t=" << m_nstart_time << " " << m_nstop_time << LBSP_CONST_CRLF \
		<< "a=tool:" << m_stool_name << "v" << m_stool_version << LBSP_CONST_CRLF \
		<< "a=type:" << m_sconference_type << LBSP_CONST_CRLF \
		<< "a=control:*" << LBSP_CONST_CRLF \
		<< "a=range:npt=-";
		if(m_dstreaming_time_range > 0)
		{
			ss << m_dstreaming_time_range;
		}

		ss << LBSP_CONST_CRLF \
		<< "a=x-qt-text-nam:" << m_ssession_name << LBSP_CONST_CRLF \
		<< "a=x-qt-text-inf:" << m_ssession_info << LBSP_CONST_CRLF;

		for(size_t i = 0; i < m_vsdp_media_desc.size(); i++)
		{
			shared_ptr<sdp_media_description> psmd = m_vsdp_media_desc[i];
			ret = psmd->ecnode(ss);
			CHECK_RESULT(ret);
		}
		ss << LBSP_CONST_CRLF;

		return ret;
	}

	int decode(string sdp)
	{
		int ret = 0;
		while(!sdp.empty())
		{
			if(sdp[0] == 'm')
			{
				sdp_media_description* psmd = new sdp_media_description();
				ret = psmd->decode(sdp);
				CHECK_RESULT(ret);
			}
			else
			{
				string line;
				string val;
				ret = read_line(sdp, line);
				CHECK_RESULT(ret);
				ret = string_split(line, val, "=");
				CHECK_RESULT(ret);
				ret = on_decode_token(line, val);
				CHECK_RESULT(ret);
			}
		}
		
		return ret;
	}

	int on_decode_token(string token, string val)
	{
		int ret = 0;
		lbdebug("sdp on_decode_token(%s, %s)\n", token.c_str(), val.c_str());
		if("v" == token)// version
		{
			if(m_nversion != stoi(val.c_str()))
			{
				lberror("Invalid sdp version %s\n", val.c_str());
				return -1;
			}
		}
		else if("o" == token)// owner info
		{
			vector<string> vstrlist = string_splits(val, " ");
			if(vstrlist.size() < 6)
			{
				lberror("invalid owner and session info %s\n", val.c_str());
				return -1;
			}
			m_sowner_user_name 			= vstrlist[0];
			m_sowner_session_id			= vstrlist[1];
			m_nowner_session_version	= atoi(vstrlist[2].c_str());
			m_sowner_network_type		= vstrlist[3];
			m_sowner_address_type		= vstrlist[4];
			m_sowner_address			= vstrlist[5];
		}
		else if("s" == token) // session name
		{
			m_ssession_name = val;
		}
		else if("i" == token) // session info
		{
			m_ssession_info = val;
		}
		else if("t" == token) //  session active time
		{
			vector<string> vstrlist = string_splits(val, " ");
			m_nstart_time = atoi(vstrlist[0].c_str());
			if(vstrlist.size() > 1)
			{
				m_nstop_time = atoi(vstrlist[1].c_str());
			}
		}
		else if("a" == token)
		{
			vector<string> vstrlist = string_splits(val, ":");
			if(vstrlist.size() < 2)
			{
				lberror("Invalid session attribut %s\n", val.c_str());
				return -1;
			}
			ret = on_decode_session_attribute(vstrlist[0], vstrlist[1]);
			CHECK_RESULT(ret);
		}
		else
		{
			lberror("Unknown token:%s and val:%s\n", token.c_str(), val.c_str());
		}

		return 0;
	}

	int on_decode_session_attribute(string key, string val)
	{
		m_mattribut_list[key] = val;
		return 0;
	}
};
};
