#include <vector>
#include "lbsp_rtsp_stack.h"
#include "lbsp_utility_string.hpp"
#include "lbsp_media_parser.hxx"
using namespace lbsp_util;
#ifdef WIN32
#include <windows.h>
#endif

int irtsp_token_codec::encode(stringstream& ss)
{
	ss << m_stoken << LAZY_CONST_COSP;
	int ret = encode_token_value(ss);
	CHECK_RESULT(ret);
	ss << LAZY_CONST_CRLF;

	return ret;
}

int irtsp_token_codec::decode(string token)
{
	int ret = read_token_and_assert(token, m_stoken);
	CHECK_RESULT(ret);
	ret = read_token_and_assert(token, LAZY_CONST_COSP);
	CHECK_RESULT(ret);
	token = string_trim(token, LAZY_CONST_CRLF);
	ret = decode_token_value(token);
	CHECK_RESULT(ret);
	return ret;
}

string irtsp_token_codec::get_token()
{
	return m_stoken;
}

string irtsp_token_codec::get_string_attribute(string key)
{
	return string();
}

int irtsp_token_codec::get_int_attribute(string key)
{
	return 0;
}

rtp_play_info():irtsp_token_codec("RTP-Info")
{
	
}

int rtp_play_info::add_track(string url, uint16_t seq_num, uint32_t rtp_timestamp)
{
	if(url.empty())
	{
		lberror("Invalid track url %s", url.c_str());
		return -1;
	}
	remove_track(url);

	play_track_info* pti = new play_track_info();
	pti->url = url;
	pti->useq_num = seq_num;
	pri->urtp_timestamp = rtp_timestamp;

	m_mtrack_info_list.push_back(pri);
	return 0;
}

int rtp_play_info::remove_track(string url)
{
	map<string, play_track_info*>::iterator it = m_mtrack_info_list.find(url);
	if(it != m_mtrack_info_list.end())
	{
		delete it->second;
		m_mtrack_info_list.erase(it);
		return 0;
	}

	return -1;
}

int rtp_play_info::track_count()
{
	return m_mtrack_info_list.size();
}

int rtp_play_info::get_track_info(int index, string& url, uint16_t& seq_num, uint32_t& rtp_timestamp)
{
	if(m_mtrack_info_list.size() < index || index < 0)
	{
		lberror("Invalid track index %d\n", index);
		return -1;
	}

	url = m_mtrack_info_list[index].m_surl;
	seq_num = m_mtrack_info_list[index].m_useq_num;
	rtp_timestamp = m_mtrack_info_list[index].m_urtp_timestamp;

	return 0;
}

int rtp_play_info::encode_token_value(stringstream& ss)
{
	if(m_mtrack_info_list.size() <= 0)
	{
		return -1;
	}
	//ss << m_stoken << LAZY_CONST_COSP;
	for(size_t i = 0; i < m_mtrack_info_list.size(); i++)
	{
		if(i > 0)
		{
			ss << ",";
		}
		ss << "url=" << m_mtrack_info_list[i].m_surl << ";seq=" << m_mtrack_info_list[i].m_useq_num << ";rtptime=" << m_mtrack_info_list[index].m_urtp_timestamp;
	}
	//ss << LAZY_CONST_CRLF;

	return 0;
}

int rtp_play_info::decode_token_value(string cmd_str)
{
	//int ret = read_token_and_assert(cmd_str, m_stoken);
	//CHECK_RESULT(ret);

	vector<string> rtp_info_list = string_splits(cmd_str, ",");
	for(size_t i = 0; i < rtp_info_list.size(); i++)
	{
		map<string, string> key_val_list;
		ret = read_key_val_pair_from_line(rtp_info_list[i], ";", "=", key_val_list);
		CHECK_RESULT(ret);
		play_track_info* pti = new play_track_info();
		for(map<string, string>::iteroator it = key_val_list.begin(); it != key_val_list; it++)
		{
			if("url" == it->first)
			{
				pti->url = it->second;
			}
			else if("seq" == it->first)
			{
				pti->useq_num = atoi(it->second.c_str());
			}
			else if("rtptime" == it->first)
			{
				pti->urtp_timestamp = atoi(it->second.c_str());
			}
			else
			{
				lberror("Unknown rtp play info key %s, val %s\n", it->first.c_str(), it->second.c_str());
			}
		}

		m_mtrack_info_list[pti->url] = pti;
	}

	return 0;
}

lazy_rtsp_transport::lazy_rtsp_transport():irtsp_token_codec("Transport")
{
	m_nclient_port_min	= -1;
    m_nclient_port_max	= -1;
    m_nrtp_channel_id	= -1;
    m_nrtcp_channel_id	= -1;
}

lazy_rtsp_transport::~lazy_rtsp_transport()
{

}

int lazy_rtsp_transport::init(string lower_transport, int rtp_channel, int rtcp_channel)
{
	m_slower_transport = lower_transport;
	if("TCP" == m_slower_transport)
	{
		m_nrtp_channel_id = rtp_channel;
		m_nrtcp_channel_id = rtcp_channel;
	}
	else if("UDP" == m_slower_transport)
	{
		m_nclient_port_min = rtp_channel;
		m_nclient_port_max = rtcp_channel;
	}
	else
	{
		return -1;
	}

	return 0;
}

int lazy_rtsp_transport::encode_token_value(stringstream& ss)
{
	m_stransport = "RTP";
	m_sprofile = "AVP";

	//ss << LAZY_RTSP_TOKEN_TRANSPORT << LAZY_CONST_COSP;
	ss << m_stransport << "/" << m_sprofile;
	if("TCP" == m_slower_transport)
	{
		ss << "/" << m_slower_transport;
	}
	if(!m_smode.empty())
	{
		ss << ";mode=" << m_smode;
	}
	ss << m_sscast_type << LAZY_CONST_comma;
	if(m_nclient_port_min > 0 && m_nclient_port_max > 0)
	{
		ss << ";client_port=" << m_nclient_port_min << "-" << m_nclient_port_max;
	}
	else if(m_nrtp_channel_id > 0 && m_nrtcp_channel_id >0)
	{
		ss << ";interleaved=" << m_nrtp_channel_id << "-" << m_nrtcp_channel_id;
	}
	//ss << LAZY_CONST_CRLF;

	return 0;
}

int lazy_rtsp_transport::decode_token_value(string attr)
{
	int ret = 0;
    
    size_t pos = string::npos;
    string token = attr;

    while (!token.empty()) {
        string item = token;
        if ((pos = item.find(";")) != string::npos) {
            item = token.substr(0, pos);
            token = token.substr(pos + 1);
        } else {
            token = "";
        }

        string item_key = item, item_value;
        if ((pos = item.find("=")) != string::npos) {
            item_key = item.substr(0, pos);
            item_value = item.substr(pos + 1);
        }

        if (transport.empty()) {
            m_stransport = item_key;
            if ((pos = transport.find("/")) != string::npos) {
                m_sprofile = transport.substr(pos + 1);
                m_stransport = transport.substr(0, pos);
            }
            if ((pos = profile.find("/")) != string::npos) {
                m_slower_transport = profile.substr(pos + 1);
                m_sprofile = profile.substr(0, pos);
            }
        }

        if (item_key == "unicast" || item_key == "multicast") {
            m_scast_type = item_key;
        } else if (item_key == "mode") {
            m_smode = item_value;
        } else if (item_key == "client_port") {
            string sport = item_value;
            string eport = item_value;
            if ((pos = eport.find("-")) != string::npos) {
                sport = eport.substr(0, pos);
                eport = eport.substr(pos + 1);
            }
            m_nclient_port_min = ::atoi(sport.c_str());
            m_nclient_port_max = ::atoi(eport.c_str());
        }
        else if(item_key == "interleaved")
        {
           sscanf(item_value.c_str(), "%u-%u", &m_nrtp_channel_id, &m_nrtcp_channel_id);
           //srs_rtsp_debug("interleaved:item_value:%s, rtp_channel_id:%u, rtcp_channel_id:%u\n", item_value.c_str(), rtp_channel_id, rtcp_channel_id);
        }
    }

    return ret;
}

lazy_rtsp_authorization::lazy_rtsp_authorization:irtsp_token_codec("Authorization")
{
}
int lazy_rtsp_authorization::encode_token_value(stringstream& ss)
{
	m_snonce = gen_md5_by_time();

	//ss << "Authorization: 
	ss << "Digest username=\"" << m_suser_name << "\""
	<< ", realm=\"" << m_srealm << "\""
	<< ", nonce=\"" << m_snonce << "\""
	<< ", uri=\"" << m_suri << "\""
	<< ", response=\"" << gen_respone() << "\"";
	//<< LAZY_CONST_CRLF;
}

// hash1 = md5($(username):$(realm):$(password))
// hash2 = md5($(method):$(uri))
// resonse = md5($(hash1):$(nonce):$(hash2))
string lazy_rtsp_authorization::gen_respone()
{
	string hash1 = bsp_utility::CMD5Maker::gen_md5_by_string((m_susername + ":" + m_srealm + ":" + m_spassword);
	string hash2 = bsp_utility::CMD5Maker::gen_md5_by_string((m_smethod + ":" + m_suri);
	string resposne = bsp_utility::CMD5Maker::gen_md5_by_string((hash1 + ":" + m_snonce + ":" + hash2);

	return resposne;
}
int lazy_rtsp_authorization::decode_token_value(string attr)
{
	string next_item;
    //srs_rtsp_debug("parser(attr:%s)\n", attr.c_str());
    m_mpair_list.clear();
    //attr = srs_string_trim_start(attr, " ");//string_trim(attr, " ");
	// read Digest
    int ret = string_split(attr, next_item, " ");
    //srs_rtsp_debug("ret:%d = string_split(attr:%s, next_item:%s, \" \")\n", ret, attr.c_str(), next_item.c_str());
    SRS_CHECK_RESULT(ret);
	m_sauth_type = next_item;
    do
    {
        //srs_rtsp_debug("attr:%s\n", attr.c_str());
        ret = string_split(attr, next_item, ",");
        //srs_rtsp_debug("ret:%d = string_split(attr:%s, next_item:%s, \" \")\n", ret, attr.c_str(), next_item.c_str());
        //SRS_CHECK_RESULT(ret);
        if(!next_item.empty())
        {
           ret = read_key_value_pair(next_item);
           SRS_CHECK_RESULT(ret);
        }
    }while(!attr.empty());
    
    return m_mpair_list.size() > 0 ? ERROR_SUCCESS : -1;
}

bool lazy_rtsp_authorization::authorize()
{
	string response = gen_digest_response(method, m_susername, m_srealm, m_spassword, m_suri, m_snonce);
	if(response == m_sresponse)
	{
		return true;
	}

	return false;
}

// hash1 = md5($(username):$(realm):$(password))
// hash2 = md5($(method):$(uri))
// resonse = md5($(hash1):$(nonce):$(hash2))
string lazy_rtsp_authorization::gen_digest_response(string method, string user_name, string realm, string pwd, string uri, string nonce)
{
	lbdebug("gen_digest_response(method:%s, user_name:%s, realm:%s, pwd:%s, uri, nonce:%s)\n", method.c_str(), user_name.c_str(), realm.c_str(), pwd.c_str(), uri.c_str(), nonce.c_str());
    string hash1 = lbsp_utility::CMD5Maker::gen_md5_by_string(ser_name + ":" + realm + ":" + pwd);
    string hash2 = lbsp_utility::CMD5Maker::gen_md5_by_string(method + ":" +  uri);
    string hash3 = lbsp_utility::CMD5Maker::gen_md5_by_string(hash1 + ":" + nonce + ":" + hash2);
    //srs_rtsp_debug("hash3:%s, org_str3:%s", hash3.c_str(), org_str3.c_str());
    return hash3;
}

int lazy_rtsp_authorization::read_key_value_pair(string attr)
{
    string key;
    int ret = string_split(attr, key, "=");
    key = string_trim(key, " ");
    attr =  string_trim(attr, "\"");
    CHECK_RESULT(ret);
    m_mpair_list[key] = attr;
	if("username" == key)
	{
		m_suser_name = attr;
	}
	else if("realm" == key)
	{
		m_srealm = attr;
	}
	else if("nonce" == key)
	{
		m_snonce = attr;
	}
	else if("uri" == key)
	{
		m_suri = attr;
	}
	else if("response" == key)
	{
		m_sresponse = attr;
	}
	else
	{
		lberror("Unknown key %s value %s pair\n", key.c_str(), attr.c_str());
	}
	return ret;
}

string lazy_rtsp_authorization::get_attribute(string attr)
{
	string value;
    if(!attr.empty())
    {
        std::map<string, string>::iterator it = m_mpair_list.find(attr);
        if(m_mpair_list.end() != it)
        {
            value = it->second;
        }
    }

    return value;
}

rtsp_public_option::rtsp_public_option():irtsp_token_codec(LAZY_RTSP_TOKEN_PUBLIC)
{

}

int rtsp_public_option::init(const vector<string>& vmethod_list)
{
	m_vmethod_list.clear();
	for(size_t i = 0; i < vmethod_list.size(); i++)
	{
		m_vmethod_list.push_back(vmethod_list[i]);
	}

	return 0;
}

int rtsp_public_option::add_method(string method)
{
	m_vmethod_list.push_back(method);
	return 0;
}

void rtsp_public_option::clear()
{
	m_vmethod_list.clear();
}

int rtsp_public_optionencode::encode_token_value(stringstream& ss)
{
	//ss << m_smethod << LAZY_CONST_COSP;
	for(size_t i = 0; i < m_vmethod_list.size(); i++)
	{
		if(i > 0)
		{
			ss << ", ";
		}
		ss << m_vmethod_list[i];
	}

	//ss << LAZY_CONST_CRLF;
	return 0;
}

int rtsp_public_option::decode_token_value(string cmd_str)
{
	m_vmethod_list = string_splits(cmd_str, ", ");

	return m_vmethod_list.size() > 0 ? 0 : -1;
}

lazy_rtsp_command::lazy_rtsp_command(ecommon_type com_type, int seq):m_sprotocol_version("RTSP/1.0"), m_ecommon_type(com_type)
{
	m_nseq			= seq;
	m_dstart_range	= -1;
	m_dstop_range	= -1;
	m_ptransport		= NULL;
	m_pauthorization	= NULL;
}

lazy_rtsp_command::~lazy_rtsp_command()
{
	reset_token();
}

void lazy_rtsp_command::reset_token()
{
	for(size_t i = 0; i < m_vtoken_list.size(); i++)
	{
		delete m_vtoken_list[i];
	}

	m_vtoken_list.clear();

	if(m_psdp)
	{
		delete m_psdp;
		m_psdp = NULL;
	}
}

string lazy_rtsp_command::Date()
{
	char buf[256] = {0};
#ifdef WIN32
	SYSTEMTIME SystemTime;
	GetSystemTime(&SystemTime);
	WCHAR dateFormat[] = L"ddd, MMM dd yyyy";
	WCHAR timeFormat[] = L"HH:mm:ss GMT\r\n";
	WCHAR inBuf[256];
	DWORD locale = LOCALE_NEUTRAL;

	int ret = GetDateFormat(locale, 0, &SystemTime,
		(LPTSTR)dateFormat, (LPTSTR)inBuf, sizeof inBuf);
	inBuf[ret - 1] = ' ';
	ret = GetTimeFormat(locale, 0, &SystemTime,
		(LPTSTR)timeFormat,
		(LPTSTR)inBuf + ret, (sizeof inBuf) - ret);
	wcstombs(buf, inBuf, wcslen(inBuf));
#else
	//char datebuf[256] = { 0 };
	time_t tt = time(NULL);
	strftime(buf, sizeof(buf), "%a, %b %d %Y %H:%M:%S GMT", gmtime(&tt));
#endif
	return string(buf);
}

int lazy_rtsp_command::encode(void* pdata, int len)
{
	CHECK_PARAM_PTR(pdata, -1);
	stringstream ss;

	int ret = encode_header(ss);
	CHECK_RESULT(ret);

	ret = encode_tokens(ss);
	CHECK_RESULT(ret);
	ss << LAZY_CONST_CRLF;

	ret = encode_content(ss);
	CHECK_RESULT(ret);
	string command_str = ss.str();
	if (len < command_str.length())
	{
		lberror("not enough data buffer for command encode, have %d, need %d\n", len, command_str.length());
		assert(0);
		return -1;
	}
	lbdebug(command_str.c_str());
	memcpy(pdata, command_str.c_str(), command_str.length());
	return ret;
}

int lazy_rtsp_command::encode_header(stringstream& ss)
{
	return 0;
}

int lazy_rtsp_command::encode_tokens(stringstream& ss)
{
	if (m_nseq >= 0)
	{
		ss << LAZY_RTSP_TOKEN_CSEQ << LAZY_CONST_COSP << m_nseq << LAZY_CONST_CRLF;
	}
	if (!m_suser_agent.empty())
	{
		ss << LAZY_RTSP_TOKEN_USER_AGENT << LAZY_CONST_COSP << m_suser_agent << LAZY_CONST_CRLF;
	}
	ss << LAZY_RTSP_TOKEN_DATE << LAZY_CONST_COSP << Date() << LAZY_CONST_CRLF;
	if (!m_scontent_base.empty())
	{
		ss << LAZY_RTSP_TOKEN_CONTENT_BASE << LAZY_CONST_COSP << m_scontent_base << LAZY_CONST_CRLF;
	}

	if (m_dstart_range >= 0)
	{
		ss << LAZY_RTSP_TOKEN_RANGE << LAZY_CONST_COSP << "npt=" << m_dstart_range << "-";
		if (m_dstop_range > m_dstart_range)
		{
			ss << m_dstop_range;
		}
		ss << LAZY_CONST_CRLF;
	}

	if(m_ptransport)
	{
		ret = m_ptransport->encode(ss);
		CHECK_RESULT(ret);
	}
	if(m_pauthorization)
	{
		ret = m_pauthorization->encode(ss);
		CHECK_RESULT(ret);
	}
	if (!m_ssession.empty())
	{
		ss << LAZY_RTSP_TOKEN_SESSION << LAZY_CONST_COSP << m_ssession << LAZY_CONST_CRLF;
	}
	return 0;
}

int lazy_rtsp_command::encode_extra_tokens(stringstream& ss)
{
	return 0;
}

int lazy_rtsp_command::encode_content(stringstream& ss)
{
	return 0;
}

lazy_rtsp_command* lazy_rtsp_command::parser_command(string com_str)
{
	string method;
	lazy_rtsp_command* prc = NULL;
	int ret = string_split(com_str, method, " ");
	if (ret < 0)
	{
		lberror("Invalid com_str:%s, split method failed\n", com_str.c_str());
		return NULL;
	}

	if (LAZY_RTSP_VERSION == method)
	{
		prc = new lazy_rtsp_response_command();
	}
	else if (LAZY_METHOD_OPTIONS == method)
	{
		prc = new lazy_rtsp_request_command();
	}
	else if (LAZY_METHOD_DESCRIBE == method)
	{
		prc = new lazy_rtsp_response_option();
	}

	ret = prc->decode(com_str);
	if (ret < 0)
	{
		lberror("Invalid com_str:%s, prc->decode failed ret:%d\n", com_str.c_str(), ret);
		return NULL;
	}

	return prc;
}

int lazy_rtsp_command::decode(string com_str)
{
	lbdebug("decode(%s)\n", com_str.c_str());
	int ret = 0;
	// split command token and content from string
	vector<string> vstrlist = string_splits(com_str, "\r\n\r\n");
	if (vstrlist.size() <= 0)
	{
		lberror("Invalid rtsp command, empty tokens");
	}
	/*int ret = decode_header(com_str);
	CHECK_RESULT(ret);
	lbdebug("decoder tokens: com_str:%s\n", com_str.c_str());*/
	

	// decode token list
	if (vstrlist.size() > 0)
	{
		lbdebug("token list:%s\n", vstrlist[0].c_str());
		vector<string> tokenlist = string_splits(vstrlist[0], LAZY_CONST_CRLF);
		on_decode_header(tokenlist[0]);
		for (size_t i = 0; i < tokenlist.size(); i++)
		{
			vector<string> token_map = string_splits(tokenlist[i], LAZY_CONST_COSP);
			if (token_map.size() != 2)
			{
				lberror("Invalid token, tokenlist[i:%d]:%s", i, tokenlist[i].c_str());
				return -1;
			}
			else
			{
				m_mtoken_list[token_map[0]] = token_map[1];
				ret = on_decode_token(token_map[0], token_map[1]);
				lbdebug("ret:%d = on_decode_token(token_map[0]:%s, token_map[1]:%s)\n", ret, token_map[0].c_str(), token_map[1].c_str());
				CHECK_RESULT(ret);
			}
		}
	}

	// decode content body
	if (vstrlist.size() > 1)
	{
		ret = decode_content(vstrlist[1]);
		lbdebug("ret:%s = decode_content(vstrlist[1]:%s)\n", ret, vstrlist[1].c_str());
		CHECK_RESULT(ret);
	}

	return ret;
}

int lazy_rtsp_command::decode_header(string& com_str)
{
	string header;
	int ret = string_split(com_str, header, LAZY_CONST_CRLF);
	CHECK_RESULT(ret);
	vector<string> hdrlist = string_splits(header, " ");
	if (hdrlist.size() < 2)
	{
		lberror("Invalid rtsp command header:%s, com_str:%s, decode_header failed\n", header.c_str(), com_str.c_str());
		return -1;
	}

	if (hdrlist[0] == m_sprotocol_version)
	{
		m_ecommon_type = e_common_type_response;
		m_smethod = LAZY_METHOD_RESPONSE;

	}

	return 0;
}

int lazy_rtsp_command::decode_content(string& content)
{
	return 0;
}

int lazy_rtsp_command::on_decode_token(string token, string value)
{
	m_mtoken_list[token] = value;
	if(LAZY_RTSP_TOKEN_CSEQ == token)
	{
		m_nseq = atoi(value.c_str());
	}
	else if(LAZY_RTSP_TOKEN_DATE == token)
	{
		m_sdate_time = value;
	}
	else if(LAZY_RTSP_TOKEN_DATE == token)
	{
		m_suser_agent = value;
	}
	else if(LAZY_RTSP_TOKEN_CONTENT_TYPE == token)
	{
		m_scontent_type = value;
	}
	else if(LAZY_RTSP_TOKEN_CONTENT_LENGTH == token)
	{
		m_ncontent_len = atoi(value.c_str());
	}
	else if(LAZY_RTSP_TOKEN_CONTENT_BASE == token)
	{
		m_scontent_base = value;
	}
	else if(LAZY_RTSP_TOKEN_SESSION ==  token)
	{
		std::vector<string> vstrlist = string_splits(value, ";");
		m_ssession = vstrlist[0];
		if(vstrlist.size() > 1)
		{
			m_nsession_time = atoi(vstrlist[1]);
		}
	}
	else if(LAZY_RTSP_TOKEN_RANGE ==  token)
	{
		string range = value;
		vector<string> vrang_list = string_splits(value, "=");
		if(vrang_list.size() < 2)
		{
			lberror("Invalid rtsp range %s", value.c_str());
			return -1;
		}
		vector<string> vrang_val  = string_splits(vrang_list[1], "-");
		if(vrang_val.size() < 1)
		{
			lberror("Invalid rtsp range %s", value.c_str());
			return -1;
		}

		m_dstart_range = atof(vrang_val[0]);
		if(vrang_val.size() >= 2)
		{
			m_dstop_range = atof(vrang_val[1]);
		}
		else
		{
			m_dstop_range = 0; 
		}
	}
	else if(LAZY_RTSP_TOKEN_ACCEPT ==  token)
	{
		m_saccept_type = value;
	}
	return 0;
}

int lazy_rtsp_command::create_tcp_transport(striing lower_transport, int rtp_channel_id, int rtcp_channel_id)
{
	m_ptransport = new lazy_rtsp_transport();
	int ret = m_ptransport->init(lower_transport, rtp_channel_id, rtcp_channel_id);

	return ret;
}

int lazy_rtsp_command::create_upd_transport(int rtp_channel_port, int rtcp_channel_port)
{
	m_ptransport = new lazy_rtsp_transport();
	int ret = m_ptransport->init("UDP", rtp_channel_port, rtcp_channel_port);

	return ret;
}

int lazy_rtsp_command::add_token(irtsp_token_codec* prtc)
{
	if(NULL == prtc)
	{
		return -1;
	}

	m_vtoken_list.push_back(prtc);

	return 0;
}

lazy_rtsp_request_command::lazy_rtsp_request_command(string method, string url):lazy_rtsp_command(e_common_type_request)
{
	m_smethod = method;
	m_surl = url;
}

lazy_rtsp_request_command::~lazy_rtsp_request_command()
{

}

int lazy_rtsp_request_command::on_encode_header(stringstream& ss)
{
	// rtsp request format:$(m_smethod) $(m_surl) $(m_sprotocol_version)
	ss << m_smethod << LAZY_CONST_SP << m_surl << LAZY_CONST_SP << m_sprotocol_version << LAZY_CONST_CRLF;
	return 0;
}

int lazy_rtsp_request_command::on_decode_header(string& cmd_str)
{
	std::vector<string> vhdrlist = string_splits(cmd_str);
	if(vlist.size() < 3)
	{
		lberror("Invalid rtsp header %s\n", cmd_str.c_str());
		return -1;
	}

	m_smethod == vhdrlist[0];
	m_surl = vhdrlist[1];
	m_sprotocol_version = vdhrlist[2];
	assert(m_sprotocol_version == LAZY_RTSP_VERSION);
	lbdebug("m_smethod:%s, m_surl:%s, m_sprotocol_version:%s\n", m_smethod.c_str(), m_surl.c_str(), m_sprotocol_version.c_str());
	return 0;
}
lazy_rtsp_response_command::lazy_rtsp_response_command(int seq) :lazy_rtsp_command(e_common_type_response, seq)
{
	m_nstatus_code = -1;
}

lazy_rtsp_response_command::lazy_rtsp_response_command(int status_code, string status_msg, int seq):lazy_rtsp_command(e_common_type_response, seq)
{
	m_nstatus_code	= status_code;
	m_sstatus_msg	= status_msg;
}

lazy_rtsp_response_command::~lazy_rtsp_response_command()
{
}

int lazy_rtsp_response_command::encode_header(stringstream& ss)
{
	// rtsp response format:$(m_sprotocol)/$(m_sversion) $(m_nstatus_code) $(m_sstatus_msg)
	ss << m_sprotocol_version << LAZY_CONST_SP << m_nstatus_code << LAZY_CONST_SP << m_sstatus_msg << LAZY_CONST_CRLF;
	return 0;
}

lazy_rtsp_response_option::lazy_rtsp_response_option(int status_code, string status_msg, int seq):lazy_rtsp_e_command(status_code, status_msg, seq)
{
	//m_spublic_method = public_method;
	m_vmethod_option.push_back(LAZY_METHOD_OPTIONS);
	m_vmethod_option.push_back(LAZY_METHOD_DESCRIBE);
	m_vmethod_option.push_back(LAZY_METHOD_SETUP);
	m_vmethod_option.push_back(LAZY_METHOD_PLAY);
	m_vmethod_option.push_back(LAZY_METHOD_TEARDOWN);
}

lazy_rtsp_response_option::~lazy_rtsp_response_option()
{
}

int lazy_rtsp_response_option::encode_extra_body(stringstream& ss)
{
	ss << LAZY_RTSP_TOKEN_PUBLIC << ":";
	for(size_t i = 0; i < m_vmethod_option.size(); i++)
	{
		ss << LAZY_CONST_SP << m_vmethod_option[i];
	}
	ss << LAZY_CONST_CRLF;
	return 0;
}

lazy_rtsp_describe_response::lazy_rtsp_describe_response(int status_code, string status_msg)
{
	m_nstatus_code = status_code;
	m_sstatus_msg = status_msg;

}

lazy_rtsp_describe_response::~lazy_rtsp_describe_response()
{

}

int lazy_rtsp_describe_response::gen_md5_by_time(string address, string session_name, string media_title)
{
	m_slocal_address	= address;
	m_ssession_name		= session_name;
	m_smedia_title		= media_title;

	m_psdp = new session_description_protocol();
	int ret = m_psdp->init(session_name, media_title, address);
	return ret;
}

int lazy_rtsp_describe_response::add_media_description(string mt, int pt, int port, int bitrate, string track_name)
{
	CHECK_PARAM_PTR(m_psdp, -1);
	char* pcodec_name = NULL;//LAZY_RTSP_H264_CODEC_NAME;
	if(LAZY_RTSP_H264_PAYLOAD_TYPE == pt)
	{
		pcodec_name = LAZY_RTSP_H264_CODEC_NAME;
	}
	else if(LAZY_RTSP_H264_PAYLOAD_TYPE == pt)
	{
		pcodec_name = LAZY_RTSP_AAC_CODEC_NAME;
	}
	else
	{
		lberror("Invalid payload type %d, not support payload type\n", pt);
		return -1;
	}
	int ret = m_psdp->add_media_description(mt, pt, port, pcodec_name, bitrate, track_name);
	lbdebug("ret:%d = m_psdp->add_media_description(mt:%d, pt:%d, port:%d, pcodec_name:%s, bitrate:%d, track_name:%s)\n", ret, mt, pt, port, pcodec_name, bitrate, track_name.c_str());
	return ret;
}

int lazy_rtsp_describe_response::set_sequence_header(int pt, uint8_t* pcfg1, int cfg1_len, uint8_t* pcfg2, int cfg2_len)
{
	CHECK_PARAM_PTR(pcfg1, -1);
	lbdebug("set_sequence_header(pt:%d, pcfg1:%p, cfg1_len:%d, pcfg2:%p, cfg2_len:%d)\n", pt, pcfg1, cfg1_len, pcfg2, cfg2_len);
	return m_psdp->set_codec_config(pt, pcfg1, cfg1_len, pcfg2, cfg2_len);
}

int lazy_rtsp_describe_response::add_media_audio(string mt, int port, int pt, int bitrate, string track_name, uint8_t* pcfg, int cfg_len)
{
	CHECK_PARAM_PTR(m_psdp, -1);
	char* pcodec_name = NULL;//LAZY_RTSP_H264_CODEC_NAME;
	if(LAZY_RTSP_H264_PAYLOAD_TYPE == pt)
	{
		pcodec_name = LAZY_RTSP_H264_CODEC_NAME;
	}
	else if(LAZY_RTSP_H264_PAYLOAD_TYPE == pt)
	{
		pcodec_name = LAZY_RTSP_AAC_CODEC_NAME;
	}
	else
	{
		lberror("Invalid payload type %d, not support payload type\n", pt);
		return -1;
	}
	int ret = m_psdp->add_media_description(mt, pt, port, pcodec_name, bitrate, track_name);
	lbdebug("ret:%d = m_psdp->add_media_description(mt:%d, pt:%d, port:%d, pcodec_name:%s, bitrate:%d, track_name:%s)\n", ret, mt, pt, port, pcodec_name, bitrate, track_name.c_str());
	return ret;
}

int lazy_rtsp_describe_response::on_encode_content(stringstream& ss)
{
	/*struct timeval tv;
    gettimeofday(&tv, NULL);
	ss << "v=0" << LAZY_CONST_CRLF
	<< "o=- " << string_format("%ld%06ld ", tv.tv_sec, tv.tv_usec) << m_nsession_version << */
	CHECK_PARAM_PTR(m_psdp, -1);

	int ret = m_psdp->encode(ss);

	return ret;
}

int on_decode_content(string sdp)
{
	m_psdp = new session_description_protocol();
	m_psdp->
}

lazy_rtsp_stack::lbsp_rtsp_stack()
{
	m_pbuf_skt = NULL;
	m_pbuf = new char[1500];
	m_nbuf_size = 1500;
}


lazy_rtsp_stack::~lbsp_rtsp_stack()
{
}

int lazy_rtsp_stack::init_socket(iread_write_handle* pskt)
{
	close();
	m_pbuf_skt = new lbsp_socket_buffer(pskt);

	return 0;
}

int lazy_rtsp_stack::start()
{
	return lazy_thread::start(0);
}
	
int lazy_rtsp_stack::stop()
{
	return lazy_thread::stop();
}

void lazy_rtsp_stack::close()
{
	if(m_pbuf_skt)
	{
		delete m_pbuf_skt;
		m_pbuf_skt = NULL;
	}
}

int lazy_rtsp_stack::on_cycle()
{
	if(NULL == m_pbuf_skt)
	{
		lberror("Invalid parameter m_pbuf_skt:%p\n", m_pbuf_skt);
		return -1;
	}

	int ret = m_pbuf_skt->read(m_pbuf, m_nbuf_size);
	CHECK_RESULT(ret);
	ret = parser_common(m_pbuf, ret);
	CHECK_RESULT(ret);
	return ret;
}

int lazy_rtsp_stack::send_message(lazy_rtsp_command* pcommon)
{
	char buf[4096] = {0};
	int ret = pcommon->encode(buf, 4096);
	CHECK_RESULT(ret);

	ret = send_data(buf, ret);
	CHECK_RESULT(ret);
	return ret;
}

int lazy_rtsp_stack::send_rtp_packet(packet_buffer* pkt)
{
	int ret = send_data(pkt->bytes(), pkt->length());
	CHECK_RESULT(ret);

	return ret;
}
#define RETRY_NUM 10

int lazy_rtsp_stack::send_data(void* pdata, int len)
{
	CHECK_PARAM_PTR(m_pread_write_handle, -1);
	int remain = len;
	int pos = 0;
	int trynum = 0;
	uint8_t* pbuf = (uint8_t*)pdata;
	while (remain > 0)
	{
		int writed = m_pread_write_handle->write(pbuf + pos, remain);
		if (writed <= 0)
		{
			//EINTR:指操作被中断唤醒，需要重新读/写, EAGAIN:非阻塞模式下调用了阻塞操作，操作没有完成，重试一次
			if (trynum++ < RETRY_NUM && (EAGAIN == errno || EINTR == errno || EWOULDBLOCK == errno))
			{
				//sv_warn("write msg timeout:%"PRId64", sendtime:%lu, reason:%s", m_llWriteTimeout, GetSysTime() - begin, strerror(errno));
				int waittime_ms = 50;
#ifdef WIN32
				Sleep(waittime_ms);
#else
				st_usleep(waittime_ms * 1000);
#endif
				continue;
			}
			lberror("writed:%d = ::send(pbuf:%p + pos:%d, remain:%d) failed! reason:%s, trynum:%d\n", writed, pbuf, pos, remain, strerror(errno), trynum);
			return -1;
		}
		remain = remain - writed;
		pos += writed;
		//m_lwrite_bytes += writed;
	};
	return pos;
}

int lazy_rtsp_stack::recv_data(void* pdata, int len)
{
	return m_pread_write_handle->read(pdata, len);
}

int lazy_rtsp_stack::parser_common(char* pcmd, int len)
{
	int ret = 0;
	CHECK_PARAM_PTR(pcmd, -1);

	if(*pcmd == 0x24)
	{
		// rtsp over tcp packet

	}
	else if(strstr(pcmd, LAZY_CONST_CRLFCRLF))
	{
		char* pver_pos = strstr(pcmd, LAZY_RTSP_VERSION);
		if(pcmd == pver_pos)
		{
			// rtsp response 
		}
		else
		{
			// rtsp request
			char resp_buf[1024] = {0};
			int len = 0;
			lazy_rtsp_response_command* presp = NULL;
			lazy_rtsp_request_command req;
			ret = req->decode(pcmd, len);
			CHECK_RESULT(ret);
			if(LAZY_METHOD_OPTIONS == req.m_smethod)
			{
				presp = new lazy_rtsp_response_option(200, "OK", req.m_nseq);
				rtsp_public_option* pres_option = new rtsp_public_option();
				pres_option->add_method(LAZY_METHOD_OPTIONS);
				pres_option->add_method(LAZY_METHOD_DESCRIBE);
				pres_option->add_method(LAZY_METHOD_SETUP);
				pres_option->add_method(LAZY_METHOD_PLAY);
				pres_option->add_method(LAZY_METHOD_TEARDOWN);
				pres_option->add_method(LAZY_METHOD_GET_PARAMETER);
				pres_option->add_method(LAZY_METHOD_SET_PARAMETER);
				ret = presp->add_token(pres_option);
				CHECK_RESULT(ret);
			}
			else if(LAZY_METHOD_DESCRIBE == req.m_smethod)
			{
				string rtsp_media_title;
				presp = new lazy_rtsp_describe_response(200, "OK", req.m_nseq);
				string local_ip = srs_get_local_ip(m_pread_write_handle->get_socket(), NULL);
				size_t pos = req->m_surl.find_last_of("/");
                if(std::string::npos != pos)
                {
                    rtsp_media_title = req->m_surl.substr(pos+1);
                }
				ret = presp->init_sdp(local_ip, "raw h264 and aac stream, streamed by lazy rtsp media server", rtsp_media_title);
				CHECK_RESULT(ret);
				rtp_channel_info* pvrci = new rtp_channel_info();
				pvrci->m_smedia_type = "video";
				pvrci->m_npt = LBSP_PAYLOAD_TYPE_H264;
				pvrci->m_nbitrate = 1000;
				pvrci->m_strack_name = "track1";
				pvrci->m_nrtp_channe_id = 0;
				pvrci->m_nrtcp_channe_id = 1;
				m_mchannel_list[pvrci->m_npt] = pvrci;
				ret = presp->add_media_description(pvrci->m_smedia_type, pvrci->m_npt, 0, pvrci->m_nbitrate, pvrci->m_strack_name);
				CHECK_RESULT(ret);

				rtp_channel_info* parci = new rtp_channel_info();
				parci->m_smedia_type = "audio";
				parci->m_npt = LBSP_PAYLOAD_TYPE_AAC;
				parci->m_nbitrate = 128;
				parci->m_strack_name = "track2";
				parci->m_nrtp_channe_id = 2;
				parci->m_nrtcp_channe_id = 3;
				m_mchannel_list[parci->m_npt] = parci;
				ret = presp->add_media_description(parci->m_smedia_type, parci->m_npt, 0, parci->m_nbitrate, parci->m_strack_name);
				CHECK_RESULT(ret);
				m_ssession = string_format("%0x", get_random_int());
			}
			else if(LAZY_METHOD_ANNOUNCE == req.m_smethod)
			{
				return -1;
			}
			else if(LAZY_METHOD_SETUP == req.m_smethod)
			{
				string track_name;
				presp = new lazy_rtsp_response_command(200, "OK", req.m_nseq);
				size_t pos = req->m_surl.find_last_of("/");
                if(std::string::npos != pos)
                {
                    track_name = req->m_surl.substr(pos+1);
                }
				rtp_channel_info* prci = find_channel_info_by_track_name(track_name);
				if(NULL == prci)
				{
					lberror("Invalid track name %s, not rtp channel info found\n", track_name.c_str());
					return -1;
				}

				lazy_rtsp_transport* ptp = new lazy_rtsp_transport();
				ret = ptp->init("TCP", prci->m_nrtp_channe_id, prci->m_nrtcp_channe_id);
				CHECK_RESULT(ret);
				presp->m_ssession = m_ssession;
				ret = presp->add_token(ptp);
				CHECK_RESULT(ret);
			}
			else if(LAZY_METHOD_PLAY == req.m_smethod)
			{
				presp = new lazy_rtsp_response_command(200, "OK", req.m_nseq);
				presp->m_dstart_range = 0.000;
				presp->m_ssession = m_ssession;

				rtp_play_info* prpi = new rtp_play_info();
				map<int, rtp_channel_info*>::iterator it = m_mchannel_list.begin(); it != m_mchannel_list.end(); it++)
				{
					t->second->useq_num = 0;
					t->second->m_urtp_timestamp = 0;
					string url = req->m_surl + "/" + it->second->m_strack_name;
					ret = prpi->add_track(url, t->second->useq_num, t->second->m_urtp_timestamp);
					CHECK_RESULT(ret);
				}

			}
			else if(LAZY_METHOD_TEARDOWN == req.m_smethod)
			{
				presp = new lazy_rtsp_response_command(200, "OK", req.m_nseq);
			}
			else
			{
				lberror("Unknown rtsp command %s\n", pcmd);
				return 0;
			}
			len = resp.encode(resp_buf, 1024);
			CHECK_RESULT(len);

			ret = m_pread_write_handle->write(resp_buf, len);
			CHECK_RESULT(ret);
			return ret;
		}
	
		// rtsp response
	}
	
	return 0;
}

rtp_channel_info* lazy_rtsp_stack::find_channel_info_by_track_name(string track_name)
{
	map<int, rtp_channel_info*>	::iterator it = m_mchannel_list.begin();
	for(; it != m_mchannel_list.end(); it++)
	{
		if(it->second && track_name == it->second->m_strack_name)
		{
			return it->second;
		}
	}

	return NULL;
}

string lazy_rtsp_stack::get_track_name_from_url(string url)
{
	url.find_last_
}