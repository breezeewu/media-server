#include "tls_socket.hpp"
#include <ios>
#include <sstream>
#include <srs_core.hpp>
#define HTTPS_PARSER_JSON
#ifdef HTTPS_PARSER_JSON
#include <srs_protocol_json.hpp>
#include <srs_core_autofree.hpp>
#endif
#define HTTP_CLIENT_TIMEOUT_US (int64_t)(30*1000*1000LL)
#define SRS_HTTP_CRLF "\r\n" // 0x0D0A
#define SRS_HTTP_CRLFCRLF "\r\n\r\n" // 0x0D0A0D0A
class https_client//:public IHttpClient
{
public:
    https_client()
    {
        m_phttp_socket = NULL;
        m_nport = 0;
    }
    ~https_client()
    {
        disconnect();
    }

    virtual int initialize(std::string uri, int64_t timeout_us = HTTP_CLIENT_TIMEOUT_US)
    {
        std::string path = uri;
        size_t pos = url_split(path, m_sschema, (const char*)"://");
        if(std::string::npos == pos)
        {
            lberror("invalid http uri:%s while parser ://!\n", path.c_str());
            return -1;
        }

        pos = url_split(path, m_shost, (const char*)":");
        if(std::string::npos == pos)
        {
           if(std::string("https") == m_sschema)
            {
                m_nport = 443;
            }
            else if(std::string("http") == m_sschema)
            {
                m_nport = 80;
            }
            else
            {
                lberror("Invalid http uri:%s while parser schema\n", uri.c_str());
                return -1;
            }
            pos = url_split(path, m_shost, (const char*)"/");
            if(std::string::npos == pos)
            {
                lberror("invalid http uri:%s while parser host!\n", uri.c_str());
                return -1;
            }
        }
        else
        {
            std::string sport;
            pos = url_split(path, sport, (const char*)"/");
            if(std::string::npos == pos)
            {
                lberror("invalid http uri:%s while parser port!\n", uri.c_str());
                return -1;
            }
            m_nport = atoi(sport.c_str());
        }

        pos = url_split(path, m_shttp_path, (const char*)"?");
        if(std::string::npos == pos)
        {
            m_shttp_path = path;
        }
        m_shttp_query = path;
        m_lltimeout_us = timeout_us;
        m_surl = uri;
        lbtrace("parser http request success, m_sschema:%s, m_shost:%s, m_nport:%d, m_shttp_path:%s, m_shttp_query:%s\n", m_sschema.c_str(), m_shost.c_str(), m_nport, m_shttp_path.c_str(), m_shttp_query.c_str());
        return 0;
    }

    /*virtual int initialize(std::string host, int p, int64_t timeout_us = SRS_HTTP_CLIENT_TIMEOUT_US)
    {
        m_shost = host;
        m_nport = p;
        m_lltimeout_us = timeout_us;
        
        lbtrace("parser http request success, m_sschema:%s, m_shost:%s, m_nport:%d, m_shttp_path:%s, m_shttp_query:%s\n", m_sschema.c_str(), m_shost.c_str(), m_nport, m_shttp_path.c_str(), m_shttp_query.c_str());
        return 0;
    }*/

    virtual int post_request_and_get_response(std::string req, std::string& resp)
    {
        int ret = 0;
        if(!m_phttp_socket)
        {
            ret = connect(m_shost, m_nport);
            if( ret < 0 || NULL == m_phttp_socket)
            {
                lberror("connect failed, m_phttp_socket:%p, ret:%d\n", m_phttp_socket, ret);
                return 0;
            }
        }
        lbtrace("post request %lu bytes req %s\n", req.length(), req.c_str());
        ret = m_phttp_socket->write((char*)req.c_str(), (int)req.length());
        if(ret < 0)
        {
            lberror("write %s post %s failed, ret:%d\n", m_sschema.c_str(), req.c_str(), ret);
            disconnect();
            return ret;
        }
        std::string res;
        
        //int recv_len = 0;
        while(1)
        {
            char buff[256] = {0};
            lbtrace("before ret:%d = m_phttp_socket->read(buff, 256)\n", ret);
            ret = m_phttp_socket->read(buff, 256);
            //lbtrace("ret:%d = m_phttp_socket->read(buff, 256)\n", ret);
            if(ret <= 0)
            {
                lberror("ret:%d = m_phttp_socket->read(resp, 256) failed", ret);
                break;
            }
            res.append(buff);
            if(memcmp("\r\n\r\n", res.c_str() + res.length() - 4, strlen("\r\n\r\n")) == 0)
            {
                break;
            }
        }
        if(res.empty())
        {
            lberror("post %s failed, recv nothing!", m_sschema.c_str());
            return -1;
        }
        lbtrace("post request recv response %s\n", res.c_str());
        size_t begin_pos = res.find_first_of("{");
        size_t end_pos = res.find_last_of("}");
	    if(std::string::npos == begin_pos || std::string::npos == end_pos || end_pos <= begin_pos)
        {
            lberror("post %s find { or } failed, begin_pos:%ld, end_pos:%ld\n", m_shttp_path.c_str(), begin_pos, end_pos);
            return -1;
        }

        resp = res.substr(begin_pos, end_pos);
        lbtrace("response body:%s\n", resp.c_str());
        return 0;
    }
    /**
    * to post specify format data to the uri.
    * @param the path to request on.
    * @param req the data post to uri. empty string to ignore.
    * @param ppmsg output the http message to read the response.
    */
    virtual int post(std::string contenttype, std::string req, int& stateCode, std::string& resp)
    {
        int ret = 0;
        if(!m_phttp_socket)
        {
            ret = connect(m_shost, m_nport);
            if( ret < 0 || NULL == m_phttp_socket)
            {
                lberror("connect failed, m_phttp_socket:%p, ret:%d\n", m_phttp_socket, ret);
                return ret;
            }
           
        }
        char name[256] = {0};
	    gethostname(name, sizeof(name));
        std::string slocal_host_name(name);
        std::stringstream ss;
        ss << "POST /" << m_shttp_path << " "
        << "HTTP/1.1" << SRS_HTTP_CRLF
        << "Host: " << m_shost << SRS_HTTP_CRLF
        << "Connection: Keep-alive" << SRS_HTTP_CRLF
        << "Content-Length: " << std::dec << req.length() << SRS_HTTP_CRLF
        //<< "User-Agent: " << "srs server" << "0.8.8" << SRS_HTTP_CRLF
        << "User-Agent: " << RTMP_SIG_SRS_NAME << RTMP_SIG_SRS_VERSION << SRS_HTTP_CRLF
        << "srs-server-host: "<< slocal_host_name << SRS_HTTP_CRLF
        //<< "x-forwarded-for: "<< slocal_host_name << SRS_HTTP_CRLF
        << "Content-Type: "<< contenttype << SRS_HTTP_CRLF
        << SRS_HTTP_CRLF
        << req;
    
        std::string data = ss.str();
        //data += req;
        /*char posturi[1024] = {0};
        sprintf(posturi, "POST /ipc/connection/token/get HTTP/1.1\r\nHost: storage-sit.sunvalleycloud.com\r\nConnection: keep-alive\r\nContent-Length: %d\r\nUser-Agent: cloud_push_sdk/1.0.0\r\nContent-Type: %s\r\n\r\n", 
        req.length(), "application/json");
        strcat(posturi, req.c_str());
        std::string data = posturi;*/
        lbtrace("%s post %lu bytes request:%s", m_sschema.c_str(), data.length(), data.c_str());
        ret = m_phttp_socket->write((char*)data.c_str(), (int)data.length());
        if(ret < 0)
        {
            lberror("write %s post failed, ret:%d\n", m_sschema.c_str(), ret);
            disconnect();
            return ret;
        }
        std::string res;
        
        //int recv_len = 0;
        while(1)
        {
            char buff[256] = {0};
            ret = m_phttp_socket->read(buff, 256);
            //lbtrace("ret:%d = m_phttp_socket->read(buff:%s, 256)\n", ret, buff);
            if(ret <= 0)
            {
                lberror("ret:%d = m_phttp_socket->read(resp, 256) failed", ret);
                break;
            }
            res.append(buff);
            if(memcmp("\r\n\r\n", res.c_str() + res.length() - 4, strlen("\r\n\r\n")) == 0)
            {
                break;
            }
        }
        if(res.empty())
        {
            lberror("post %s failed, recv nothing!", m_sschema.c_str());
            return -1;
        }

        lbtrace("post request recv response %s\n", res.c_str());
        size_t begin_pos = res.find_first_of("{");
        size_t end_pos = res.find_last_of("}");
	    if(std::string::npos == begin_pos || std::string::npos == end_pos || end_pos <= begin_pos)
        {
            lberror("post %s find { or } failed, begin_pos:%lu, end_pos:%lu\n", m_shttp_path.c_str(), begin_pos, end_pos);
            return -1;
        }

        resp = res.substr(begin_pos, end_pos + 1);
        lbtrace("response body:%s\n", resp.c_str());
#ifdef HTTPS_PARSER_JSON
        SrsJsonAny* info = SrsJsonAny::loads((char*)resp.c_str());
        if (!info) {
            //ret = ERROR_JSON_STRING_PARSER_FAIL;
            lberror("invalid response info:%p. res=%s", info, resp.c_str());
            return ERROR_JSON_LOADS;
        }
        SrsAutoFree(SrsJsonAny, info);
    
        // response error code in string.
        if (!info->is_object()) {
            /*if (ret != ERROR_SUCCESS) {
                lberror("invalid response number, info:%p", info);
                return ;
            }*/
            lberror("invalid object !info->is_object()");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
    
        // parser json result
        SrsJsonObject* res_info = info->to_object();
        SrsJsonAny* result = NULL;
        if ((result = res_info->ensure_property_integer("stateCode")) == NULL) {
            lberror("invalid response while parser stateCode without stateCode, result:%p", result);
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        stateCode = (int)result->to_integer();
        //srs_verbose("before  res_info->ensure_property_string(stateMsg)");
        if ((result = res_info->ensure_property_string("stateMsg")) == NULL) {
            lberror("invalid response while parser push_ts without stateMsg, result:%p, statecode:%d", result, stateCode);
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        //srs_verbose("before  statemsg = result->to_str()");
        std::string statemsg = result->to_str();
        srs_trace("post get response stateCode:%d, statemsg:%s\n", stateCode, statemsg.c_str());
#endif
        return resp.length() > 0 ? 0 : -1;
    }

    int parser_http_url(std::string url, std::string* pschema, std::string* phost, int* pport, std::string* ppath, std::string* pquery = NULL)
    {
        std::string uri = url;
        std::string schema;
        std::string host;
        std::string path;
        std::string query;
        int port;
        size_t pos = url_split(uri, schema, (const char*)"://");
        if(std::string::npos == pos)
        {
            lberror("invalid http uri:%s while parser ://!\n", uri.c_str());
            return -1;
        }

        pos = url_split(uri, m_shost, (const char*)":");
        if(std::string::npos == pos)
        {
           if(std::string("https") == schema)
            {
                port = 443;
            }
            else if(std::string("http") == schema)
            {
                port = 80;
            }
            else
            {
                lberror("Invalid http url:%s while parser schema\n", url.c_str());
                return -1;
            }
            pos = url_split(uri, host, (const char*)"/");
            if(std::string::npos == pos)
            {
                lberror("invalid http url:%s while parser host!\n", url.c_str());
                return -1;
            }
        }
        else
        {
            std::string sport;
            pos = url_split(uri, sport,(const char*)"/");
            if(std::string::npos == pos)
            {
                lberror("invalid http url:%s while parser port!\n", url.c_str());
                return -1;
            }
            port = atoi(sport.c_str());
        }

        pos = url_split(uri, path, (const char*)"?");
        if(std::string::npos == pos)
        {
            //lberror("invalid http url:%s while parser http path!\n", url.c_str());
            //return -1;
            path = uri;
        }
        query = uri;
        if(pschema)
        {
            *pschema = schema;
        }
        if(phost)
        {
            *phost = host;
        }
        if(pport)
        {
            *pport = port;
        }
        if(ppath)
        {
            *ppath = path;
        }
        
        if(pquery)
        {
            *pquery = query;
        }

        lbtrace("parser http request success, schema:%s, host:%s, port:%d, path:%s, query:%s\n", schema.c_str(), host.c_str(), port, path.c_str(), query.c_str());
        return 0;
    }
    /**
    * to get specify format data from the uri.
    * @param the path to request on.
    * @param req the data post to uri. empty string to ignore.
    * @param ppmsg output the http message to read the response.
    */
    virtual int get(std::string contenttype, std::string req, std::string res)
    {
        int ret = 0;
        if(!m_phttp_socket)
        {
            ret = connect(m_shost, m_nport);
            if( ret < 0 || NULL == m_phttp_socket)
            {
                lberror("connect failed, m_phttp_socket:%p, ret:%d\n", m_phttp_socket, ret);
                return 0;
            }
           
        }
        // send GET request to uri
        // GET %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s
        std::stringstream ss;
        ss << "GET /" << m_shttp_path << " "
            << "HTTP/1.1" << SRS_HTTP_CRLF
            << "Host: " << m_shost << SRS_HTTP_CRLF
            << "Connection: Keep-Alive" << SRS_HTTP_CRLF
            << "Content-Length: " << std::dec << req.length() << SRS_HTTP_CRLF
            << "User-Agent: " << "srs server" << "0.5.0.3" << SRS_HTTP_CRLF
            //<< "User-Agent: " << RTMP_SIG_SRS_NAME << RTMP_SIG_SRS_VERSION << SRS_HTTP_CRLF
            << "Content-Type: " << contenttype << SRS_HTTP_CRLF
            << SRS_HTTP_CRLF
            << req;

        std::string data = ss.str();
        ret = m_phttp_socket->write((char*)data.c_str(), data.length());
        if(ret < 0)
        {
            lberror("ret:%d = m_phttp_socket->write((char*)data.c_str():%s, data.length():%lu)\n", ret, data.c_str(), data.length());
            return  ret;
        }

        while(1)
        {
            char buff[256] = {0};
            ret = m_phttp_socket->read(buff, 256);
            if(ret < 0)
            {
                lberror("ret:%d = m_phttp_socket->read(resp, 1024) failed", ret);
                break;
            }
            res.append(buff);
            if(memcmp("\r\n\r\n", res.c_str() + res.length() - 4, strlen("\r\n\r\n")) == 0)
            {
                break;
            }
        }
        if(res.empty())
        {
            lberror("post %s failed, recv nothing!", m_sschema.c_str());
            return -1;
        }
        lbtrace("post request recv response %s\n", res.c_str());
        return 0;
    }

protected:
    int connect(std::string host, int port = 0)
    {
        int ret = 0;
        if(m_sschema == "https")
        {
            CTLSSocket* ptls_socket = new CTLSSocket(TLS_CLIENT_VERSION_TOP_MOST);
            LB_ADD_MEM(ptls_socket, sizeof(CTLSSocket));
            lbtrace("ptls_socket:%p = new CTLSSocket(TLS_CLIENT_VERSION_TOP_MOST)\n", ptls_socket);
            //ret = ptls_socket->init_cert(TLS_CLIENT_VERSION_TOP_MOST);
            if(ret < 0)
            {
                lbtrace("ret:%d = ptls_socket->init_cert(TLS_CLIENT_VERSION_TOP_MOST)\n", ret);
                return ret;
            }
            m_phttp_socket = ptls_socket;
        }
        else
        {
            CTCPSocket* ptcp_socket = new CTCPSocket();
            LB_ADD_MEM(ptcp_socket, sizeof(CTCPSocket));
            m_phttp_socket = ptcp_socket;
        }
        
        ret = m_phttp_socket->init_socket();
        if(ret < 0)
        {
            lbtrace("ret:%d = m_phttp_socket->init_socket() failed\n", ret);
            return ret;
        }

        ret = m_phttp_socket->connect(m_shost.c_str(), m_nport);
        lbtrace("ret:%d = m_ptls_socket->connect(m_shost:%s, m_nport:%d)\n", ret, m_shost.c_str(), m_nport);
        return ret;
    }

    void disconnect()
    {
        if(m_phttp_socket)
        {
            m_phttp_socket->close();
            LB_DEL(m_phttp_socket);
            //delete m_phttp_socket;
            m_phttp_socket = NULL;
        }
    }

    int url_split(std::string& path, std::string& split, const char* ptag)
    {
        if(path.empty() || NULL == ptag)
        {
            lberror("Invalid path:%s or ptag:%p\n", path.c_str(), ptag);
            return -1;
        }
        size_t pos = path.find_first_of(ptag, 0);
        if(std::string::npos == pos || pos <= 0)
        {
            return -1;
        }
        split = path.substr(0, pos);
        path = path.substr(pos + strlen(ptag));
        lbtrace("url split path:%s split:%s, ptag:%s\n", path.c_str(), split.c_str(), ptag);
        return 0;
    }
protected:
    int                 m_nfd;
    std::string         m_sschema;
    std::string         m_shost;
    int                 m_nport;
    std::string         m_shttp_path;
    std::string         m_shttp_query;
    std::string         m_sip;
    std::string         m_surl;

    ITCPSocket*         m_phttp_socket;
    int64_t             m_lltimeout_us;
};
