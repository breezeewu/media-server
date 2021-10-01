#pragma once
#include <string>
#include "lbsp_io_tls_socket.hpp"
using namespace std;
namespace lbsp_util{
#define HTTP_VERSION    ""
#define LBSP_HTTP_CRLF      "\r\n"
#define HTTP_ATTRIBUTE_HOST                     "Host"
#define HTTP_ATTRIBUTE_CONNECTION               "Connection"
#define HTTP_ATTRIBUTE_CONTENT_LENGTH           "Content-Length"
#define HTTP_ATTRIBUTE_USER_AGENT               "User-Agent"
#define HTTP_ATTRIBUTE_SRS_SERVER_NAME          "srs-server-name"
#define HTTP_ATTRIBUTE_CONTENT_TYPE             "Content-Type"
#define HTTP_ATTRIBUTE_DATE                     "Date"
#define HTTP_ATTRIBUTE_TRANSFER_ENCODING        "Transfer-Encoding"


class CHttpCommon
{
public:
    std::string         m_sbody;
    std::map<std::string, std::string>      m_mhttp_attr_list;
public:
    CHttpCommon(){}
    virtual ~CHttpCommon(){}
    int praser_http_common(std::string http_cmd)
    {
        std::string http_line;
        int ret = 0;
        //lbdebug("http_cmd:%s", http_cmd.c_str());
        ret = http_read_line(http_cmd, http_line);
        //lbdebug("ret:%d = http_read_line(http_cmd:%s, http_line:%s)\n", ret, http_cmd.c_str(), http_line.c_str());
        if(ERROR_SUCCESS != ret || http_line.empty())
        {
            lberror("http parser header failed, ret:%d, http_cmd:%s, http_line:%s\n", ret, http_cmd.c_str(), http_line.c_str());
            return ret;
        }
        ret = http_parser_header(http_line);
        
        if(ERROR_SUCCESS != ret)
        {
            lberror("ret:%d = http_parser_header(http_line:%s) failed\n", ret, http_line.c_str());
        }

        do
        {
            ret = http_read_line(http_cmd, http_line);
            if(0 == ret && http_line.empty())
            {
                // parser body ...
                ret = http_parser_body(http_cmd, m_sbody);
                //lbdebug("ret:%d = http_parser_body(http_cmd:%s, m_sbody:%s)\n", ret, http_cmd.c_str(), m_sbody.c_str());
                if(ERROR_SUCCESS != ret)
                {
                    lberror("parser http body %s failed, ret:%d\n", m_sbody.c_str(), ret);
                }
                break;
            }
            else
            {
                std::string attr_name;
                std::string attr_value;
                ret = http_parser_attribute(http_line, attr_name, attr_value);
                //lbdebug("ret:%d = http_parser_attribute(http_line:%s, attr_name:%s, attr_value:%s)\n", ret, http_line.c_str(), attr_name.c_str(), attr_value.c_str());
                if(ERROR_SUCCESS != ret)
                {
                    lberror("parser http attr %s failed, ret:%d\n", http_line.c_str(), ret);
                    break;
                }
                m_mhttp_attr_list[attr_name]    = attr_value;
            }
        }while(ERROR_SUCCESS == ret);
        
        return ret;
    }

    std::string get_body()
    {
        return m_sbody;
    }

    int http_parser_attribute(std::string attr_line, std::string& attr_name, std::string& attr_value)
    {
        attr_value = attr_line;
        int ret = url_split(attr_value, attr_name, ":");
        //lbdebug("parser attribute name %s:value:%s", attr_name.c_str(), attr_value.c_str());
        /*if(0 != ret)
        {
            lberror("parser attribut line %s failed, ret:%d", attr_line.c_str(), ret);
            return ret;
        }*/
        attr_name = string_trim(attr_name, " ");
        attr_value = string_trim(attr_value, " ");
        return ret;
    }

    std::string get_attribute(const char* pattr_name)
    {
        if(pattr_name)
        {
            std::map<std::string, std::string>::iterator it = m_mhttp_attr_list.find(pattr_name);
            if(m_mhttp_attr_list.end() != it)
            {
                return it->second;
            }
        }

        return std::string();;
    }

    int http_parser_body(std::string http_cmd, std::string& body)
    {
        int ret = 0;
        bool chunked = false;
        http_cmd = string_trim(http_cmd, LBSP_HTTP_CRLF);
        //lbdebug("(http_cmd:%s, body:%s)", http_cmd.c_str(), body.c_str());
        if(get_attribute(HTTP_ATTRIBUTE_TRANSFER_ENCODING) == "chunked")
        {
            chunked = true;
        }
        std::string content_len = get_attribute(HTTP_ATTRIBUTE_CONTENT_LENGTH);
        int bodylen = 0;
        if(!content_len.empty())
        {
            bodylen = atoi(content_len.c_str());
        }
        //lbdebug("chunked:%d, content_len:%s, bodylen:%d\n", (int)chunked, content_len.c_str(), bodylen);
        body.clear();
        do
        {
            std::string chunk_line;
            if(chunked)
            {
                
                ret = http_read_line(http_cmd, chunk_line);
                //lbdebug("ret:%d = http_read_line(http_cmd:%s, chunk_line:%s)\n", ret, http_cmd.c_str(), chunk_line.c_str());
                if(ret != ERROR_SUCCESS)
                {
                    break;
                }
                sscanf(chunk_line.c_str(), "%x", &bodylen);
                //bodylen = atoi(chunk_str.c_str());
                if(bodylen <= 0)
                {
                    break;
                }
            }
            ret = http_read_line(http_cmd, chunk_line);
            if(ret != ERROR_SUCCESS)
            {
                body.append(http_cmd.data(), http_cmd.size());
                break;
            }
            body.append(chunk_line.data(), bodylen);
            
            //http_cmd = http_cmd.substr(bodylen, http_cmd.length());
            //lbdebug("bodylen:%d, http_cmd:%s, chunk_line:%s, body:%s\n", bodylen, http_cmd.c_str(), chunk_line.c_str(), body.c_str());
            
        }while(chunked);

        //lbtrace("parser body:%s, bodylen:%d\n", body.c_str(), bodylen);
        return 0;
    }

protected:
    int url_split(std::string& path, std::string& attr, const char* ptag)
    {
        if(path.empty() || NULL == ptag)
        {
            lberror("Invalid path:%s or ptag:%p\n", path.c_str(), ptag);
            return -1;
        }
        attr.clear();
        size_t pos = path.find_first_of(ptag, 0);
        if(0 == pos)
        {
            return 0;
        }
        if(std::string::npos == pos)
        {
            return -1;
        }
        attr = path.substr(0, pos);
        path = path.substr(pos + strlen(ptag));
        //lbdebug("url split path:%s split:%s, ptag:%s\n", path.c_str(), attr.c_str(), ptag);
        return 0;
    }

    std::string string_trim(std::string str, std::string tag)
    {
        size_t pos1 = str.find_first_not_of(tag);
        size_t pos2 = str.find_last_not_of(tag);
        pos1 = pos1 == std::string::npos ? 0 : pos1;
        pos2 = pos2 == std::string::npos ? str.length() : pos2 + 1;
    
        std::string trim_str =  str.substr(pos1, pos2);

        return trim_str;
    }

    int http_read_line(std::string& http_cmd, std::string& http_line)
    {
        int ret = url_split(http_cmd, http_line, LBSP_HTTP_CRLF);

        return ret;
    }

    virtual int http_parser_header(std::string http_line) = 0;
};

class CHttpRequest:public CHttpCommon
{
protected:
    std::string         m_smethod;
    std::string         m_spath;
    std::string         m_sversion;

public:
    CHttpRequest(){}
    ~CHttpRequest(){}

protected:
     virtual int http_parser_header(std::string http_line)
    {
        int ret = 0;
        http_line = string_trim(http_line, LBSP_HTTP_CRLF);
        http_line = string_trim(http_line, " ");
        ret = url_split(http_line, m_smethod, " ");
        if(ERROR_SUCCESS != ret)
        {
            lberror("parser http req method failed, http_line:%s, m_smethod:%s\n", http_line.c_str(), m_smethod.c_str());
            return ret;
        }

        ret = url_split(http_line, m_spath, " ");
        if(ERROR_SUCCESS != ret)
        {
            lberror("parser http req path failed, http_line:%s, m_spath:%s\n", http_line.c_str(), m_spath.c_str());
            //return ret;
            m_spath = http_line;
        }
        ret = url_split(http_line, m_sversion, " ");
        if(ERROR_SUCCESS != ret)
        {
            m_sversion = http_line;
        }
        //lbdebug("parser requset http header m_smethod:%s, m_spath:%s, m_sversion:%s\n", m_smethod.c_str(), m_spath.c_str(), m_sversion.c_str());
        return ret;
    }
};

class CHttpResponse:public CHttpCommon
{
protected:
    std::string         m_sversion;
    int                 m_nstatus_code;
    std::string         m_sstatus_msg;
public:
    CHttpResponse(){}
    ~CHttpResponse(){}

    int get_status()
    {
        return m_nstatus_code;
    }

    std::string get_status_msg()
    {
        return m_sstatus_msg;
    }

protected:
     virtual int http_parser_header(std::string http_line)
    {
        int ret = 0;
        std::string status_code;
        http_line = string_trim(http_line, LBSP_HTTP_CRLF);
        http_line = string_trim(http_line, " ");
        ret = url_split(http_line, m_sversion, " ");
        if(ERROR_SUCCESS != ret)
        {
            lberror("parser http req method failed, http_line:%s, m_sversion:%s\n", http_line.c_str(), m_sversion.c_str());
            return ret;
        }

        ret = url_split(http_line, status_code, " ");
        if(ERROR_SUCCESS != ret)
        {
            status_code = http_line;
            //lberror("parser http req path failed, http_line:%s, status_code:%s\n", http_line.c_str(), status_code.c_str());
            //return ret;
        }

        m_nstatus_code = atoi(status_code.c_str());
        if(!http_line.empty())
        {
            ret = url_split(http_line, m_sstatus_msg, " ");
            if(ERROR_SUCCESS != ret)
            {
                m_sstatus_msg = http_line;
            }
        }
        //lbdebug("parser response http header m_sversion:%s, m_nstatus_code:%d, m_sstatus_msg:%s\n", m_sversion.c_str(), m_nstatus_code, m_sstatus_msg.c_str());
        return ERROR_SUCCESS;
    }
};


class CHttpClient
{
protected:
    string      m_shttp_url;
    string      m_sschema;
    string      m_shost;
    string      m_shttp_path;
    string      m_shttp_query;
    string      m_sbody;
    int         m_nport;
    int         m_estatus_code;
    ITCPSocket* m_psocket;
public:
    CHttpClient()
    {
        m_psocket = NULL;
        m_nport = 0;
        m_estatus_code = 200;
    }

    ~CHttpClient()
    {
        if(m_psocket)
        {
            delete m_psocket;
            m_psocket = NULL;
        }
    }

    int parser_url(const string& http_url)
    {
        std::string path = http_url;
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
                lberror("Invalid http uri:%s while parser schema\n", http_url.c_str());
                return -1;
            }
            pos = url_split(path, m_shost, (const char*)"/");
            if(std::string::npos == pos)
            {
                lberror("invalid http uri:%s while parser host!\n", http_url.c_str());
                return -1;
            }
        }
        else
        {
            std::string sport;
            pos = url_split(path, sport, (const char*)"/");
            if(std::string::npos == pos)
            {
                lberror("invalid http uri:%s while parser port!\n", http_url.c_str());
                return -1;
            }
            m_nport = atoi(sport.c_str());
        }

        pos = url_split(path, m_shttp_path, (const char*)"?");
        if(std::string::npos == pos)
        {
            m_shttp_path = path;
        }
        m_shttp_path = "/" + m_shttp_path;
        m_shttp_query = path;
        m_shttp_url = http_url;

        return 0;
    }

    string get_path()
    {
        return m_shttp_path;
    }

    string get_host()
    {
        return m_shost;
    }
    // send http/https request with http header and body
    int send_request_and_get_response(const string& req, int& code, string& resp)
    {
        int ret = -1;
        std::string response;
        CHttpResponse httpresp;
        do
        {
           if(m_sschema == "http")
        {
            m_psocket = new CTCPSocket();
        }
        else if("https" == m_sschema)
        {
            CTLSSocket* ptlsskt = new CTLSSocket();
            ptlsskt->init_cert(TLS_CLIENT_VERSION_TOP_MOST);
            m_psocket = ptlsskt;
            //m_psocket = new CTLSSocket();
            //m_psocket->i
        }
        else
        {
            lberror("Invalid http schema %s\n", m_sschema.c_str());
            break;
        }
        ret = m_psocket->connect(m_shost.c_str(), m_nport);
        //lbtrace("ret:%d = m_psocket->connect(m_shost.c_str():%s, m_nport:%d)\n", ret, m_shost.c_str(), m_nport);
        if(ret != 0)
        {
            lberror("%s send_request_and_get_response ret:%d = m_psocket->connect(m_shost.c_str():%s, m_nport:%d), req:%s\n", m_sschema.c_str(), ret, m_shost.c_str(), m_nport, req.c_str());
            break;
        }

        ret = m_psocket->write(req.c_str(), req.length());
        //lbtrace("ret:%d = m_psocket->write(req:%s, req.length():%ld)\n", ret, req.c_str(), req.length());
        if(ret < 0)
        {
            lberror("ret:%d = m_psocket->write(req.c_str():%s, req.length():%ld failed\n", ret, req.c_str(), req.length());
            break;
        }

        while(1)
        {
            char buff[1024] = {0};
            ret = m_psocket->read(buff, 1024);
            //lbtrace("ret:%d = m_psocket->read(buff:%s, 1024)\n", ret, buff);
            if(ret < 0)
            {
                lberror("ret:%d = m_phttp_socket->read(resp, 1024) failed", ret);
                break;
            }
            else
            {
                lbusleep(20000);
            }
            response.append(buff);
            if(memcmp("\r\n\r\n", response.c_str() + response.length() - 4, strlen("\r\n\r\n")) == 0 || '}'== buff[ret-1])
            {
                break;
            }
        }
        //lbtrace("response:%s\n", response.c_str());
        if(0 > ret)
        {
            lberror("ret:%d = m_psocket->read(resp:%s, 4096), req:%s failed\n", ret, response.c_str(), req.c_str());
            break;
        }
        ret = httpresp.praser_http_common(response);
        //lbtrace("ret:%d = httpresp.praser_http_common(response)\n", ret);
        if(ERROR_SUCCESS != ret)
        {
            lberror("ret:%d = httpresp.praser_http_common(resp:%s) failed\n", ret, response.c_str());
            break;
        }
        m_estatus_code = httpresp.get_status();
        m_sbody = httpresp.get_body();
        resp = response;
        code = m_estatus_code;
        if(200 == m_estatus_code)
        {
            ret = 0;
            //lbtrace("send http request success!, req:%s\nm_estatus_code:%d, resp:%s\n", req.c_str(), m_estatus_code, resp.c_str());
        }
        } while (0);

        if(m_psocket)
        {
            m_psocket->close();
            delete m_psocket;
            m_psocket = NULL;
        }
        return ret;
    }

    int send_req_and_get_resp(const std::string method, const std::string url,  const std::string body, std::string& resp, std::string content_type = "application/json;charset=UTF-8")
    {
        int ret = -1;
        //int code = 0;
        std::string req;
        std::string response;
        CHttpResponse httpresp;
        do
        {
            ret = parser_url(url);
            if(ret < 0)
            {
                lberror("ret:%d = httpclient parser url %s failed\n", ret, url.c_str());
                break;
            }
            std::stringstream ss;
            ss << method << " " << url << " "
            << "HTTP/1.1" << LBSP_HTTP_CRLF
            << "Host: " << m_shost << LBSP_HTTP_CRLF
            << "Connection: Keep-Alive" << LBSP_HTTP_CRLF
            << "User-Agent: " << "sunvalley librtmp " << "V2020.06.09" << LBSP_HTTP_CRLF;
            if(!body.empty())
            {
                ss << "Content-Length: " << std::dec << body.length() << LBSP_HTTP_CRLF;
                ss << "Content-Type: "<< "application/json;charset=UTF-8" << LBSP_HTTP_CRLF << LBSP_HTTP_CRLF;
                ss << body << LBSP_HTTP_CRLF;
            }
            req = ss.str();
            if(m_sschema == "http")
            {
                m_psocket = new CTCPSocket();
            }
            else if("https" == m_sschema)
            {
                CTLSSocket* ptlsskt = new CTLSSocket();
                ptlsskt->init_cert(TLS_CLIENT_VERSION_TOP_MOST);
                m_psocket = ptlsskt;
                //m_psocket = new CTLSSocket();
                //m_psocket->i
            }
            else
            {
                lberror("Invalid http schema %s\n", m_sschema.c_str());
                break;
            }
            ret = m_psocket->connect(m_shost.c_str(), m_nport);
            //lbtrace("ret:%d = m_psocket->connect(m_shost.c_str():%s, m_nport:%d)\n", ret, m_shost.c_str(), m_nport);
            if(ret != 0)
            {
                lberror("%s send_request_and_get_response ret:%d = m_psocket->connect(m_shost.c_str():%s, m_nport:%d), req:%s\n", m_sschema.c_str(), ret, m_shost.c_str(), m_nport, req.c_str());
                break;
            }

            ret = m_psocket->write(req.c_str(), req.length());
            //lbtrace("ret:%d = m_psocket->write(req:%s, req.length():%ld)\n", ret, req.c_str(), req.length());
            if(ret < 0)
            {
                lberror("ret:%d = m_psocket->write(req.c_str():%s, req.length():%ld failed\n", ret, req.c_str(), req.length());
                break;
            }
            
            while(1)
            {
                char buff[1024] = {0};
                ret = m_psocket->read(buff, 1024);
                //lbtrace("ret:%d = m_psocket->read(buff:%s, 1024)\n", ret, buff);
                if(ret < 0)
                {
                    lberror("ret:%d = m_phttp_socket->read(resp, 1024) failed", ret);
                    break;
                }
                else
                {
                    lbusleep(20000);
                }
                response.append(buff);
                if(memcmp("\r\n\r\n", response.c_str() + response.length() - 4, strlen("\r\n\r\n")) == 0 || '}'== buff[ret-1])
                {
                    break;
                }
            }
            //lbtrace("response:%s\n", response.c_str());
            if(0 > ret)
            {
                lberror("ret:%d = m_psocket->read(resp:%s, 4096), req:%s failed\n", ret, response.c_str(), req.c_str());
                break;
            }
            
            ret = httpresp.praser_http_common(response);
            //lbtrace("ret:%d = httpresp.praser_http_common(response)\n", ret);
            if(ERROR_SUCCESS != ret)
            {
                lberror("ret:%d = httpresp.praser_http_common(resp:%s) failed\n", ret, response.c_str());
                break;
            }
            m_estatus_code = httpresp.get_status();
            m_sbody = httpresp.get_body();
            resp = response;
            //code = m_estatus_code;
            if(200 == m_estatus_code)
            {
                ret = 0;
                //lbtrace("send http request success!, req:%s\nm_estatus_code:%d, resp:%s\n", req.c_str(), m_estatus_code, resp.c_str());
            }
        } while (0);

        if(m_psocket)
        {
            m_psocket->close();
            delete m_psocket;
            m_psocket = NULL;
        }
        return ret;
    }

    std::string get_body()
    {
        return m_sbody;
    }

protected:
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
        //lbdebug("url split path:%s split:%s, ptag:%s\n", path.c_str(), split.c_str(), ptag);
        return 0;
    }
};
};
