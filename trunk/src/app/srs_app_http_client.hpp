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

#ifndef SRS_APP_HTTP_CLIENT_HPP
#define SRS_APP_HTTP_CLIENT_HPP

/*
#include <srs_app_http_client.hpp>
*/
#include <srs_core.hpp>

#include <string>

#ifdef SRS_AUTO_HTTP_CORE

#include <srs_app_st.hpp>

class SrsHttpUri;
class SrsHttpParser;
class ISrsHttpMessage;
class SrsStSocket;

// the default timeout for http client.
#define SRS_HTTP_CLIENT_TIMEOUT_US (int64_t)(30*1000*1000LL)

/**
* http client to GET/POST/PUT/DELETE uri
*/
class SrsHttpClient
{
private:
    bool connected;
    st_netfd_t stfd;
    SrsStSocket* skt;
    SrsHttpParser* parser;
private:
    int64_t timeout_us;
    // host name or ip.
    std::string host;
    int port;
public:
    SrsHttpClient();
    virtual ~SrsHttpClient();
public:
    /**
    * initialize the client, connect to host and port.
    */
    virtual int initialize(std::string h, int p, int64_t t_us = SRS_HTTP_CLIENT_TIMEOUT_US);
public:
    /**
     * Content-Type类型：
     * application/x-www-form-urlencoded ：数据被编码为名称/值对。这是标准的编码格式，名称/键值对使用&分隔开
     * text/xml ：xml格式字符串
     * application/json ：json格式字符串
     * multipart/form-data ：既可上传一个或多个二进制文件，也可上传表单键值对，最后只转化为一条消息， 其中分隔符boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW（=后面的字符可以自定义）
     * Content-Type:application/octet-stream ：二进制文件，一次只能上传一个
     * text/plain：纯文本的传输。空格转换为“+”，但不支持特殊字符编码
     **/
    /**
    * to post json format Content-Type data to the uri.
    * @param the path to request on.
    * @param req the data post to uri. empty string to ignore.
    * @param ppmsg output the http message to read the response.
    */
    virtual int post(std::string path, std::string req, ISrsHttpMessage** ppmsg);
    /**
    * to get json format data from the uri.
    * @param the path to request on.
    * @param req the data post to uri. empty string to ignore.
    * @param ppmsg output the http message to read the response.
    */
    virtual int get(std::string path, std::string req, ISrsHttpMessage** ppmsg);

    /**
    * to post specify format data to the uri.
    * @param the path to request on.
    * @param req the data post to uri. empty string to ignore.
    * @param ppmsg output the http message to read the response.
    */
    virtual int post(std::string path, std::string contenttype, std::string req, ISrsHttpMessage** ppmsg);
    /**
    * to get specify format data from the uri.
    * @param the path to request on.
    * @param req the data post to uri. empty string to ignore.
    * @param ppmsg output the http message to read the response.
    */
    virtual int get(std::string path, std::string contenttype, std::string req, ISrsHttpMessage** ppmsg);

    virtual std::string get_local_ip();

    virtual std::string get_local_host_name();
private:
    virtual void disconnect();
    virtual int connect();
};

#endif

#endif

