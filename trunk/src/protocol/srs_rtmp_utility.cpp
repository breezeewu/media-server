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

#include <srs_rtmp_utility.hpp>

// for srs-librtmp, @see https://github.com/ossrs/srs/issues/213
#ifndef _WIN32
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <stdlib.h>
#include <vector>
#include <map>
#include <srs_kernel_log.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_kernel_stream.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_kernel_codec.hpp>
#include <srs_kernel_consts.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_rtmp_io.hpp>
#include <lbsp_rsa_enc.hpp>
#include <lbsp_utility_string.hpp>
using namespace std;
using namespace lbsp_util;
char prikey[] = "-----BEGIN PRIVATE KEY-----\r\n\
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMS3WBd7J1pE1H+q\r\n\
mHDoFgNA85a9dBSbes4jET0NPlzvDIAnW9ZNBTeqDPH3MJ7U/TRaYoXPWpFGTuLb\r\n\
AlhZJ2h4iK3F1iTtDnd7n44XSyoJ0zSrtPK9KSmH/jVVA6D/kKajgzPPky+PGzGq\r\n\
wKHg6H16PWMZ5c92ElUndkkChPpZAgMBAAECgYA7r9m1vjNRi2LinbOFRpYvRIzk\r\n\
ZvWKryZS14cKfDM45Xtogwi1fEch/aHR5QvGlZ+CPA56xVCYlbmn0YXjoqF246DU\r\n\
qI3ZdzLFLfDSZBf98XOVboQWmGm5pIWXtY8sE0wrn8g160E5IFor3MOOTIMKB2QN\r\n\
xnRclUoFdGVMZbSNpQJBAPYa/zWKmOWJ4rq4hi6g1MBo+uW3918szFGh640N+Jdi\r\n\
GCqku/joGhGBtdKFjBnFjhv5c2h59RW/0ye+0f0Svn8CQQDMoAQA7GUSa03zOh2W\r\n\
/NRVtzoK3tRaNacec03SUyDCmxk0CKJoLnv14LM6w2GuqJldPAD2pKcaf6kKWpGR\r\n\
RYsnAkEAvYK4d2BMsKTnJOWm3g0XBztPyMlLAc0bYNkQ68OQY/IzrdLAtMD2IfkC\r\n\
LCSOZ+IKtlv2lMMlCSR30ylLxldCvQJBALZVx/uCqjWVhGo92OwX8qVGlePl11dj\r\n\
A72whSHrjP+b8QNaxk0LTs40IcE1JK/b8H0R4NHmujh0lQ5y0c+fJnUCQAp7JEQj\r\n\
q2c81E3JD+9dYDCVsmw3Y9wtmS3CWQdZEcDxnchOOQTlwuzx077rKcZh4QjuYfM1\r\n\
BiU/mCVATHhMe8Y=\r\n\
-----END PRIVATE KEY-----";
char pubkey[] = "-----BEGIN PUBLIC KEY-----\r\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEt1gXeydaRNR/qphw6BYDQPOW\r\n\
vXQUm3rOIxE9DT5c7wyAJ1vWTQU3qgzx9zCe1P00WmKFz1qRRk7i2wJYWSdoeIit\r\n\
xdYk7Q53e5+OF0sqCdM0q7TyvSkph/41VQOg/5Cmo4Mzz5MvjxsxqsCh4Oh9ej1j\r\n\
GeXPdhJVJ3ZJAoT6WQIDAQAB\r\n\
-----END PUBLIC KEY-----";

void srs_discovery_tc_url(
    string tcUrl, 
    string& schema, string& host, string& vhost, 
    string& app, string& stream, string& port, std::string& param
) {
    size_t pos = std::string::npos;
    std::string url = tcUrl;
    
    if ((pos = url.find("://")) != std::string::npos) {
        schema = url.substr(0, pos);
        url = url.substr(schema.length() + 3);
        srs_info("discovery schema=%s", schema.c_str());
    }
    
    if ((pos = url.find("/")) != std::string::npos) {
        host = url.substr(0, pos);
        url = url.substr(host.length() + 1);
        srs_info("discovery host=%s", host.c_str());
    }

    port = SRS_CONSTS_RTMP_DEFAULT_PORT;
    if ((pos = host.find(":")) != std::string::npos) {
        port = host.substr(pos + 1);
        host = host.substr(0, pos);
        srs_info("discovery host=%s, port=%s", host.c_str(), port.c_str());
    }
    
#if 0
    if ((pos = url.find("?")) != std::string::npos) {
        /*port = host.substr(pos + 1);
        host = host.substr(0, pos);*/
        param = url.substr(pos + 1);
        url = url.substr(0, pos);
        srs_info("discovery host=%s, port=%s", url.c_str(), param.c_str());
    }

    vector<string> urllist = string_splits(url, "/");
    if(urllist.size() >= 3 && urllist[0].length() == 32)
    {

    }
    else
    {
    }
    

#else
    app = url;
    vhost = host;
    srs_vhost_resolve(vhost, app, param);
    srs_vhost_resolve(vhost, stream, param);
    
    if (param == "?vhost="SRS_CONSTS_RTMP_DEFAULT_VHOST) {
        param = "";
    }
#endif
}

void srs_discovery_tc_url(
    std::string tcUrl, 
    std::string& schema, std::string& host, std::string& vhost, 
    std::string& app, std::string& stream, std::string& port, std::string& param, std::string& token
)
{
    size_t pos = std::string::npos;
    std::string url = tcUrl;
    
    if ((pos = url.find("://")) != std::string::npos) {
        schema = url.substr(0, pos);
        url = url.substr(schema.length() + 3);
        srs_info("discovery schema=%s", schema.c_str());
    }
    
    if ((pos = url.find("/")) != std::string::npos) {
        host = url.substr(0, pos);
        url = url.substr(host.length() + 1);
        srs_info("discovery host=%s", host.c_str());
    }

    port = SRS_CONSTS_RTMP_DEFAULT_PORT;
    if ((pos = host.find(":")) != std::string::npos) {
        port = host.substr(pos + 1);
        host = host.substr(0, pos);
        srs_info("discovery host=%s, port=%s", host.c_str(), port.c_str());
    }
    

    if ((pos = url.find("?")) != std::string::npos) {
        /*port = host.substr(pos + 1);
        host = host.substr(0, pos);*/
        param = url.substr(pos + 1);
        url = url.substr(0, pos);
        srs_info("discovery host=%s, port=%s", url.c_str(), param.c_str());
    }

    vector<string> urllist = string_splits(url, "/");
    if(urllist.size() >= 3)
    {
        token = urllist[0];
        app = urllist[1];
        stream = urllist[2];
    }
    else if(urllist.size() >= 2)
    {
        app = urllist[urllist.size()-1];
        token = urllist[urllist.size()-2];
    }
    else if(urllist.size() > 0)
    {
        app = urllist[urllist.size()-1];
    }
    else
    {
        srs_error("Invalid url:%s\n", url.c_str());
    }
    
    
    if(!param.empty())
    {
        map<string, string> pair_list = read_key_value_pair(param, "&", "=");
        for(map<string, string>::iterator it = pair_list.begin(); it != pair_list.end(); it++)
        {
            srs_rtsp_debug("param key:%s, value:%s\n", it->first.c_str(), it->second.c_str());
            if("token" == it->first)
            {
                token = it->second;
            }
        }
    }
    srs_rtsp_debug("app:%s, stream:%s, token:%s\n", app.c_str(), stream.c_str(), token.c_str());
}

void srs_vhost_resolve(string& vhost, string& app, string& param)
{
    // get original param
    size_t pos = 0;
    if ((pos = app.find("?")) != std::string::npos) {
        param = app.substr(pos);
    }
    
    // filter tcUrl
    app = srs_string_replace(app, ",", "?");
    app = srs_string_replace(app, "...", "?");
    app = srs_string_replace(app, "&&", "?");
    app = srs_string_replace(app, "=", "?");
    
    if ((pos = app.find("?")) != std::string::npos) {
        std::string query = app.substr(pos + 1);
        app = app.substr(0, pos);
        
        if ((pos = query.find("vhost?")) != std::string::npos) {
            query = query.substr(pos + 6);
            if (!query.empty()) {
                vhost = query;
            }
            if ((pos = vhost.find("?")) != std::string::npos) {
                vhost = vhost.substr(0, pos);
            }
        }
    }
    
    /* others */
}

void srs_random_generate(char* bytes, int size)
{
    static bool _random_initialized = false;
    if (!_random_initialized) {
        srand(0);
        _random_initialized = true;
        //srs_trace("srand initialized the random.");
    }
    
    for (int i = 0; i < size; i++) {
        // the common value in [0x0f, 0xf0]
        bytes[i] = 0x0f + (rand() % (256 - 0x0f - 0x0f));
    }
}

string srs_generate_tc_url(string ip, string vhost, string app, string port, string param)
{
    string tcUrl = "rtmp://";
    
    if (vhost == SRS_CONSTS_RTMP_DEFAULT_VHOST) {
        tcUrl += ip;
    } else {
        tcUrl += vhost;
    }
    
    if (port != SRS_CONSTS_RTMP_DEFAULT_PORT) {
        tcUrl += ":";
        tcUrl += port;
    }
    
    tcUrl += "/";
    tcUrl += app;
    tcUrl += param;
    
    return tcUrl;
}

/**
* compare the memory in bytes.
*/
bool srs_bytes_equals(void* pa, void* pb, int size)
{
    u_int8_t* a = (u_int8_t*)pa;
    u_int8_t* b = (u_int8_t*)pb;
    
    if (!a && !b) {
        return true;
    }
    
    if (!a || !b) {
        return false;
    }
    
    for(int i = 0; i < size; i++){
        if(a[i] != b[i]){
            return false;
        }
    }

    return true;
}

int srs_do_rtmp_create_msg(char type, u_int32_t timestamp, char* data, int size, int stream_id, SrsSharedPtrMessage** ppmsg)
{
    int ret = ERROR_SUCCESS;
    
    *ppmsg = NULL;
    SrsSharedPtrMessage* msg = NULL;
    
    if (type == SrsCodecFlvTagAudio) {
        SrsMessageHeader header;
        header.initialize_audio(size, timestamp, stream_id);
        
        msg = new SrsSharedPtrMessage();
        LB_ADD_MEM(msg, sizeof(SrsSharedPtrMessage));
        if ((ret = msg->create(&header, data, size)) != ERROR_SUCCESS) {
            srs_freep(msg);
            return ret;
        }
    } else if (type == SrsCodecFlvTagVideo) {
        SrsMessageHeader header;
        header.initialize_video(size, timestamp, stream_id);
        
        msg = new SrsSharedPtrMessage();
        LB_ADD_MEM(msg, sizeof(SrsSharedPtrMessage));
        if ((ret = msg->create(&header, data, size)) != ERROR_SUCCESS) {
            srs_freep(msg);
            return ret;
        }
    } else if (type == SrsCodecFlvTagScript) {
        SrsMessageHeader header;
        header.initialize_amf0_script(size, stream_id);
        
        msg = new SrsSharedPtrMessage();
        LB_ADD_MEM(msg, sizeof(SrsSharedPtrMessage));
        if ((ret = msg->create(&header, data, size)) != ERROR_SUCCESS) {
            srs_freep(msg);
            return ret;
        }
    } else {
        ret = ERROR_STREAM_CASTER_FLV_TAG;
        srs_error("rtmp unknown tag type=%#x. ret=%d", type, ret);
        return ret;
    }

    *ppmsg = msg;

    return ret;
}

int srs_rtmp_create_msg(char type, u_int32_t timestamp, char* data, int size, int stream_id, SrsSharedPtrMessage** ppmsg)
{
    int ret = ERROR_SUCCESS;

    // only when failed, we must free the data.
    if ((ret = srs_do_rtmp_create_msg(type, timestamp, data, size, stream_id, ppmsg)) != ERROR_SUCCESS) {
        srs_freepa(data);
        return ret;
    }

    return ret;
}

std::string srs_generate_stream_url(std::string vhost, std::string app, std::string stream) 
{
    std::string url = "";
    
    if (SRS_CONSTS_RTMP_DEFAULT_VHOST != vhost){
    	url += vhost;
    }
    url += "/";
    url += app;
    url += "/";
    url += stream;

    return url;
}

int srs_write_large_iovs(ISrsProtocolReaderWriter* skt, iovec* iovs, int size, ssize_t* pnwrite)
{
    int ret = ERROR_SUCCESS;
    
    // the limits of writev iovs.
    // for srs-librtmp, @see https://github.com/ossrs/srs/issues/213
#ifndef _WIN32
    // for linux, generally it's 1024.
    static int limits = (int)sysconf(_SC_IOV_MAX);
#else
    static int limits = 1024;
#endif
    
    // send in a time.
    if (size < limits) {
        if ((ret = skt->writev(iovs, size, pnwrite)) != ERROR_SUCCESS) {
            if (!srs_is_client_gracefully_close(ret)) {
                srs_error("send with writev failed. ret=%d", ret);
            }
            return ret;
        }
        return ret;
    }
    
    // send in multiple times.
    int cur_iov = 0;
    while (cur_iov < size) {
        int cur_count = srs_min(limits, size - cur_iov);
        if ((ret = skt->writev(iovs + cur_iov, cur_count, pnwrite)) != ERROR_SUCCESS) {
            if (!srs_is_client_gracefully_close(ret)) {
                srs_error("send with writev failed. ret=%d", ret);
            }
            return ret;
        }
        cur_iov += cur_count;
    }
    
    return ret;
}

int simple_read_file(FILE** ppfile,  const char* ppath, char* prelpath, char* pdata, int len)
{
    if(!ppfile || !pdata || len <= 0)
    {
        return -1;
    }

    int readlen = 0;
    FILE* pfile = *ppfile;
    if(!pfile && prelpath)
    {
        char filepath[256] = {0};
        if(ppath && strlen(ppath) > 0)
        {
            strcpy(filepath, ppath);
        }
        strcat(filepath, prelpath);
        pfile = *ppfile = fopen(filepath, "rb");
    }
    
    if(pfile)
    {
        readlen = fread(pdata, 1, len, pfile);
    }

    return readlen;
}

int simple_write_file(FILE** ppfile,  const char* ppath, char* prelpath, char* pdata, int len)
{
    if(!ppfile || !pdata || len <= 0)
    {
        return -1;
    }

    int writelen = 0;
    FILE* pfile = *ppfile;
    if(!pfile && prelpath)
    {
        char filepath[256] = {0};
        if(ppath && strlen(ppath) > 0)
        {
            strcpy(filepath, ppath);
        }
        
        char* pfilename = strrchr(prelpath, '/');
        if(!pfilename || pfilename == prelpath)
        {
            // ���������Ŀ¼������ֱ��ƴ��
            strcat(filepath, prelpath);
        }
        else
        {
            memcpy(filepath + strlen(filepath), prelpath, pfilename - prelpath);
            if(0 != access(filepath, F_OK))
            {
                mkdir(filepath, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
            }
        }
        pfile = *ppfile = fopen(filepath, "wb");
    }
    
    if(pfile)
    {
        writelen = fwrite(pdata, 1, len, pfile);
    }

    return writelen;
}
extern char pubkey[];
extern char prikey[];
std::string encode_rsa_private_key(std::string org_str)
{
    rsaenc rsa_enc;
    char enc_buf[512] = {0};
    char b64str[512] = {0};
    if(org_str.empty())
    {
        return std::string();
    }
    //std::string token = req->app + ":" + req->stream + ":" + req->token + ":" + req->srsForwardHostName + ":" + req->devicesn;
    int enclen  = rsa_enc.private_key_encrypt(prikey, (const char*)org_str.c_str(), org_str.size(), (char*)enc_buf, 512);
    if(enclen <= 0)
    {
        srs_error("enclen:%d = rsa_enc.private_key_encrypt(prikey, (const char*)token:%d, token.size():%d, enc_buf, 256) failed\n", enclen, org_str.c_str(), org_str.size());
        return std::string();
    }
    srs_av_base64_encode(b64str, 512, (u_int8_t*)enc_buf, enclen);
    srs_trace("org_token:%s, enc_buf:%s\n", org_str.c_str(), b64str);
    return std::string(b64str);
}

std::string decode_rsa_public_key(std::string enc_str)
{
    rsaenc rsa_dec;
    char enc_buf[512] = {0};
    char dec_buf[512] = {0};
    if(enc_str.empty())
    {
        return std::string();
    }
    int enc_len = srs_av_base64_decode((u_int8_t*)enc_buf, enc_str.c_str(), 512);
    int dec_len = rsa_dec.public_key_decrypt(pubkey, dec_buf, 512, enc_buf, enc_len);
    if(dec_len <= 0)
    {
        srs_error("dec_len:%d = rsa_dec.public_key_decrypt(pubkey, dec_buf:%p, 512, enc_buf:%p, enc_len:%d)\n", dec_len, dec_buf, enc_buf, enc_len);
    }
    std::string dec_token = dec_buf;
    srs_trace("dec_token:%s, forward_token:%s\n", dec_token.c_str(), enc_str.c_str());
    return dec_token;
}

std::string encode_rsa_public_key(std::string org_str)
{
    rsaenc rsa_enc;
    char enc_buf[512] = {0};
    char b64str[512] = {0};
    if(org_str.empty())
    {
        return std::string();
    }

    //std::string token = req->app + ":" + req->stream + ":" + req->token + ":" + req->srsForwardHostName + ":" + req->devicesn;
    int enclen  = rsa_enc.public_key_encrypt(prikey, (const char*)org_str.c_str(), org_str.size(), enc_buf, 512);
    if(enclen <= 0)
    {
        srs_error("enclen:%d = rsa_enc.private_key_encrypt(prikey, (const char*)token:%d, token.size():%d, enc_buf, 256) failed\n", enclen, org_str.c_str(), org_str.size());
        return std::string();
    }
    srs_av_base64_encode(b64str, 512, (u_int8_t*)enc_buf, enclen);
    srs_trace("org_token:%s, enc_buf:%s\n", org_str.c_str(), b64str);
    return std::string(b64str);
}

std::string decoder_rsa_private_key(std::string enc_str)
{
    char rsa_enc[256] = {0};
    char dec_buf[256] = {0};
    if(enc_str.empty())
    {
        return std::string();
    }

    int rsa_enc_len = srs_av_base64_decode((u_int8_t*)rsa_enc, enc_str.c_str(), 256);
    if(rsa_enc_len > 0)
    {
        return std::string();
    }
   
    rsaenc rsa_dec;
    int declen  = rsa_dec.private_key_decrypt(prikey, (const char*)rsa_enc, rsa_enc_len, (char*)dec_buf, 256);
    //srs_trace("declen:%d  = rsa_dec.private_key_decrypt\n", declen);
    if(declen <= 0)
    {
        srs_error("declen:%d = rsa_dec.private_key_decrypt(prikey, (const char*)rsa_enc:%p, rsa_enc_len:%ld, dec_buf:%s, 256)\n", declen, rsa_enc, rsa_enc_len, dec_buf);
    }
    return std::string(dec_buf);
}