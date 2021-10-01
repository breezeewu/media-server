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

#include <srs_app_http_hooks.hpp>

#ifdef SRS_AUTO_HTTP_CALLBACK

#include <sstream>
using namespace std;

#include <srs_kernel_error.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_app_st.hpp>
#include <srs_protocol_json.hpp>
#include <srs_app_dvr.hpp>
#include <srs_app_http_client.hpp>
#include <srs_core_autofree.hpp>
#include <srs_app_config.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_app_http_conn.hpp>
#include <srs_app_utility.hpp>
#include <srs_protocol_json.hpp>
#include <lbsp_io_http_client.hpp>

#define SRS_HTTP_RESPONSE_OK    SRS_XSTR(ERROR_SUCCESS)

#define SRS_HTTP_HEADER_BUFFER        1024
#define SRS_HTTP_READ_BUFFER    4096
#define SRS_HTTP_BODY_BUFFER        32 * 1024

// the timeout for hls notify, in us.
#define SRS_HLS_NOTIFY_TIMEOUT_US (int64_t)(10*1000*1000LL)

SrsHttpHooks::SrsHttpHooks()
{
}

SrsHttpHooks::~SrsHttpHooks()
{
}

int SrsHttpHooks::on_connect(string url, SrsRequest* req)
{
    int ret = ERROR_SUCCESS;
    
    int client_id = _srs_context->get_id();
    
    std::stringstream ss;
    ss << SRS_JOBJECT_START
        << SRS_JFIELD_STR("action", "on_connect") << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("client_id", client_id) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("ip", req->ip) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("vhost", req->vhost) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("app", req->app) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("tcUrl", req->tcUrl) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("pageUrl", req->pageUrl)
        << SRS_JOBJECT_END;
        
    std::string data = ss.str();
    std::string res;
    int status_code;
    if ((ret = do_post(url, data, status_code, res)) != ERROR_SUCCESS) {
        srs_error("http post on_connect uri failed. "
            "client_id=%d, url=%s, request=%s, response=%s, code=%d, ret=%d",
            client_id, url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return ret;
    }
    
    srs_trace("http hook on_connect success. "
        "client_id=%d, url=%s, request=%s, response=%s, ret=%d",
        client_id, url.c_str(), data.c_str(), res.c_str(), ret);
    
    return ret;
}

void SrsHttpHooks::on_close(string url, SrsRequest* req, int64_t send_bytes, int64_t recv_bytes)
{
    int ret = ERROR_SUCCESS;
    
    int client_id = _srs_context->get_id();
    
    std::stringstream ss;
    ss << SRS_JOBJECT_START
        << SRS_JFIELD_STR("action", "on_close") << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("client_id", client_id) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("ip", req->ip) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("vhost", req->vhost) << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("send_bytes", send_bytes) << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("recv_bytes", recv_bytes) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("app", req->app)
        << SRS_JOBJECT_END;
        
    std::string data = ss.str();
    std::string res;
    int status_code;
    if ((ret = do_post(url, data, status_code, res)) != ERROR_SUCCESS) {
        srs_warn("http post on_close uri failed, ignored. "
            "client_id=%d, url=%s, request=%s, response=%s, code=%d, ret=%d",
            client_id, url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return;
    }
    
    srs_trace("http hook on_close success. "
        "client_id=%d, url=%s, request=%s, response=%s, ret=%d",
        client_id, url.c_str(), data.c_str(), res.c_str(), ret);
    
    return;
}

int SrsHttpHooks::on_publish(string url, SrsRequest* req)
{
    int ret = ERROR_SUCCESS;
    
    int client_id = _srs_context->get_id();
    
    std::stringstream ss;
    ss << SRS_JOBJECT_START
        << SRS_JFIELD_STR("action", "on_publish") << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("client_id", client_id) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("ip", req->ip) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("vhost", req->vhost) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("app", req->app) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("tcUrl", req->tcUrl) << SRS_JFIELD_CONT  // Add tcUrl for auth publish rtmp stream client
        << SRS_JFIELD_STR("stream", req->stream) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("param", req->param)
        << SRS_JOBJECT_END;
        
    std::string data = ss.str();
    std::string res;
    int status_code;
    if ((ret = do_post(url, data, status_code, res)) != ERROR_SUCCESS) {
        srs_error("http post on_publish uri failed. "
            "client_id=%d, url=%s, request=%s, response=%s, code=%d, ret=%d",
            client_id, url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return ret;
    }
    
    srs_trace("http hook on_publish success. "
        "client_id=%d, url=%s, request=%s, response=%s, ret=%d",
        client_id, url.c_str(), data.c_str(), res.c_str(), ret);
    
    return ret;
}

void SrsHttpHooks::on_unpublish(string url, SrsRequest* req)
{
    int ret = ERROR_SUCCESS;
    
    int client_id = _srs_context->get_id();
    
    std::stringstream ss;
    ss << SRS_JOBJECT_START
        << SRS_JFIELD_STR("action", "on_unpublish") << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("client_id", client_id) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("ip", req->ip) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("vhost", req->vhost) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("app", req->app) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("stream", req->stream) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("param", req->param)
        << SRS_JOBJECT_END;
        
    std::string data = ss.str();
    std::string res;
    int status_code;
    if ((ret = do_post(url, data, status_code, res)) != ERROR_SUCCESS) {
        srs_warn("http post on_unpublish uri failed, ignored. "
            "client_id=%d, url=%s, request=%s, response=%s, code=%d, ret=%d",
            client_id, url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return;
    }
    
    srs_trace("http hook on_unpublish success. "
        "client_id=%d, url=%s, request=%s, response=%s, ret=%d",
        client_id, url.c_str(), data.c_str(), res.c_str(), ret);
    
    return;
}

int SrsHttpHooks::on_play(string url, SrsRequest* req)
{
    int ret = ERROR_SUCCESS;
    
    int client_id = _srs_context->get_id();
    
    std::stringstream ss;
    ss << SRS_JOBJECT_START
        << SRS_JFIELD_STR("action", "on_play") << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("client_id", client_id) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("ip", req->ip) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("vhost", req->vhost) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("app", req->app) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("stream", req->stream) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("param", req->param) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("pageUrl", req->pageUrl)
        << SRS_JOBJECT_END;
        
    std::string data = ss.str();
    std::string res;
    int status_code;
    if ((ret = do_post(url, data, status_code, res)) != ERROR_SUCCESS) {
        srs_error("http post on_play uri failed. "
            "client_id=%d, url=%s, request=%s, response=%s, code=%d, ret=%d",
            client_id, url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return ret;
    }
    
    srs_trace("http hook on_play success. "
        "client_id=%d, url=%s, request=%s, response=%s, ret=%d",
        client_id, url.c_str(), data.c_str(), res.c_str(), ret);
    
    return ret;
}

void SrsHttpHooks::on_stop(string url, SrsRequest* req)
{
    int ret = ERROR_SUCCESS;
    
    int client_id = _srs_context->get_id();
    
    std::stringstream ss;
    ss << SRS_JOBJECT_START
        << SRS_JFIELD_STR("action", "on_stop") << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("client_id", client_id) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("ip", req->ip) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("vhost", req->vhost) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("app", req->app) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("stream", req->stream) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("param", req->param)
        << SRS_JOBJECT_END;
        
    std::string data = ss.str();
    std::string res;
    int status_code;
    if ((ret = do_post(url, data, status_code, res)) != ERROR_SUCCESS) {
        srs_warn("http post on_stop uri failed, ignored. "
            "client_id=%d, url=%s, request=%s, response=%s, code=%d, ret=%d",
            client_id, url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return;
    }
    
    srs_trace("http hook on_stop success. "
        "client_id=%d, url=%s, request=%s, response=%s, ret=%d",
        client_id, url.c_str(), data.c_str(), res.c_str(), ret);
    
    return;
}

int SrsHttpHooks::on_dvr(int cid, string url, SrsRequest* req, string file)
{
    int ret = ERROR_SUCCESS;
    
    int client_id = cid;
    std::string cwd = _srs_config->cwd();
    
    std::stringstream ss;
    ss << SRS_JOBJECT_START
        << SRS_JFIELD_STR("action", "on_dvr") << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("client_id", client_id) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("ip", req->ip) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("vhost", req->vhost) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("app", req->app) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("stream", req->stream) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("param", req->param) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("cwd", cwd) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("file", file)
        << SRS_JOBJECT_END;
        
    std::string data = ss.str();
    std::string res;
    int status_code;
    if ((ret = do_post(url, data, status_code, res)) != ERROR_SUCCESS) {
        srs_error("http post on_dvr uri failed, ignored. "
            "client_id=%d, url=%s, request=%s, response=%s, code=%d, ret=%d",
            client_id, url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return ret;
    }
    
    srs_trace("http hook on_dvr success. "
        "client_id=%d, url=%s, request=%s, response=%s, ret=%d",
        client_id, url.c_str(), data.c_str(), res.c_str(), ret);
    
    return ret;
}

int SrsHttpHooks::on_hls(int cid, string url, SrsRequest* req, string file, string ts_url, string m3u8, string m3u8_url, int sn, double duration)
{
    int ret = ERROR_SUCCESS;
    
    int client_id = cid;
    std::string cwd = _srs_config->cwd();
    
    // the ts_url is under the same dir of m3u8_url.
    string prefix = srs_path_dirname(m3u8_url);
    if (!prefix.empty() && !srs_string_is_http(ts_url)) {
        ts_url = prefix + "/" + ts_url;
    }
    
    std::stringstream ss;
    ss << SRS_JOBJECT_START
        << SRS_JFIELD_STR("action", "on_hls") << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("client_id", client_id) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("ip", req->ip) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("vhost", req->vhost) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("app", req->app) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("stream", req->stream) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("param", req->param) << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("duration", duration) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("cwd", cwd) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("file", file) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("url", ts_url) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("m3u8", m3u8) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR("m3u8_url", m3u8_url) << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG("seq_no", sn)
        << SRS_JOBJECT_END;
        
    std::string data = ss.str();
    std::string res;
    int status_code;
    if ((ret = do_post(url, data, status_code, res)) != ERROR_SUCCESS) {
        srs_error("http post on_hls uri failed, ignored. "
            "client_id=%d, url=%s, request=%s, response=%s, code=%d, ret=%d",
            client_id, url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return ret;
    }
    
    srs_trace("http hook on_hls success. "
        "client_id=%d, url=%s, request=%s, response=%s, ret=%d",
        client_id, url.c_str(), data.c_str(), res.c_str(), ret);
    
    return ret;
}

int SrsHttpHooks::on_hls_notify(int cid, std::string url, SrsRequest* req, std::string ts_url, int nb_notify)
{
    int ret = ERROR_SUCCESS;
    
    int client_id = cid;
    std::string cwd = _srs_config->cwd();
    
    if (srs_string_is_http(ts_url)) {
        url = ts_url;
    }
    
    url = srs_string_replace(url, "[app]", req->app);
    url = srs_string_replace(url, "[stream]", req->stream);
    url = srs_string_replace(url, "[ts_url]", ts_url);
    url = srs_string_replace(url, "[param]", req->param);
    
    int64_t starttime = srs_update_system_time_ms();
    
    SrsHttpUri uri;
    if ((ret = uri.initialize(url)) != ERROR_SUCCESS) {
        srs_error("http: post failed. url=%s, ret=%d", url.c_str(), ret);
        return ret;
    }
    
    SrsHttpClient http;
    if ((ret = http.initialize(uri.get_host(), uri.get_port(), SRS_HLS_NOTIFY_TIMEOUT_US)) != ERROR_SUCCESS) {
        return ret;
    }
    
    std::string path = uri.get_query();
    if (path.empty()) {
        path = uri.get_path();
    } else {
        path = uri.get_path();
        path += "?";
        path += uri.get_query();
    }
    srs_warn("GET %s", path.c_str());
    
    ISrsHttpMessage* msg = NULL;
    if ((ret = http.get(path.c_str(), "", &msg)) != ERROR_SUCCESS) {
        return ret;
    }
    SrsAutoFree(ISrsHttpMessage, msg);
    
    int nb_buf = srs_min(nb_notify, SRS_HTTP_READ_BUFFER);
    char* buf = new char[nb_buf];
    LB_ADD_MEM(buf, nb_buf);
    SrsAutoFreeA(char, buf);
    
    int nb_read = 0;
    ISrsHttpResponseReader* br = msg->body_reader();
    while (nb_read < nb_notify && !br->eof()) {
        int nb_bytes = 0;
        if ((ret = br->read(buf, nb_buf, &nb_bytes)) != ERROR_SUCCESS) {
            break;
        }
        nb_read += nb_bytes;
    }
    
    int spenttime = (int)(srs_update_system_time_ms() - starttime);
    srs_trace("http hook on_hls_notify success. client_id=%d, url=%s, code=%d, spent=%dms, read=%dB, ret=%d",
        client_id, url.c_str(), msg->status_code(), spenttime, nb_read, ret);
    
    // ignore any error for on_hls_notify.
    ret = ERROR_SUCCESS;
    
    return ret;
}

int SrsHttpHooks::on_digest_authorize(std::string url, std::string contenttype, std::string user_name, std::string realm, std::string method, std::string uri, std::string nonce, std::string response)
{
    int ret = ERROR_SUCCESS;
    srs_trace("on_digest_authorize(url:%s, user_name:%s, realm:%s, method:%s, uri:%s, nonce:%s, response:%s)", url.c_str(), user_name.c_str(), realm.c_str(), method.c_str(), uri.c_str(), nonce.c_str(), response.c_str());
    std::stringstream ss;
    /*if("x-www-form-urlencoded" == contenttype)
    {
        ss << SV_HTTP_HOOKS_PARAM_RTMP_APP_NAME << "=" << req->app << 
        "&" << SV_HTTP_HOOKS_PARAM_RTMP_STREAM_NAME << "=" << req->stream <<
        "&" << SV_HTTP_HOOKS_PARAM_RTMP_DISCONNECT_TYPE << "=" << req->disconnect_type;
    }
    else*/ if("application/json" == contenttype)
    {
        ss << SRS_JOBJECT_START << "\r\n"
        << SRS_JFIELD_NAME("Authorization") << SRS_JOBJECT_START << "\r\n"
        << SRS_JFIELD_STR("type", "Digest") << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_DIGEST_AUTH_PARAM_METHOD, method) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_DIGEST_AUTH_PARAM_USER_NAME, user_name) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_DIGEST_AUTH_PARAM_REALM, realm) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_DIGEST_AUTH_PARAM_NONCE, nonce) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_DIGEST_AUTH_PARAM_URI, uri) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_DIGEST_AUTH_PARAM_RESPONSE, response) << "\r\n"
        << SRS_JOBJECT_END;
    }
    std::string data = ss.str();
     srs_trace("send request:%s\n", data.c_str());
    std::string res;
    int status_code;
    if ((ret = do_post(url, contenttype, data, status_code, res)) != ERROR_SUCCESS) {
        srs_error("http post on_connect uri failed, ignored. "
            "url=%s, request=%s, response=%s, code=%d, ret=%d",
            url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return ret;
    }
    //srs_trace("before ret = get_response_msg(res, statecode, statemsg)");
    int statecode = 0;
    std::string statemsg;
    ret = get_response_msg(res, statecode, statemsg);
    if(ERROR_SUCCESS != ret || 200 != statecode)
    {
        srs_error("http on_connect response failed, ret:%d, statecode:%d, statemsg:%s", ret, statecode, statemsg.c_str());
    }
    else
    {
        srs_info("http hook on_connect success. statecode:%d, statemsg:%s, ret:%d", statecode, statemsg.c_str(), ret);
    }
    srs_trace("request:%s, response:%s\n", data.c_str(), res.c_str());
    return ret;
}

int SrsHttpHooks::on_play_action(std::string url, std::string contenttype, std::string devicesn, std::string protocol, std::string token, std::string action)
{
    std::stringstream ss;
    //string contenttype = "application/json";
    std::string data;
    int code = 0, ret = 0;
    std::string resp;
    string stateMsg;
    if("application/json" == contenttype)
    {
        ss << SRS_JOBJECT_START << "\r\n"
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_DEVICE_SN, devicesn) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_PROTOCOL, protocol) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_TOKEN, token) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_ACTION, action) << "\r\n"
        << SRS_JOBJECT_END;
    }
    else
    {
        srs_error("Invalid content type %s\n", contenttype.c_str());
        return -1;
    }
    data = ss.str();
    ret = SrsHttpHooks::do_post2(url, contenttype, data, code, resp);
    if(ERROR_SUCCESS != ret)
    {
        srs_error("post %s failed\ncode:%d, response:%s\n", data.c_str(), code, resp.c_str());
    }
    SRS_CHECK_RESULT(ret);
    if(!resp.empty())
    {
        SrsJsonAny* info = SrsJsonAny::loads((char*)resp.c_str());
        if (!info) {
            srs_error("invalid response info:%p. ret=%d", info, ret);
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        SrsAutoFree(SrsJsonAny, info);
        
        // response error code in string.
        if (!info->is_object()) {
            srs_error("invalid object !info->is_object()");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        SrsJsonAny* res_code = NULL;
        SrsJsonObject* res_info = info->to_object();
        if (res_code = res_info->ensure_property_integer("stateCode"))
        {
        //srs_error("invalid response while parser stateCode failed");
        //return ERROR_JSON_STRING_PARSER_FAIL;
            code = res_code->to_integer();
        }

        if (res_code = res_info->ensure_property_string("stateMsg")) {
            //srs_error("invalid response while parser stateMsg failed");
            //return ERROR_JSON_STRING_PARSER_FAIL;
            stateMsg = res_code->to_str();
        }
    }

    if(200 != code)
    {
        srs_error("code:%d, msg:%s, protocol:%s, devicesn:%s, token:%s, action:%s\n", code, stateMsg.c_str(), protocol.c_str(), devicesn.c_str(), token.c_str(), action.c_str());
        ret = -1;
    }
    else
    {
        srs_trace("play action success, protocol:%s, devicesn:%s, token:%s, action:%s\n", protocol.c_str(), devicesn.c_str(), token.c_str(), action.c_str());
        ret = ERROR_SUCCESS;
    }
    
    return ret;
}

int SrsHttpHooks::thirdpart_event_notify(SrsRequest* req, std::string event_type)
{
    if(NULL == req || e_push_stream_type_live != req->streamType)
    {
        return -1;
    }
    bool enable = _srs_config->get_bool_config("enabled", false, req->vhost.c_str(), "http_hooks_on_paly");
    string url = _srs_config->get_string_config("on_event", NULL, req->vhost.c_str(), "http_hooks_on_paly");
    if(!enable || url.empty())
    {
        return 0;
    }
     char hostnaem[256] = {0};
    gethostname(hostnaem, 256);
    //std::string ip = srs_get_local_ip(_rtmp_server->get_fd(), NULL);
    event_type = "srs_" + std::string(hostnaem) + "_" + event_type;
    url = srs_string_replace(url, "[devicesn]", req->devicesn);
    url = srs_string_replace(url, "[event_type]", event_type);
    srs_debug("thirdpart_event_notify url:%s\n", url.c_str());
    std::string method = "POST";
    std::string body, resp;
    stringstream ss;
    ss << SRS_JOBJECT_START << "\r\n"
    << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_DEVICE_SN, req->devicesn) << SRS_JFIELD_CONT
    << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_EVENT_TYPE, event_type)
    << SRS_JOBJECT_END;
    body = ss.str();//"{\r\n\"device_sn\"=\"P020101000101200707400001\"\r\n}\r\n";
    CHttpClient httpclient;
    srs_trace("before httpclient.send_req_and_get_resp(method, url:%s, body, resp)\n", url.c_str());
    int ret = httpclient.send_req_and_get_resp(method, url, body, resp);
     srs_trace("ret:%d = httpclient.send_req_and_get_resp(method:%s, url, body:%s, resp:%s)\n", ret, body.c_str(), resp.c_str());
    return ret;
}

int SrsHttpHooks::do_post(std::string url, std::string req, int& code, string& res)
{
    int ret = ERROR_SUCCESS;
    
    SrsHttpUri uri;
    if ((ret = uri.initialize(url)) != ERROR_SUCCESS) {
        srs_error("http: post failed. url=%s, ret=%d", url.c_str(), ret);
        return ret;
    }
    
    SrsHttpClient http;
    if ((ret = http.initialize(uri.get_host(), uri.get_port())) != ERROR_SUCCESS) {
        return ret;
    }
    
    ISrsHttpMessage* msg = NULL;
    if ((ret = http.post(uri.get_path(), req, &msg)) != ERROR_SUCCESS) {
        return ret;
    }
    SrsAutoFree(ISrsHttpMessage, msg);
    
    code = msg->status_code();
    if ((ret = msg->body_read_all(res)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // ensure the http status is ok.
    // https://github.com/ossrs/srs/issues/158
    if (code != SRS_CONSTS_HTTP_OK) {
        ret = ERROR_HTTP_STATUS_INVALID;
        srs_error("invalid response status=%d. ret=%d", code, ret);
        return ret;
    }
    
    // should never be empty.
    if (res.empty()) {
        ret = ERROR_HTTP_DATA_INVALID;
        srs_error("invalid empty response. ret=%d", ret);
        return ret;
    }
    
    // parse string res to json.
    SrsJsonAny* info = SrsJsonAny::loads((char*)res.c_str());
    if (!info) {
        ret = ERROR_HTTP_DATA_INVALID;
        srs_error("invalid response %s. ret=%d", res.c_str(), ret);
        return ret;
    }
    SrsAutoFree(SrsJsonAny, info);
    
    // response error code in string.
    if (!info->is_object()) {
        if (res != SRS_HTTP_RESPONSE_OK) {
            ret = ERROR_HTTP_DATA_INVALID;
            srs_error("invalid response number %s. ret=%d", res.c_str(), ret);
            return ret;
        }
        return ret;
    }
    
    // response standard object, format in json: {"code": 0, "data": ""}
    SrsJsonObject* res_info = info->to_object();
    SrsJsonAny* res_code = NULL;
    if ((res_code = res_info->ensure_property_integer("code")) == NULL) {
        ret = ERROR_RESPONSE_CODE;
        srs_error("invalid response without code, ret=%d", ret);
        return ret;
    }

    if ((res_code->to_integer()) != ERROR_SUCCESS) {
        ret = ERROR_RESPONSE_CODE;
        srs_error("error response code=%d. ret=%d", res_code->to_integer(), ret);
        return ret;
    }
    
    return ret;
}

int SrsHttpHooks::on_authorize(std::string url, std::string contenttype, SrsRequest* req)
{
    int ret = ERROR_SUCCESS;
    int stateCode = 0;
    string stateMsg;
    if(!req)
    {
        srs_error("token auth failed, req:%p", req);
        return ERROR_RTMP_TOKEN_AUTH_FAIL;
    }
    srs_info("(url:%s, contenttype:%s, req->token:%s)", url.c_str(), contenttype.c_str(), req->token.c_str());
    std::stringstream ss;
    if("x-www-form-urlencoded" == contenttype)
    {
        ss << SV_HTTP_HOOKS_PARAM_TOKEN << "=" << req->token <<
        "&" << SV_HTTP_HOOKS_PARAM_RTMP_APP_NAME << "=" << req->app <<
        "&" << SV_HTTP_HOOKS_PARAM_RTMP_DEVICESN << "=" << req->devicesn;
        
    }
    else if("application/json" == contenttype)
    {
        ss << SRS_JOBJECT_START << "\r\n"
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_TOKEN, req->token) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_RTMP_APP_NAME, req->app) << SRS_JFIELD_CONT //"\r\n"
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_RTMP_DEVICESN, req->devicesn) << "\r\n"
        //<< SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_RTMP_STREAM_NAME, req->stream) << "\r\n" 
        << SRS_JOBJECT_END;
    }
    std::string data = ss.str();
    std::string res;
    int status_code;
    if ((ret = do_post(url, contenttype, data, status_code, res)) != ERROR_SUCCESS) {
        srs_error("http post on_authorize uri failed, ignored. "
            "url=%s, request=%s, response=%s, code=%d, ret=%d",
            url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return ret;
    }
    
    /*int statecode = 0;
    std::string statemsg;
    ret = get_response_msg(res, statecode, statemsg);
    if(ERROR_SUCCESS != ret || 200 != statecode)
    {
        srs_error("http on_authorize response failed, ret:%d, statecode:%d, statemsg:%s", ret, statecode, statemsg.c_str());
        return ERROR_RTMP_CONNECT_TOKEN_AUTH_FAIL;
    }
    else
    {
        srs_trace("http hook on_authorize success. statecode:%d, statemsg:%s, ret:%d", statecode, statemsg.c_str(), ret);
    }*/
    SrsJsonAny* info = SrsJsonAny::loads((char*)res.c_str());
    if (!info) {
        //ret = ERROR_JSON_STRING_PARSER_FAIL;
        srs_error("invalid response info:%p. ret=%d", info, ret);
        return ERROR_JSON_STRING_PARSER_FAIL;
    }
    SrsAutoFree(SrsJsonAny, info);
    
    // response error code in string.
    if (!info->is_object()) {
        /*if (ret != ERROR_SUCCESS) {
            srs_error("invalid response number, info:%p", info);
            return ;
        }*/
        srs_error("invalid object !info->is_object()");
        return ERROR_JSON_STRING_PARSER_FAIL;
    }
    
    // response standard object, format in json: {"code": 0, "data": ""}
    SrsJsonObject* res_info = info->to_object();
    SrsJsonAny* res_code = NULL;
    if(res_info->get_property("data"))
    {
        if ((res_code = res_info->ensure_property_integer("stateCode")) == NULL) {
	        srs_error("invalid response while parser stateCode failed");
	        return ERROR_JSON_STRING_PARSER_FAIL;
        }
        stateCode = res_code->to_integer();

        if ((res_code = res_info->ensure_property_string("stateMsg")) == NULL) {
            srs_error("invalid response while parser stateMsg failed");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
    
        stateMsg = res_code->to_str();
        srs_info("stateCode:%d, stateMsg:%s = res_code->to_str()", stateCode, stateMsg.c_str());

        if(200 == stateCode)
        {
            if ((res_code = res_info->get_property("data")) == NULL) {
                srs_error("invalid response while parser stateMsg failed");
                return ERROR_JSON_STRING_PARSER_FAIL;
            }
            if (!res_code->is_object()) {
                srs_error("invalid data object !info->is_object()");
                return ERROR_JSON_STRING_PARSER_FAIL;
            }
            res_info = res_code->to_object(); 
        }
    
    }

    if(!res_info)
    {
        srs_error("res_info:%p = res_code->to_object() failed\n", res_info);
        return ERROR_JSON_STRING_PARSER_FAIL;
    }
    if ((res_code = res_info->ensure_property_string("appKey")) == NULL) {
        srs_error("invalid response while parser appKey failed");
        return ERROR_JSON_STRING_PARSER_FAIL;
    }
    string appKey = res_code->to_str();
    if (res_code = res_info->ensure_property_string("userId")) {
        req->userid = res_code->to_str();
    }
    else
    {
        srs_warn("warning! parser userId failed, use default userid");
        //req->userid = "dawson";
    }
    //srs_trace("stateCode:%d, stateMsg:%s, appKey:%s", stateCode, stateMsg.c_str(), appKey.c_str());
    
    req->appkey = appKey;
    srs_debug("authorize success, stateCode:%d, stateMsg:%s, appKey:%s, req->stream:%s", stateCode, stateMsg.c_str(), req->appkey.c_str(), req->userid.c_str(), req->stream.c_str());
    return ERROR_SUCCESS;
    
    return ERROR_RTMP_TOKEN_AUTH_FAIL;
}

int SrsHttpHooks::on_connect(std::string url, std::string contenttype, SrsRequest* req)
{
    int ret = ERROR_SUCCESS;
    srs_info("(url:%s, contenttype:%s, req:%p)", url.c_str(), contenttype.c_str(), req);
    std::stringstream ss;
    if("x-www-form-urlencoded" == contenttype)
    {
        ss << SV_HTTP_HOOKS_PARAM_APPKEY_NAME << "=" << req->appkey << 
        "&" << SV_HTTP_HOOKS_PARAM_DEVICE_SN << "=" << req->devicesn;
    }
    else if("application/json" == contenttype)
    {
        ss << SRS_JOBJECT_START << "\r\n"
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_APPKEY_NAME, req->appkey) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_DEVICE_SN, req->devicesn) << "\r\n"
        << SRS_JOBJECT_END;
    }
    std::string data = ss.str();
    std::string res;
    int status_code;
    if ((ret = do_post(url, contenttype, data, status_code, res)) != ERROR_SUCCESS) {
        srs_error("http post on_connect uri failed, ignored. "
            "url=%s, request=%s, response=%s, code=%d, ret=%d",
            url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return ret;
    }
    srs_verbose("before ret = get_response_msg(res, statecode, statemsg)");
    int statecode = 0;
    std::string statemsg;
    ret = get_response_msg(res, statecode, statemsg);
    if(ERROR_SUCCESS != ret || 200 != statecode)
    {
        srs_error("http on_connect response failed, ret:%d, statecode:%d, statemsg:%s", ret, statecode, statemsg.c_str());
    }
    
    return ret;
}

int SrsHttpHooks::on_close(std::string url, std::string contenttype, SrsRequest* req, int64_t send_bytes, int64_t recv_bytes)
{
    int ret = ERROR_SUCCESS;
    srs_info("(url:%s, contenttype:%s, app:%s, stream:%s, disconnect_type:%d, send_bytes%"PRId64", recv_bytes:%"PRId64")", url.c_str(), contenttype.c_str(), req->devicesn.c_str(), req->app.c_str(), req->stream.c_str(), req->disconnect_type, send_bytes, recv_bytes);
    std::stringstream ss;
    if("x-www-form-urlencoded" == contenttype)
    {
        ss << SV_HTTP_HOOKS_PARAM_RTMP_APP_NAME << "=" << req->app << 
        "&" << SV_HTTP_HOOKS_PARAM_RTMP_STREAM_NAME << "=" << req->stream <<
        "&" << SV_HTTP_HOOKS_PARAM_RTMP_DISCONNECT_TYPE << "=" << req->disconnect_type;
    }
    else if("application/json" == contenttype)
    {
        ss << SRS_JOBJECT_START << "\r\n"
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_RTMP_APP_NAME, req->app) << SRS_JFIELD_CONT
        << SRS_JFIELD_STR(SV_HTTP_HOOKS_PARAM_RTMP_STREAM_NAME, req->stream) << SRS_JFIELD_CONT
        << SRS_JFIELD_ORG(SV_HTTP_HOOKS_PARAM_RTMP_DISCONNECT_TYPE, req->disconnect_type) << "\r\n"
        << SRS_JOBJECT_END;
    }
    std::string data = ss.str();
    std::string res;
    int status_code;
    if ((ret = do_post(url, contenttype, data, status_code, res)) != ERROR_SUCCESS) {
        srs_error("http post on_connect uri failed, ignored. "
            "url=%s, request=%s, response=%s, code=%d, ret=%d",
            url.c_str(), data.c_str(), res.c_str(), status_code, ret);
        return ret;
    }
    //srs_trace("before ret = get_response_msg(res, statecode, statemsg)");
    int statecode = 0;
    std::string statemsg;
    ret = get_response_msg(res, statecode, statemsg);
    if(ERROR_SUCCESS != ret || 200 != statecode)
    {
        srs_error("http on_connect response failed, ret:%d, statecode:%d, statemsg:%s", ret, statecode, statemsg.c_str());
    }
    else
    {
        srs_info("http hook on_connect success. statecode:%d, statemsg:%s, ret:%d", statecode, statemsg.c_str(), ret);
    }
    
    return ret;
}

int SrsHttpHooks::on_publish(std::string url, std::string contenttype, SrsRequest* req)
{
    return ERROR_SUCCESS;
}

void SrsHttpHooks::on_unpublish(std::string url, std::string contenttype, SrsRequest* req)
{
}

int SrsHttpHooks::on_hls(int cid, std::string url, std::string contenttype, SrsRequest* req, std::string file, std::string ts_url, std::string m3u8, std::string m3u8_url, int sn, double duration)
{
    return ERROR_SUCCESS;
}

int SrsHttpHooks::do_post(std::string url, std::string contenttype, std::string req, int& code, std::string& res)
{
    //return do_post2(url, contenttype, req, code, res);
    if(0 == url.find("https://"))
    {
        return do_post2(url, contenttype, req, code, res);
        //return do_post_https(url, contenttype, req, code, res);
    }
    int ret = ERROR_SUCCESS;
    srs_info("(url:%s, contenttype:%s, req:%s) begin", url.c_str(), contenttype.c_str(), req.c_str());
    SrsHttpUri uri;
    if ((ret = uri.initialize(url)) != ERROR_SUCCESS) {
        srs_error("http: post failed. url=%s, ret=%d", url.c_str(), ret);
        return ret;
    }
    
    SrsHttpClient http;
    if ((ret = http.initialize(uri.get_host(), uri.get_port())) != ERROR_SUCCESS) {
        srs_error("ret:%d = http.initialize(uri.get_host():%s, uri.get_port():%d) failed", ret, uri.get_host(), uri.get_port());
        return ret;
    }
    
    ISrsHttpMessage* msg = NULL;
    if ((ret = http.post(uri.get_path(), contenttype, req, &msg)) != ERROR_SUCCESS) {
        srs_error("ret:%d = http.post(uri.get_path():%s, contenttype:%s, req:%s, &msg:%p) failed", ret, uri.get_path(), contenttype.c_str(), req.c_str(), msg);
        return ret;
    }
    SrsAutoFree(ISrsHttpMessage, msg);
    
    code = msg->status_code();
    if ((ret = msg->body_read_all(res)) != ERROR_SUCCESS) {
        srs_error("ret:%d = msg->body_read_all(res:%s) failed", ret, res.c_str());
        return ret;
    }
    srs_info("code:%d, res:%s", code, res.c_str());
    // ensure the http status is ok.
    // https://github.com/ossrs/srs/issues/158
    if (code != SRS_CONSTS_HTTP_OK) {
        ret = ERROR_HTTP_STATUS_INVALID;
        srs_error("invalid response status=%d. ret=%d", code, ret);
        return ret;
    }
    
    // should never be empty.
    if (res.empty()) {
        ret = ERROR_HTTP_DATA_INVALID;
        srs_error("invalid empty response. ret=%d", ret);
        return ret;
    }

    return ret;
}

int SrsHttpHooks::do_post2(std::string url, std::string contenttype, std::string req, int& code, std::string& res)
{
    int ret = 0;
    lbsp_util::CHttpClient httpclient;
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    ret = httpclient.parser_url(url);
    if(ret < 0)
    {
        lberror("parser http url %s failed, ret:%d\n", url.c_str(), ret);
        return ret;
    }
    // send POST request to uri
    // POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s
    std::stringstream ss;
    ss << "POST " << httpclient.get_path() << " "
        << "HTTP/1.1" << SRS_HTTP_CRLF
        << "Host: " << httpclient.get_host() << SRS_HTTP_CRLF
        << "Connection: Keep-Alive" << SRS_HTTP_CRLF
        << "Content-Length: " << std::dec << req.length() << SRS_HTTP_CRLF
        << "User-Agent: " << RTMP_SIG_SRS_NAME << RTMP_SIG_SRS_VERSION << SRS_HTTP_CRLF
        << "srs-server-host: "<< hostname << SRS_HTTP_CRLF
        //<< "x-forwarded-for: "<< slocal_host_name << SRS_HTTP_CRLF
        << "Content-Type: "<< contenttype << SRS_HTTP_CRLF
        << SRS_HTTP_CRLF
        << req;
    /*std::stringstream ss;
    ss << "POST " << httpclient.get_path() << " "
        << "HTTP/1.1" << SRS_HTTP_CRLF
        << "Host: " << httpclient.get_host() << SRS_HTTP_CRLF
        << "Connection: Keep-Alive" << SRS_HTTP_CRLF
        << "Content-Length: " << std::dec << req.length() << SRS_HTTP_CRLF
        << "User-Agent: " << RTMP_SIG_SRS_NAME << RTMP_SIG_SRS_VERSION << SRS_HTTP_CRLF
        << "srs-server-host: "<< hostname << SRS_HTTP_CRLF
        //<< "x-forwarded-for: "<< slocal_host_name << SRS_HTTP_CRLF
        << "Content-Type: "<< contenttype << SRS_HTTP_CRLF
        << SRS_HTTP_CRLF
        << req;*/
    
    std::string data = ss.str();

    
    
    std::string resp;
    ret = httpclient.send_request_and_get_response(data, code, resp);
    //srs_trace("ret:%d = httpclient.send_request_and_get_response(req:%s, code:%d, resp:%s)\n", ret, req.c_str(), code, resp.c_str());
    if(ret != ERROR_SUCCESS || code != 200)
    {
        //code = 0;
        lberror("ret:%d = httpclient.send_request_and_get_response(data:%s, code:%d, resp:%s) failed\n", ret, data.c_str(), code, resp.c_str());
        return ret;
    }
    //code = 200;
    res = httpclient.get_body();
    //srs_trace("body:%s\n", res.c_str());
    return res.empty() ? ERROR_HTTP_HANDLER_INVALID : ERROR_SUCCESS;
}

int SrsHttpHooks::get_response_msg(std::string res, int& code, std::string& statemsg)
{
    srs_verbose("(res:%s) begin", res.c_str());
    SrsJsonAny* info = SrsJsonAny::loads((char*)res.c_str());
    if (!info) {
        //ret = ERROR_JSON_STRING_PARSER_FAIL;
        srs_error("invalid response info:%p. res=%s", info, res.c_str());
        return ERROR_JSON_LOADS;
    }
    SrsAutoFree(SrsJsonAny, info);
    
    // response error code in string.
    if (!info->is_object()) {
        /*if (ret != ERROR_SUCCESS) {
            srs_error("invalid response number, info:%p", info);
            return ;
        }*/
        srs_error("invalid object !info->is_object()");
        return ERROR_JSON_STRING_PARSER_FAIL;
    }
    
    // parser json result
    SrsJsonObject* res_info = info->to_object();
    SrsJsonAny* result = NULL;
    srs_verbose("before  res_info->ensure_property_integer(stateCode)");
    if ((result = res_info->ensure_property_integer("stateCode")) == NULL) {
        srs_error("invalid response while parser stateCode without stateCode, result:%p", result);
        return ERROR_JSON_STRING_PARSER_FAIL;
    }
    code = (int)result->to_integer();
    srs_verbose("before  res_info->ensure_property_string(stateMsg)");
    if ((result = res_info->ensure_property_string("stateMsg")) == NULL) {
        srs_error("invalid response while parser push_ts without stateMsg, result:%p, statecode:%d", result, code);
        return ERROR_JSON_STRING_PARSER_FAIL;
    }
    srs_verbose("before  statemsg = result->to_str()");
    statemsg = result->to_str();
    srs_verbose("code:%d, statemsg:%s", code, statemsg.c_str());
    return ERROR_SUCCESS;
}
#endif
