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

#ifndef SRS_APP_HTTP_HOOKS_HPP
#define SRS_APP_HTTP_HOOKS_HPP

#define SV_HTTP_HOOKS_PARAM_APPKEY_NAME          "appKey"
#define SV_HTTP_HOOKS_PARAM_DEVICE_SN            "deviceSN"
#define SV_HTTP_HOOKS_PARAM_TOKEN                "token"
#define SV_HTTP_HOOKS_PARAM_RTMP_APP_NAME        "rtmpAppName"
#define SV_HTTP_HOOKS_PARAM_RTMP_STREAM_NAME     "rtmpStreamName"
#define SV_HTTP_HOOKS_PARAM_RTMP_DEVICESN        "deviceSN"
#define SV_HTTP_HOOKS_PARAM_RTMP_DISCONNECT_TYPE "disconnectType"
#define SV_HTTP_HOOKS_PARAM_ACTION               "action"
#define SV_HTTP_HOOKS_PARAM_PROTOCOL             "protocol"
#define SV_HTTP_HOOKS_PARAM_EVENT_TYPE           "event_type"

#define SV_DIGEST_AUTH_PARAM_METHOD               "method"
#define SV_DIGEST_AUTH_PARAM_USER_NAME            "user_name"
#define SV_DIGEST_AUTH_PARAM_REALM                "realm"
#define SV_DIGEST_AUTH_PARAM_NONCE                "nonce"
#define SV_DIGEST_AUTH_PARAM_URI                  "uri"
#define SV_DIGEST_AUTH_PARAM_RESPONSE             "response"
/*
#include <srs_app_http_hooks.hpp>
*/
#include <srs_core.hpp>

#include <string>

#ifdef SRS_AUTO_HTTP_CALLBACK

#include <http_parser.h>

class SrsHttpUri;
class SrsStSocket;
class SrsRequest;
class SrsHttpParser;
class SrsFlvSegment;

/**
* the http hooks, http callback api,
* for some event, such as on_connect, call
* a http api(hooks).
*/
class SrsHttpHooks
{
private:
    SrsHttpHooks();
public:
    virtual ~SrsHttpHooks();
public:
    /**
    * on_connect hook, when client connect to srs.
    * @param url the api server url, to valid the client. 
    *         ignore if empty.
    */
    static int on_connect(std::string url, SrsRequest* req);
    /**
    * on_close hook, when client disconnect to srs, where client is valid by on_connect.
    * @param url the api server url, to process the event. 
    *         ignore if empty.
    */
    static void on_close(std::string url, SrsRequest* req, int64_t send_bytes, int64_t recv_bytes);
    /**
    * on_publish hook, when client(encoder) start to publish stream
    * @param url the api server url, to valid the client. 
    *         ignore if empty.
    */
    static int on_publish(std::string url, SrsRequest* req);
    /**
    * on_unpublish hook, when client(encoder) stop publish stream.
    * @param url the api server url, to process the event. 
    *         ignore if empty.
    */
    static void on_unpublish(std::string url, SrsRequest* req);
    /**
    * on_play hook, when client start to play stream.
    * @param url the api server url, to valid the client. 
    *         ignore if empty.
    */
    static int on_play(std::string url, SrsRequest* req);
    /**
    * on_stop hook, when client stop to play the stream.
    * @param url the api server url, to process the event. 
    *         ignore if empty.
    */
    static void on_stop(std::string url, SrsRequest* req);
    /**
     * on_dvr hook, when reap a dvr file.
     * @param url the api server url, to process the event.
     *         ignore if empty.
     * @param file the file path, can be relative or absolute path.
     * @param cid the source connection cid, for the on_dvr is async call.
     */
    static int on_dvr(int cid, std::string url, SrsRequest* req, std::string file);
    /**
     * when hls reap segment, callback.
     * @param url the api server url, to process the event.
     *         ignore if empty.
     * @param file the ts file path, can be relative or absolute path.
     * @param ts_url the ts url, which used for m3u8.
     * @param m3u8 the m3u8 file path, can be relative or absolute path.
     * @param m3u8_url the m3u8 url, which is used for the http mount path.
     * @param sn the seq_no, the sequence number of ts in hls/m3u8.
     * @param duration the segment duration in seconds.
     * @param cid the source connection cid, for the on_dvr is async call.
     */
    static int on_hls(int cid, std::string url, SrsRequest* req, std::string file, std::string ts_url, std::string m3u8, std::string m3u8_url, int sn, double duration);
    /**
     * when hls reap segment, callback.
     * @param url the api server url, to process the event.
     *         ignore if empty.
     * @param ts_url the ts uri, used to replace the variable [ts_url] in url.
     * @param nb_notify the max bytes to read from notify server.
     * @param cid the source connection cid, for the on_dvr is async call.
     */
    static int on_hls_notify(int cid, std::string url, SrsRequest* req, std::string ts_url, int nb_notify);

    // add by dawson below
    /**
    * on_connect hook, when client connect to srs. http notify with contenttype
    * @param url the api server url, to valid the client. 
    *         ignore if empty.
    */
    static int on_authorize(std::string url, std::string contenttype, SrsRequest* req);

    /**
    * on_connect hook, when client connect to srs. http notify with contenttype
    * @param url the api server url, to valid the client. 
    *         ignore if empty.
    */
    static int on_connect(std::string url, std::string contenttype, SrsRequest* req);

    /**
    * on_close hook, when client disconnect to srs, where client is valid by on_connect.
    * @param url the api server url, to process the event. 
    *         ignore if empty.
    */
    static int on_close(std::string url, std::string contenttype, SrsRequest* req, int64_t send_bytes, int64_t recv_bytes);

    /**
    * on_publish hook, when client(encoder) start to publish stream
    * @param url the api server url, to valid the client. 
    *         ignore if empty.
    */
    static int on_publish(std::string url, std::string contenttype, SrsRequest* req);
    /**
    * on_unpublish hook, when client(encoder) stop publish stream.
    * @param url the api server url, to process the event. 
    *         ignore if empty.
    */
    static void on_unpublish(std::string url, std::string contenttype, SrsRequest* req);

    /**
     * when hls reap segment, callback.
     * @param url the api server url, to process the event.
     *         ignore if empty.
     * @param file the ts file path, can be relative or absolute path.
     * @param ts_url the ts url, which used for m3u8.
     * @param m3u8 the m3u8 file path, can be relative or absolute path.
     * @param m3u8_url the m3u8 url, which is used for the http mount path.
     * @param sn the seq_no, the sequence number of ts in hls/m3u8.
     * @param duration the segment duration in seconds.
     * @param cid the source connection cid, for the on_dvr is async call.
     */
    static int on_hls(int cid, std::string url, std::string contenttype, SrsRequest* req, std::string file, std::string ts_url, std::string m3u8, std::string m3u8_url, int sn, double duration);

    static int on_digest_authorize(std::string url, std::string contenttype, std::string user_name, std::string realm, std::string method, std::string uri, std::string nonce, std::string response);

    static int on_play_action(std::string url, std::string contenttype, std::string devicesn, std::string protocol, std::string token, std::string action);

    static int thirdpart_event_notify(SrsRequest* req, std::string event_type);
    //static int on_play_action(std::string url, std::string contenttype, std::string devicesn, std::string protocol, std::string token, std::string action);
    
    static int do_post2(std::string url, std::string contenttype, std::string req, int& code, std::string& res);

private:
    static int do_post(std::string url, std::string req, int& code, std::string& res);

    static int do_post(std::string url, std::string contenttype, std::string req, int& code, std::string& res);

    //static int do_post_https(std::string url, std::string contenttype, std::string req, int& code, std::string& res);

    static int get_response_msg(std::string res, int& code, std::string& statemsg);
    //static int get_response_msg(std::string res, int& code, std::string& statemsg);
};

#endif

#endif

