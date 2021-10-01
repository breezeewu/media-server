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

#ifndef SRS_APP_RTMP_CONN_HPP
#define SRS_APP_RTMP_CONN_HPP

/*
#include <srs_app_rtmp_conn.hpp>
*/

#include <srs_core.hpp>

#include <srs_app_st.hpp>
#include <srs_app_conn.hpp>
#include <srs_app_reload.hpp>
#include <srs_rtmp_stack.hpp>

class SrsServer;
class SrsRtmpServer;
class SrsRequest;
class SrsResponse;
class SrsSource;
class SrsRefer;
class SrsConsumer;
class SrsCommonMessage;
class SrsStSocket;
#ifdef SRS_AUTO_HTTP_CALLBACK    
class SrsHttpHooks;
#endif
class SrsBandwidth;
class SrsKbps;
class SrsRtmpClient;
class SrsSharedPtrMessage;
class SrsQueueRecvThread;
class SrsPublishRecvThread;
class SrsSecurity;
class ISrsWakable;

// aes key encoder type
#define SV_KEY_ENC_TYPE_NONE        0
#define SV_KEY_ENC_TYPE_RSA         1
#define SV_KEY_ENC_TYPE_BASE64      2
#define RTMP_CONNECT_DB_CONF            "rtmp_connect_db"
#define RTMP_CONN_INFO_TABLE_NAME       "connection_info"
#define RTMP_STORAGE_SPACE_INFO_NAME    "storage_space_info"

/**
* the client provides the main logic control for RTMP clients.
*/
class SrsRtmpConn : public virtual SrsConnection, public virtual ISrsReloadHandler
{
    // for the thread to directly access any field of connection.
    friend class SrsPublishRecvThread;
private:
    SrsServer* server;
    SrsRequest* req;
    SrsResponse* res;
    SrsStSocket* skt;
    SrsRtmpServer* rtmp;
    SrsRefer* refer;
    SrsBandwidth* bandwidth;
    SrsSecurity* security;
    // the wakable handler, maybe NULL.
    ISrsWakable* wakable;
    // elapse duration in ms
    // for live play duration, for instance, rtmpdump to record.
    // @see https://github.com/ossrs/srs/issues/47
    int64_t duration;
    SrsKbps* kbps;
    // the MR(merged-write) sleep time in ms.
    int mw_sleep;
    // the MR(merged-write) only enabled for play.
    int mw_enabled;
    // for realtime
    // @see https://github.com/ossrs/srs/issues/257
    bool realtime;
    // the minimal interval in ms for delivery stream.
    double send_min_interval;
    // publish 1st packet timeout in ms
    int publish_1stpkt_timeout;
    // publish normal packet timeout in ms
    int publish_normal_timeout;
    // whether enable the tcp_nodelay.
    bool tcp_nodelay;
    // The type of client, play or publish.
    SrsRtmpConnType client_type;
    unsigned long            llast_active_time;
    std::string              m_slocal_ip;
    int                         m_nport;
    int64_t                     m_llast_ping_timestamp;
    int64_t                     m_lon_connect_timestamp;
    static class   database_connection_manager*    m_pdb_conn_mgr;
public:
    SrsRtmpConn(SrsServer* svr, st_netfd_t c);
    virtual ~SrsRtmpConn();
public:
    virtual void dispose();
protected:
    virtual int do_cycle();
// interface ISrsReloadHandler
public:
    virtual int on_reload_vhost_removed(std::string vhost);
    virtual int on_reload_vhost_mw(std::string vhost);
    virtual int on_reload_vhost_smi(std::string vhost);
    virtual int on_reload_vhost_tcp_nodelay(std::string vhost);
    virtual int on_reload_vhost_realtime(std::string vhost);
    virtual int on_reload_vhost_p1stpt(std::string vhost);
    virtual int on_reload_vhost_pnt(std::string vhost);
// interface IKbpsDelta
public:
    virtual void resample();
    virtual int64_t get_send_bytes_delta();
    virtual int64_t get_recv_bytes_delta();
    virtual void cleanup();
#ifdef SRS_AUTO_FORWARD_WEBRTC
    virtual int send_metadate(SrsOnMetaDataPacket* pmetadata);
#endif
private:
    // when valid and connected to vhost/app, service the client.
    virtual int service_cycle();
    // stream(play/publish) service cycle, identify client first.
    virtual int stream_service_cycle();
    virtual int check_vhost();
    virtual int playing(SrsSource* source);
    virtual int do_playing(SrsSource* source, SrsConsumer* consumer, SrsQueueRecvThread* trd);
    virtual int publishing(SrsSource* source);
    virtual int do_publishing(SrsSource* source, SrsPublishRecvThread* trd);
    virtual int acquire_publish(SrsSource* source, bool is_edge);
    virtual void release_publish(SrsSource* source, bool is_edge);
    virtual int handle_publish_message(SrsSource* source, SrsCommonMessage* msg, bool is_fmle, bool vhost_is_edge);
    virtual int process_publish_message(SrsSource* source, SrsCommonMessage* msg, bool vhost_is_edge);
    virtual int process_play_control_msg(SrsConsumer* consumer, SrsCommonMessage* msg);
    virtual void change_mw_sleep(int sleep_ms);
    virtual void set_sock_options();
private:
    virtual int check_edge_token_traverse_auth();
    virtual int connect_server(int origin_index, st_netfd_t* pstsock);
    virtual int do_token_traverse_auth(SrsRtmpClient* client);
private:
    virtual int http_hooks_on_authorize();// add by dawson for token authorize
    virtual int http_hooks_on_play_authorize(); // add by zwu for play token authorize
    virtual int http_hooks_on_connect();
    virtual void http_hooks_on_play_close();
    virtual void http_hooks_on_close();
    virtual int write_database_on_close();
    virtual int http_hooks_on_publish();
    virtual void http_hooks_on_unpublish();
    virtual int http_hooks_on_play();
    virtual void http_hooks_on_stop();
    virtual bool is_http_hooks_close_enable();

    virtual int on_authorize();
    
    virtual int on_connect();

    virtual void on_close();

    // add by dawson
    virtual int handle_metadata(SrsOnMetaDataPacket* metadata);
    virtual int load_write_data_config();
    virtual int authorize_check(SrsRtmpConnType type);

    virtual std::string decrypt_aes_key(int enc_type, const char* enc_buf, int enc_len);

    int rtmp_connnection_change(int connected);

    bool write_rtmp_conn_enalbe();

    static  long            llive_rtmp_conn;
    static long             llive_svr_cycle;
    static long             llive_publishing;
    SrsRtmpConnType         m_ertmp_conn_type;
/*#ifdef RSA_ENCRYPT_AES_KEY
    virtual std::string rsa_decrypt(const char* ppriv_key, const char* penc_buf, int len);
#endif*/
    //virtual int metadata(SrsOnMetaDataPacket* metadata);
    // add end
};

#endif

