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

#include <srs_app_rtmp_conn.hpp>

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sstream>
using namespace std;

#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_core_autofree.hpp>
#include <srs_app_source.hpp>
#include <srs_app_server.hpp>
#include <srs_app_pithy_print.hpp>
#include <srs_app_config.hpp>
#include <srs_app_refer.hpp>
#include <srs_app_hls.hpp>
#include <srs_app_bandwidth.hpp>
#include <srs_app_st.hpp>
#include <srs_app_http_hooks.hpp>
#include <srs_app_edge.hpp>
#include <srs_app_utility.hpp>
#include <srs_rtmp_msg_array.hpp>
#include <srs_rtmp_amf0.hpp>
#include <srs_app_recv_thread.hpp>
#include <srs_core_performance.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_app_security.hpp>
#include <srs_app_statistic.hpp>
#include <srs_rtmp_utility.hpp>
#include <lbsp_utility_common.hpp>
#include <srs_app_db_conn.hpp>
#include <srs_app_db_conn.hpp>

#define RTMP_HTTP_HOOKS_CONF_NAME "rtmp_http_hooks"
#ifdef RSA_ENCRYPT_AES_KEY
#include <lbsp_rsa_enc.hpp>
//#include <rsa_encrypt.hpp>
extern char prikey[];
extern char pubkey[];
/*char prikey[] = "-----BEGIN PRIVATE KEY-----\r\n\
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
-----END PUBLIC KEY-----";*/
#endif
// when stream is busy, for example, streaming is already
// publishing, when a new client to request to publish,
// sleep a while and close the connection.
#define SRS_STREAM_BUSY_SLEEP_US (int64_t)(3*1000*1000LL)

// the timeout to wait encoder to republish
// if timeout, close the connection.
#define SRS_REPUBLISH_SEND_TIMEOUT_US (int64_t)(3*60*1000*1000LL)
// if timeout, close the connection.
#define SRS_REPUBLISH_RECV_TIMEOUT_US (int64_t)(3*60*1000*1000LL)

// the timeout to wait client data, when client paused
// if timeout, close the connection.
#define SRS_PAUSED_SEND_TIMEOUT_US (int64_t)(30*60*1000*1000LL)
// if timeout, close the connection.
#define SRS_PAUSED_RECV_TIMEOUT_US (int64_t)(30*60*1000*1000LL)

// when edge timeout, retry next.
#define SRS_EDGE_TOKEN_TRAVERSE_TIMEOUT_US (int64_t)(3*1000*1000LL)
long SrsRtmpConn::llive_rtmp_conn(0);
long SrsRtmpConn::llive_svr_cycle(0);
long SrsRtmpConn::llive_publishing(0);
database_connection_manager* SrsRtmpConn::m_pdb_conn_mgr(NULL);
SrsRtmpConn::SrsRtmpConn(SrsServer* svr, st_netfd_t c)
    : SrsConnection(svr, c)
{
    server = svr;
    req = new SrsRequest();
    LB_ADD_MEM(req, sizeof(SrsRequest));
    res = new SrsResponse();
    LB_ADD_MEM(res, sizeof(SrsResponse));
    skt = new SrsStSocket(c);
    LB_ADD_MEM(skt, sizeof(SrsStSocket));
    rtmp = new SrsRtmpServer(skt);
    LB_ADD_MEM(rtmp, sizeof(SrsRtmpServer));
    srs_verbose("%s rtmp:%p = new SrsRtmpServer(skt:%p), skt = new SrsStSocket(c:%p)", __FUNCTION__, rtmp, skt, c);
    refer = new SrsRefer();
    LB_ADD_MEM(refer, sizeof(SrsRefer));
    bandwidth = new SrsBandwidth();
    LB_ADD_MEM(bandwidth, sizeof(SrsBandwidth));
    security = new SrsSecurity();
    LB_ADD_MEM(security, sizeof(SrsSecurity));
    duration = 0;
    kbps = new SrsKbps();
    LB_ADD_MEM(kbps, sizeof(SrsKbps));
    kbps->set_io(skt, skt);
    wakable = NULL;
    
    mw_sleep = SRS_PERF_MW_SLEEP;
    mw_enabled = false;
    realtime = SRS_PERF_MIN_LATENCY_ENABLED;
    send_min_interval = 0;
    tcp_nodelay = false;
    client_type = SrsRtmpConnUnknown;
    m_llast_ping_timestamp = 0;
    m_lon_connect_timestamp = get_local_timestamp();
    // is_receive = false;
    
    _srs_config->subscribe(this);
}

SrsRtmpConn::~SrsRtmpConn()
{
    //srs_trace("destruct SrsRtmpConn begin");
    _srs_config->unsubscribe(this);
    
    srs_freep(req);
    srs_freep(res);
    srs_freep(rtmp);
    srs_freep(skt);
    srs_freep(refer);
    srs_freep(bandwidth);
    srs_freep(security);
    srs_freep(kbps);
    //srs_trace("destruct SrsRtmpConn end");
}

void SrsRtmpConn::dispose()
{
    SrsConnection::dispose();
    
    // wakeup the handler which need to notice.
    if (wakable) {
        wakable->wakeup();
    }
}

// TODO: return detail message when error for client.
int SrsRtmpConn::do_cycle()
{
    int ret = ERROR_SUCCESS;
    llive_rtmp_conn++;
    srs_info("RTMP client ip=%s", ip.c_str());
    req->disconnect_type = RTMP_DISCONNECT_BY_CLIENT;
    rtmp->set_recv_timeout(SRS_CONSTS_RTMP_RECV_TIMEOUT_US);
    rtmp->set_send_timeout(SRS_CONSTS_RTMP_SEND_TIMEOUT_US);
    
    if ((ret = rtmp->handshake()) != ERROR_SUCCESS) {
        //tag_error(get_device_sn(req, 0), "rtmp handshake failed. ret=%d, ip:%s", ret, ip.c_str());
        llive_rtmp_conn--;
        return ret;
    }
    
    // add by dawson for write data test
    load_write_data_config();
    // add end

    srs_verbose("rtmp handshake success");
    
    if ((ret = rtmp->connect_app(req)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "rtmp connect vhost/app failed. ret=%d, llive_rtmp_conn:%ld", ret, llive_rtmp_conn);
        llive_rtmp_conn--;
        return ret;
    }
    srs_verbose("rtmp connect app success");
    
    // add by dawson for rtmp connect notify


    // set client ip to request.
    req->ip = ip;
    
    srs_info("connect app, "
        "tcUrl=%s, pageUrl=%s, swfUrl=%s, schema=%s, vhost=%s, port=%s, app=%s, stream:%s args=%s, devicesn:%s", 
        req->tcUrl.c_str(), req->pageUrl.c_str(), req->swfUrl.c_str(), 
        req->schema.c_str(), req->vhost.c_str(), req->port.c_str(),
        req->app.c_str(), req->stream.c_str(), (req->args? "(obj)":"null"), req->devicesn.c_str());
    
    // show client identity
    if(req->args) {
        std::string srs_version;
        std::string srs_server_ip;
        int srs_pid = 0;
        int srs_id = 0;
        
        SrsAmf0Any* prop = NULL;
        if ((prop = req->args->ensure_property_string("srs_version")) != NULL) {
            srs_version = prop->to_str();
        }
        if ((prop = req->args->ensure_property_string("srs_server_ip")) != NULL) {
            srs_server_ip = prop->to_str();
        }
        if ((prop = req->args->ensure_property_number("srs_pid")) != NULL) {
            srs_pid = (int)prop->to_number();
        }
        if ((prop = req->args->ensure_property_number("srs_id")) != NULL) {
            srs_id = (int)prop->to_number();
        }
        
        srs_info("edge-srs ip=%s, version=%s, pid=%d, id=%d", 
            srs_server_ip.c_str(), srs_version.c_str(), srs_pid, srs_id);
        if (srs_pid > 0) {
            srs_trace("edge-srs ip=%s, version=%s, pid=%d, id=%d", 
                srs_server_ip.c_str(), srs_version.c_str(), srs_pid, srs_id);
        }
    }
    
    ret = service_cycle();
    llive_rtmp_conn--;
    srs_trace("devicesn:%s SrsRtmpConn::do_cycle  ret:%d = service_cycle(), llive_rtmp_conn:%ld, connect duration:%" PRId64 "\n", req->devicesn.c_str(), ret, llive_rtmp_conn, get_local_timestamp() - m_lon_connect_timestamp);
    on_close();
    //http_hooks_on_close();
    
    return ret;
}

int SrsRtmpConn::on_reload_vhost_removed(string vhost)
{
    int ret = ERROR_SUCCESS;
    
    if (req->vhost != vhost) {
        return ret;
    }
    
    // if the vhost connected is removed, disconnect the client.
    srs_trace("vhost %s removed/disabled, close client url=%s", 
        vhost.c_str(), req->get_stream_url().c_str());
    
    // should never close the fd in another thread,
    // one fd should managed by one thread, we should use interrupt instead.
    // so we just ignore the vhost enabled event.
    //srs_close_stfd(stfd);
    
    return ret;
}

int SrsRtmpConn::on_reload_vhost_mw(string vhost)
{
    int ret = ERROR_SUCCESS;
    
    if (req->vhost != vhost) {
        return ret;
    }
    
    int sleep_ms = _srs_config->get_mw_sleep_ms(req->vhost);
    
    // when mw_sleep changed, resize the socket send buffer.
    change_mw_sleep(sleep_ms);

    return ret;
}

int SrsRtmpConn::on_reload_vhost_smi(string vhost)
{
    int ret = ERROR_SUCCESS;
    
    if (req->vhost != vhost) {
        return ret;
    }
    
    double smi = _srs_config->get_send_min_interval(vhost);
    if (smi != send_min_interval) {
        srs_trace("apply smi %.2f=>%.2f", send_min_interval, smi);
        send_min_interval = smi;
    }
    
    return ret;
}

int SrsRtmpConn::on_reload_vhost_tcp_nodelay(string vhost)
{
    int ret = ERROR_SUCCESS;
    
    if (req->vhost != vhost) {
        return ret;
    }
    
    set_sock_options();
    
    return ret;
}

int SrsRtmpConn::on_reload_vhost_realtime(string vhost)
{
    int ret = ERROR_SUCCESS;
    
    if (req->vhost != vhost) {
        return ret;
    }
    
    bool realtime_enabled = _srs_config->get_realtime_enabled(req->vhost);
    if (realtime_enabled != realtime) {
        srs_trace("realtime changed %d=>%d", realtime, realtime_enabled);
        realtime = realtime_enabled;
    }

    return ret;
}

int SrsRtmpConn::on_reload_vhost_p1stpt(string vhost)
{
    int ret = ERROR_SUCCESS;
    
    if (req->vhost != vhost) {
        return ret;
    }
    
    int p1stpt = _srs_config->get_publish_1stpkt_timeout(req->vhost);
    if (p1stpt != publish_1stpkt_timeout) {
        srs_trace("p1stpt changed %d=>%d", publish_1stpkt_timeout, p1stpt);
        publish_1stpkt_timeout = p1stpt;
    }
    
    return ret;
}

int SrsRtmpConn::on_reload_vhost_pnt(string vhost)
{
    int ret = ERROR_SUCCESS;
    
    if (req->vhost != vhost) {
        return ret;
    }
    
    int pnt = _srs_config->get_publish_normal_timeout(req->vhost);
    if (pnt != publish_normal_timeout) {
        srs_trace("p1stpt changed %d=>%d", publish_normal_timeout, pnt);
        publish_normal_timeout = pnt;
    }
    
    return ret;
}

void SrsRtmpConn::resample()
{
    kbps->resample();
}

int64_t SrsRtmpConn::get_send_bytes_delta()
{
    return kbps->get_send_bytes_delta();
}

int64_t SrsRtmpConn::get_recv_bytes_delta()
{
    return kbps->get_recv_bytes_delta();
}

void SrsRtmpConn::cleanup()
{
    kbps->cleanup();
}
    
int SrsRtmpConn::service_cycle()
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = rtmp->set_window_ack_size((int)(2.5 * 1000 * 1000))) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "set window acknowledgement size failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("set window acknowledgement size success");
        
    if ((ret = rtmp->set_peer_bandwidth((int)(2.5 * 1000 * 1000), 2)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0),"set peer bandwidth failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("set peer bandwidth success");

    // get the ip which client connected.
    m_slocal_ip = srs_get_local_ip(st_netfd_fileno(stfd), &m_nport);
    
    // do bandwidth test if connect to the vhost which is for bandwidth check.
    if (_srs_config->get_bw_check_enabled(req->vhost)) {
        return bandwidth->bandwidth_check(rtmp, skt, req, m_slocal_ip);
    }
    
    // set chunk size to larger.
    // set the chunk size before any larger response greater than 128,
    // to make OBS happy, @see https://github.com/ossrs/srs/issues/454
    int chunk_size = _srs_config->get_chunk_size(req->vhost);
    if ((ret = rtmp->set_chunk_size(chunk_size)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "set chunk_size=%d failed. ret=%d", chunk_size, ret);
        return ret;
    }
    srs_info("set chunk_size=%d success", chunk_size);
    
    // response the client connect ok.
    if ((ret = rtmp->response_connect_app(req, m_slocal_ip.c_str())) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "response connect app failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("response connect app success, req->token:%s", req->token.c_str());
        
    if ((ret = rtmp->on_bw_done()) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "on_bw_done failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("on_bw_done success");
    llive_svr_cycle++;
    while (!disposed) {
        ret = stream_service_cycle();
        
        // stream service must terminated with error, never success.
        // when terminated with success, it's user required to stop.
        if (ret == ERROR_SUCCESS) {
            continue;
        }
        
        // when not system control error, fatal error, return.
        if (!srs_is_system_control_error(ret)) {
            if (ret != ERROR_SOCKET_TIMEOUT && !srs_is_client_gracefully_close(ret)) {
                tag_error(get_device_sn(req, 0), "stream service cycle failed. ret=%d", ret);
            }
            llive_svr_cycle--;
            return ret;
        }
        
        // for republish, continue service
        if (ret == ERROR_CONTROL_REPUBLISH) {
            // set timeout to a larger value, wait for encoder to republish.
            rtmp->set_send_timeout(SRS_REPUBLISH_RECV_TIMEOUT_US);
            rtmp->set_recv_timeout(SRS_REPUBLISH_SEND_TIMEOUT_US);
            
            srs_trace("control message(unpublish) accept, retry stream service.");
            continue;
        }
        
        // for "some" system control error, 
        // logical accept and retry stream service.
        if (ret == ERROR_CONTROL_RTMP_CLOSE) {
            // TODO: FIXME: use ping message to anti-death of socket.
            // @see: https://github.com/ossrs/srs/issues/39
            // set timeout to a larger value, for user paused.
            rtmp->set_recv_timeout(SRS_PAUSED_RECV_TIMEOUT_US);
            rtmp->set_send_timeout(SRS_PAUSED_SEND_TIMEOUT_US);
            
            srs_trace("control message(close) accept, retry stream service.");
            continue;
        }
        
        // for other system control message, fatal error.
        llive_svr_cycle--;
        tag_error(get_device_sn(req, 0), "control message(%d) reject as error. llive_svr_cycle=%ld", ret, llive_svr_cycle);
        return ret;
    }
    llive_svr_cycle--;
    srs_trace("SrsRtmpConn::service_cycle end ret:%d, llive_svr_cycle:%ld, connetction time:%" PRId64 " ms\n", ret, llive_svr_cycle, get_local_timestamp() - m_lon_connect_timestamp);
    return ret;
}

int SrsRtmpConn::stream_service_cycle()
{
    int ret = ERROR_SUCCESS;
    
    SrsRtmpConnType type;
    //srs_trace("req->app:%s, req->stream:%s, req->param:%s", req->app.c_str(), req->stream.c_str(), req->param.c_str());
    if ((ret = rtmp->identify_client(res->stream_id, type, req->stream, req->param, req->duration)) != ERROR_SUCCESS) {
        if (!srs_is_client_gracefully_close(ret)) {
            tag_error(get_device_sn(req, 0), "identify client failed. ret=%d", ret);
        }
        return ret;
    }

    client_type = type;
   // srs_trace("res->stream_id:%d, req->app:%s, req->stream:%s, req->duration:%lf, req->param:%s, req->token:%s\n", res->stream_id, req->app.c_str(), req->stream.c_str(), req->duration, req->param.c_str(), req->token.c_str());
    srs_discovery_tc_url(req->tcUrl, req->schema, req->host, req->vhost, req->app, req->stream, req->port, req->param, req->token);
    req->strip();
    /*req->stream = "24d4c86a5e2986e22926f302b68fce28";
    req->app = "678d87d67eca1bfe1912b03b75bbc38b";
    req->token = "94a08da1fecbb6e8b46990538c7b50b2";*/
    //srs_warn("push rtmp without devicesn:%s!", req->devicesn.c_str());
    //srs_trace("client identified, type=%s, peer ip:%s, req->app:%s, stream_name=%s, duration=%.2f, param=%s, req->token:%s", srs_client_type_string(type).c_str(), srs_get_peer_ip(rtmp->get_fd()).c_str(), req->app.c_str(), req->stream.c_str(), req->duration, req->param.c_str(), req->token.c_str());
    
    // add by dawson for no token check
    if(req->devicesn.empty())
    {
        req->devicesn = req->stream;
        srs_info("devicesn is empty, req->devicesn:%s = req->stream:%s\n", req->devicesn.c_str(), req->stream.c_str());
    }
    // add end
    // discovery vhost, resolve the vhost from config
    SrsConfDirective* parsed_vhost = _srs_config->get_vhost(req->vhost);
    if (parsed_vhost) {
        req->vhost = parsed_vhost->arg0();
    }
    
    if (req->schema.empty() || req->vhost.empty() || req->port.empty() || req->app.empty()) {
        ret = ERROR_RTMP_REQ_TCURL;
        tag_error(get_device_sn(req, 0), "discovery tcUrl failed. "
                  "tcUrl=%s, schema=%s, vhost=%s, port=%s, app=%s, ret=%d",
                  req->tcUrl.c_str(), req->schema.c_str(), req->vhost.c_str(), req->port.c_str(), req->app.c_str(), ret);
        return ret;
    }
    
    if ((ret = check_vhost()) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "check vhost failed. ret=%d", ret);
        return ret;
    }
    
    // add by dawson
    if((ret = authorize_check(type)) != ERROR_SUCCESS)
    {
        tag_error(get_device_sn(req, 0), "authorize check failed, ret:%d, connection break!", ret);
        return ret;
    }

    if((ret = rtmp_connnection_change(1)) != ERROR_SUCCESS)
    {
        tag_error(get_device_sn(req, 0), "add rtmp push connection, ret:%d\n", ret);
    }
    // add end
    m_lon_connect_timestamp = get_local_timestamp();
    srs_trace("connected stream, peer ip:%s, tcUrl=%s, pageUrl=%s, swfUrl=%s, schema=%s, vhost=%s, port=%s, app=%s, stream=%s, req->userid:%s, param=%s, sn:%s, args=%s, req->eauth_type:%d",
        srs_get_peer_ip(rtmp->get_fd()).c_str(), req->tcUrl.c_str(), req->pageUrl.c_str(), req->swfUrl.c_str(),
        req->schema.c_str(), req->vhost.c_str(), req->port.c_str(),
        req->app.c_str(), req->stream.c_str(), req->userid.c_str(), req->param.c_str(), req->devicesn.c_str(), (req->args? "(obj)":"null"), req->eauth_type);
    
    // do token traverse before serve it.
    // @see https://github.com/ossrs/srs/pull/239
    if (true) {
        bool vhost_is_edge = _srs_config->get_vhost_is_edge(req->vhost);
        bool edge_traverse = _srs_config->get_vhost_edge_token_traverse(req->vhost);
        if (vhost_is_edge && edge_traverse) {
            if ((ret = check_edge_token_traverse_auth()) != ERROR_SUCCESS) {
                srs_warn("token auth failed, ret=%d", ret);
                return ret;
            }
        }
    }
    
    // security check
    if ((ret = security->check(type, ip, req)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "security check failed. ret=%d", ret);
        return ret;
    }
    srs_info("security check ok");
    
    // Never allow the empty stream name, for HLS may write to a file with empty name.
    // @see https://github.com/ossrs/srs/issues/834
    if (req->stream.empty()) {
        ret = ERROR_RTMP_STREAM_NAME_EMPTY;
        tag_error(get_device_sn(req, 0), "RTMP: Empty stream name not allowed, ret=%d", ret);
        return ret;
    }

    // client is identified, set the timeout to service timeout.
    rtmp->set_recv_timeout(SRS_CONSTS_RTMP_RECV_TIMEOUT_US);
    rtmp->set_send_timeout(SRS_CONSTS_RTMP_SEND_TIMEOUT_US);
    
    // find a source to serve.
    SrsSource* source = NULL;
    if ((ret = SrsSource::fetch_or_create(req, server, &source)) != ERROR_SUCCESS) {
        return ret;
    }
    srs_assert(source != NULL);
    do
    {
        // update the statistic when source disconveried.
        SrsStatistic* stat = SrsStatistic::instance();
        //srs_trace("before stat->on_client(_srs_context->get_id(), req, this, type)\n");
        if ((ret = stat->on_client(_srs_context->get_id(), req, this, type)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "stat client failed. ret=%d", ret);
            //return ret;
            break;
        }

        bool vhost_is_edge = _srs_config->get_vhost_is_edge(req->vhost);
        bool enabled_cache = _srs_config->get_gop_cache(req->vhost);
        srs_info("source url=%s, ip=%s, cache=%d, is_edge=%d, source_id=%d[%d]",
            req->get_stream_url().c_str(), ip.c_str(), enabled_cache, vhost_is_edge, 
            source->source_id(), source->source_id());
        source->set_cache(enabled_cache);
        
        m_llast_ping_timestamp = get_local_timestamp();
        //client_type = type;
        switch (type) {
            case SrsRtmpConnPlay: {
                srs_trace("start to play stream %s.", req->stream.c_str());
                
                // response connection start play
                if ((ret = rtmp->start_play(res->stream_id)) != ERROR_SUCCESS) {
                    tag_error(get_device_sn(req, 0), "start to play stream failed. ret=%d", ret);
                    //return ret;
                    break;
                }
                if ((ret = http_hooks_on_play()) != ERROR_SUCCESS) {
                    tag_error(get_device_sn(req, 0), "http hook on_play failed. ret=%d", ret);
                    //return ret;
                    break;
                }
                
                srs_info("start to play stream %s success", req->stream.c_str());
                ret = playing(source);
                http_hooks_on_stop();
                break;
                //return ret;
            }
            case SrsRtmpConnFMLEPublish: {
                //srs_trace("FMLE start to publish stream %s.", req->stream.c_str());
#if  defined(SRS_AUTO_FORWARD_WEBRTC) || defined(SRS_AUTO_RTSP_SERVER)
                source->set_rtmp_server(rtmp);
#endif
                if ((ret = rtmp->start_fmle_publish(res->stream_id)) != ERROR_SUCCESS) {
                    tag_error(get_device_sn(req, 0), "start to publish stream failed. ret=%d", ret);
                    break;
                    //return ret;
                }
                ret = publishing(source);
                srs_info("ret:%d = publishing(source:%p)", ret, source);
                break;
                //return ret;
            }
            case SrsRtmpConnHaivisionPublish: {
                srs_trace("Haivision start to publish stream %s.", req->stream.c_str());
                
                if ((ret = rtmp->start_haivision_publish(res->stream_id)) != ERROR_SUCCESS) {
                    tag_error(get_device_sn(req, 0), "start to publish stream failed. ret=%d", ret);
                    break;
                    //return ret;
                }
                
                ret = publishing(source);
                break;
            }
            case SrsRtmpConnFlashPublish: {
                srs_trace("flash start to publish stream %s.", req->stream.c_str());
                
                if ((ret = rtmp->start_flash_publish(res->stream_id)) != ERROR_SUCCESS) {
                    tag_error(get_device_sn(req, 0), "flash start to publish stream failed. ret=%d", ret);
                    break;
                    //return ret;
                }
                
                ret = publishing(source);
                break;
            }
            default: {
                ret = ERROR_SYSTEM_CLIENT_INVALID;
                srs_trace("invalid client type=%d. ret=%d", type, ret);
                break;
                //return ret;
            }
        }
    }while(0);

    //srs_trace("rtmp end of stream, rtmp connection change to close\n", source);

    if((ret = rtmp_connnection_change(0)) != ERROR_SUCCESS)
    {
        tag_error(get_device_sn(req, 0), "add rtmp push connection, ret:%d\n", ret);
    }

    if(source)
    {
        source->release_ref();
        //srs_debug("ref:%d = source:%p->release_ref()", ref, source);
        source = NULL;
    }

    return ret;
}

int SrsRtmpConn::check_vhost()
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(req != NULL);
    
    SrsConfDirective* vhost = _srs_config->get_vhost(req->vhost);
    if (vhost == NULL) {
        ret = ERROR_RTMP_VHOST_NOT_FOUND;
        tag_error(get_device_sn(req, 0), "vhost %s not found. ret=%d", req->vhost.c_str(), ret);
        return ret;
    }
    
    if (!_srs_config->get_vhost_enabled(req->vhost)) {
        ret = ERROR_RTMP_VHOST_NOT_FOUND;
        tag_error(get_device_sn(req, 0), "vhost %s disabled. ret=%d", req->vhost.c_str(), ret);
        return ret;
    }
    
    if (req->vhost != vhost->arg0()) {
        srs_trace("vhost change from %s to %s", req->vhost.c_str(), vhost->arg0().c_str());
        req->vhost = vhost->arg0();
    }
    
    if ((ret = refer->check(req->pageUrl, _srs_config->get_refer(req->vhost))) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "check refer failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("check refer success.");

    // add by dawson for token authorization
    ret = on_authorize();
    if(ERROR_SUCCESS != ret)
    {
        tag_error(get_device_sn(req, 0), "ret:%d = on_authorize() failed", ret);
        if(ERROR_RTMP_NO_TOKEN == ret)
        {
            req->eauth_type = e_auth_type_no_token;
        }
        else
        {
            req->eauth_type = e_auth_type_failed;
        }
    }
    else
    {
        req->eauth_type = e_auth_type_success;
        srs_rtsp_debug("req->eauth_type = e_auth_type_success\n");
    }
    

    if ((ret = http_hooks_on_connect()) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "ret:%d = http_hooks_on_connect() failed", ret);
        return ret;
    }
    
    return ret;
}

int SrsRtmpConn::playing(SrsSource* source)
{
    int ret = ERROR_SUCCESS;
    
    // create consumer of souce.
    SrsConsumer* consumer = NULL;
    if ((ret = source->create_consumer(this, consumer)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "create consumer failed. ret=%d", ret);
        return ret;
    }
    SrsAutoFree(SrsConsumer, consumer);
    srs_verbose("consumer created success.");

    // use isolate thread to recv, 
    // @see: https://github.com/ossrs/srs/issues/217
    SrsQueueRecvThread trd(consumer, rtmp, SRS_PERF_MW_SLEEP);
    
    // start isolate recv thread.
    if ((ret = trd.start()) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "start isolate recv thread failed. ret=%d", ret);
        return ret;
    }
    
    // delivery messages for clients playing stream.
    wakable = consumer;
    ret = do_playing(source, consumer, &trd);
    wakable = NULL;
    
    // stop isolate recv thread
    trd.stop();
    
    // warn for the message is dropped.
    if (!trd.empty()) {
        srs_warn("drop the received %d messages", trd.size());
    }
    
    return ret;
}

int SrsRtmpConn::do_playing(SrsSource* source, SrsConsumer* consumer, SrsQueueRecvThread* trd)
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(consumer != NULL);
    
    if ((ret = refer->check(req->pageUrl, _srs_config->get_refer_play(req->vhost))) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "check play_refer failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("check play_refer success.");
    
    // initialize other components
    SrsPithyPrint* pprint = SrsPithyPrint::create_rtmp_play();
    SrsAutoFree(SrsPithyPrint, pprint);

    SrsMessageArray msgs(SRS_PERF_MW_MSGS);
    bool user_specified_duration_to_stop = (req->duration > 0);
    int64_t starttime = -1;
    
    // setup the realtime.
    realtime = _srs_config->get_realtime_enabled(req->vhost);
    // setup the mw config.
    // when mw_sleep changed, resize the socket send buffer.
    mw_enabled = true;
    change_mw_sleep(_srs_config->get_mw_sleep_ms(req->vhost));
    // initialize the send_min_interval
    send_min_interval = _srs_config->get_send_min_interval(req->vhost);
    
    // set the sock options.
    set_sock_options();
    
    srs_trace("start play smi=%.2f, mw_sleep=%d, mw_enabled=%d, realtime=%d, tcp_nodelay=%d",
        send_min_interval, mw_sleep, mw_enabled, realtime, tcp_nodelay);
    
    while (!disposed) {
        // collect elapse for pithy print.
        pprint->elapse();
        
        // when source is set to expired, disconnect it.
        if (expired) {
            ret = ERROR_USER_DISCONNECT;
            tag_error(get_device_sn(req, 0), "connection expired. ret=%d", ret);
            return ret;
        }

        // to use isolate thread to recv, can improve about 33% performance.
        // @see: https://github.com/ossrs/srs/issues/196
        // @see: https://github.com/ossrs/srs/issues/217
        while (!trd->empty()) {
            SrsCommonMessage* msg = trd->pump();
            srs_verbose("pump client message to process.");
            
            if ((ret = process_play_control_msg(consumer, msg)) != ERROR_SUCCESS) {
                if (!srs_is_system_control_error(ret) && !srs_is_client_gracefully_close(ret)) {
                    tag_error(get_device_sn(req, 0), "process play control message failed. ret=%d", ret);
                }
                return ret;
            }
        }
        
        // quit when recv thread error.
        if ((ret = trd->error_code()) != ERROR_SUCCESS) {
            if (!srs_is_client_gracefully_close(ret) && !srs_is_system_control_error(ret)) {
                tag_error(get_device_sn(req, 0), "recv thread failed. ret=%d", ret);
            }
            return ret;
        }
        
#ifdef SRS_PERF_QUEUE_COND_WAIT
        // for send wait time debug
        srs_verbose("send thread now=%"PRId64"us, wait %dms", srs_update_system_time_ms(), mw_sleep);
        
        // wait for message to incoming.
        // @see https://github.com/ossrs/srs/issues/251
        // @see https://github.com/ossrs/srs/issues/257
        if (realtime) {
            // for realtime, min required msgs is 0, send when got one+ msgs.
            consumer->wait(0, mw_sleep);
        } else {
            // for no-realtime, got some msgs then send.
            consumer->wait(SRS_PERF_MW_MIN_MSGS, mw_sleep);
        }
        
        // for send wait time debug
        srs_verbose("send thread now=%"PRId64"us wakeup", srs_update_system_time_ms());
#endif
        
        // get messages from consumer.
        // each msg in msgs.msgs must be free, for the SrsMessageArray never free them.
        // @remark when enable send_min_interval, only fetch one message a time.
        int count = (send_min_interval > 0)? 1 : 0;
        if ((ret = consumer->dump_packets(&msgs, count)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "get messages from consumer failed. ret=%d", ret);
            return ret;
        }

        // reportable
        if (pprint->can_print()) {
            kbps->sample();
            srs_trace("-> "SRS_CONSTS_LOG_PLAY
                " time=%"PRId64", msgs=%d, okbps=%d,%d,%d, ikbps=%d,%d,%d, mw=%d",
                pprint->age(), count,
                kbps->get_send_kbps(), kbps->get_send_kbps_30s(), kbps->get_send_kbps_5m(),
                kbps->get_recv_kbps(), kbps->get_recv_kbps_30s(), kbps->get_recv_kbps_5m(),
                mw_sleep
            );
        }
        
        // we use wait timeout to get messages,
        // for min latency event no message incoming,
        // so the count maybe zero.
        if (count > 0) {
            srs_verbose("mw wait %dms and got %d msgs %d(%"PRId64"-%"PRId64")ms", 
                mw_sleep, count, 
                (count > 0? msgs.msgs[count - 1]->timestamp - msgs.msgs[0]->timestamp : 0),
                (count > 0? msgs.msgs[0]->timestamp : 0), 
                (count > 0? msgs.msgs[count - 1]->timestamp : 0));
        }
        
        if (count <= 0) {
#ifndef SRS_PERF_QUEUE_COND_WAIT
            srs_info("mw sleep %dms for no msg", mw_sleep);
            st_usleep(mw_sleep * 1000);
#else
            srs_verbose("mw wait %dms and got nothing.", mw_sleep);
#endif
            // ignore when nothing got.
            continue;
        }
        srs_info("got %d msgs, min=%d, mw=%d", count, SRS_PERF_MW_MIN_MSGS, mw_sleep);
        
        // only when user specifies the duration, 
        // we start to collect the durations for each message.
        if (user_specified_duration_to_stop) {
            for (int i = 0; i < count; i++) {
                SrsSharedPtrMessage* msg = msgs.msgs[i];
                
                // foreach msg, collect the duration.
                // @remark: never use msg when sent it, for the protocol sdk will free it.
                if (starttime < 0 || starttime > msg->timestamp) {
                    starttime = msg->timestamp;
                }
                duration += msg->timestamp - starttime;
                starttime = msg->timestamp;
            }
        }
        
        // sendout messages, all messages are freed by send_and_free_messages().
        // no need to assert msg, for the rtmp will assert it.
        if (count > 0 && (ret = rtmp->send_and_free_messages(msgs.msgs, count, res->stream_id)) != ERROR_SUCCESS) {
            if (!srs_is_client_gracefully_close(ret)) {
                tag_error(get_device_sn(req, 0), "send messages to client failed. ret=%d", ret);
            }
            return ret;
        }
        
        // if duration specified, and exceed it, stop play live.
        // @see: https://github.com/ossrs/srs/issues/45
        if (user_specified_duration_to_stop) {
            if (duration >= (int64_t)req->duration) {
                ret = ERROR_RTMP_DURATION_EXCEED;
                srs_trace("stop live for duration exceed. ret=%d", ret);
                return ret;
            }
        }
        
        // apply the minimal interval for delivery stream in ms.
        if (send_min_interval > 0) {
            st_usleep((int64_t)(send_min_interval * 1000));
        }
    }
    
    return ret;
}

int SrsRtmpConn::publishing(SrsSource* source)
{
    int ret = ERROR_SUCCESS;

    if ((ret = refer->check(req->pageUrl, _srs_config->get_refer_publish(req->vhost))) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "check publish_refer failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("check publish_refer success.");

    if ((ret = http_hooks_on_publish()) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "http hook on_publish failed. ret=%d", ret);
        return ret;
    }

    bool vhost_is_edge = _srs_config->get_vhost_is_edge(req->vhost);
    if ((ret = acquire_publish(source, vhost_is_edge)) == ERROR_SUCCESS) {
        // use isolate thread to recv,
        // @see: https://github.com/ossrs/srs/issues/237
        SrsPublishRecvThread trd(rtmp, req, 
            st_netfd_fileno(stfd), 0, this, source,
            client_type != SrsRtmpConnFlashPublish,
            vhost_is_edge);

        srs_info("start to publish stream %s success", req->stream.c_str());
        ret = do_publishing(source, &trd);
        srs_info("ret:%d = do_publishing(source, &trd)", ret);
        // stop isolate recv thread
        trd.stop();
    }
    
    // whatever the acquire publish, always release publish.
    // when the acquire error in the midlle-way, the publish state changed,
    // but failed, so we must cleanup it.
    // @see https://github.com/ossrs/srs/issues/474
    // @remark when stream is busy, should never release it.
    if (ret != ERROR_SYSTEM_STREAM_BUSY) {
        srs_info("before release_publish");
        release_publish(source, vhost_is_edge);
        srs_info("release_publish(source:%p, vhost_is_edge:%d)", source, (int)vhost_is_edge);
    }

    http_hooks_on_unpublish();
    srs_info("publishing end, ret:%d", ret);
    return ret;
}

int SrsRtmpConn::do_publishing(SrsSource* source, SrsPublishRecvThread* trd)
{
    int ret = ERROR_SUCCESS;
    srs_info("(source:%p, trd:%p)do publishing begin", source, trd);
    SrsPithyPrint* pprint = SrsPithyPrint::create_rtmp_publish();
    SrsAutoFree(SrsPithyPrint, pprint);
    llive_publishing++;
    // start isolate recv thread.
    if ((ret = trd->start()) != ERROR_SUCCESS) {
        llive_publishing--;
        tag_error(get_device_sn(req, 0), "deivce_sn:%s start isolate recv thread failed. ret=%d, llive_publishing:%ld", req->devicesn.c_str(), ret, llive_publishing);
        return ret;
    }
    
    // change the isolate recv thread context id,
    // merge its log to current thread.
    int receive_thread_cid = trd->get_cid();
    trd->set_cid(_srs_context->get_id());
    
    // initialize the publish timeout.
    publish_1stpkt_timeout = _srs_config->get_publish_1stpkt_timeout(req->vhost);
    publish_normal_timeout = _srs_config->get_publish_normal_timeout(req->vhost);
    
    // set the sock options.
    set_sock_options();
    
    if (true) {
        bool mr = _srs_config->get_mr_enabled(req->vhost);
        int mr_sleep = _srs_config->get_mr_sleep_ms(req->vhost);
        //srs_trace("start publish mr=%d/%d, p1stpt=%d, pnt=%d, tcp_nodelay=%d, rtcid=%d", mr, mr_sleep, publish_1stpkt_timeout, publish_normal_timeout, tcp_nodelay, receive_thread_cid);
    }

    int64_t nb_msgs = 0;
    uint64_t nb_frames = 0;
    llast_active_time = get_sys_time();
    while (!disposed) {
        pprint->elapse();
        
        // when source is set to expired, disconnect it.
        if (expired) {
            ret = ERROR_USER_DISCONNECT;
            llive_publishing--;
            tag_error(get_device_sn(req, 0), "deivce_sn:%s connection expired. ret=%d, llive_publishing:%ld", req->devicesn.c_str(), ret, llive_publishing);
            if(req)
            {
                req->disconnect_type = RTMP_DISCONNECT_BY_CLIENT;
            }
            return ret;
        }
        srs_verbose("wait for message, nb_msgs:%d", nb_msgs);
        // cond wait for timeout.
        if (nb_msgs == 0) {
            // when not got msgs, wait for a larger timeout.
            // @see https://github.com/ossrs/srs/issues/441
            trd->wait(publish_1stpkt_timeout);
        } else {
            trd->wait(publish_normal_timeout);
        }
        srs_verbose("after wait");
        // check the thread error code.
        if ((ret = trd->error_code()) != ERROR_SUCCESS) {
            if (!srs_is_system_control_error(ret) && !srs_is_client_gracefully_close(ret)) {
                tag_error(get_device_sn(req, 0), "deivce_sn:%s recv thread failed. ret=%d", req->devicesn.c_str(), ret);
            }
            llive_publishing--;
            srs_trace("deivce_sn:%s ret:%d = trd->error_code()) != ERROR_SUCCESS, llive_publishing:%ld\n", req->devicesn.c_str(), ret, llive_publishing);
            if(req)
            {
                req->disconnect_type = RTMP_DISCONNECT_BY_CLIENT;
            }
            return ret;
        }

        // when not got any messages, timeout.
        if (trd->nb_msgs() <= nb_msgs) {
            ret = ERROR_SOCKET_TIMEOUT;
            tag_error(get_device_sn(req, 0), "publish timeout %dms, nb_msgs=%"PRId64", ret=%d, timeout_dur:%lu", nb_msgs? publish_normal_timeout : publish_1stpkt_timeout, nb_msgs, ret, get_sys_time() - llast_active_time);

            //tag_error(get_device_sn(req, 0), "deivce_sn:%s trd->nb_msgs():%d <= nb_msgs:%d, timeout", req->devicesn.c_str(), trd->nb_msgs(), nb_msgs);
            if(req)
            {
                req->disconnect_type = RTMP_DISCONNECT_BY_TIMEOUT;
            }
            break;
        }
        llast_active_time = get_sys_time();
        nb_msgs = trd->nb_msgs();
        srs_info("after nb_msgs:%d", nb_msgs);
        // Update the stat for video fps.
        // @remark https://github.com/ossrs/srs/issues/851
        SrsStatistic* stat = SrsStatistic::instance();
        if (req && (ret = stat->on_video_frames(req, (int)(trd->nb_video_frames() - nb_frames))) != ERROR_SUCCESS) {
            llive_publishing--;
            tag_error(get_device_sn(req, 0), "deivce_sn:%s ret:%d = stat->on_video_frames(req, (int)(trd->nb_video_frames():%"PRId64" - nb_frames:%"PRId64") failed, llive_publishing:%ld", req->devicesn.c_str(), ret, trd->nb_video_frames(), nb_frames, llive_publishing);
            req->disconnect_type = RTMP_DISCONNECT_BY_SERVER_ERROR;
            return ret;
        }
        nb_frames = trd->nb_video_frames();
        srs_info("nb_msgs:%"PRId64", nb_frames:%"PRId64" = trd->nb_video_frames()", nb_msgs, nb_frames);
        // reportable
        /*if (pprint->can_print()) {
            kbps->sample();
            bool mr = _srs_config->get_mr_enabled(req->vhost);
            int mr_sleep = _srs_config->get_mr_sleep_ms(req->vhost);
            //srs_trace("is here do_publishing");
            srs_trace("<- "SRS_CONSTS_LOG_CLIENT_PUBLISH
                " time=%"PRId64", okbps=%d,%d,%d, ikbps=%d,%d,%d, mr=%d/%d, p1stpt=%d, pnt=%d", pprint->age(),
                kbps->get_send_kbps(), kbps->get_send_kbps_30s(), kbps->get_send_kbps_5m(),
                kbps->get_recv_kbps(), kbps->get_recv_kbps_30s(), kbps->get_recv_kbps_5m(),
                mr, mr_sleep, publish_1stpkt_timeout, publish_normal_timeout
            );
        }*/
    }
    llive_publishing--;
    srs_trace("deivce_sn:%s do publishing end, ret:%d, llive_publishing:%ld, timeout_dur:%lu", req->devicesn.c_str(), ret, llive_publishing, get_sys_time() - llast_active_time);
    return ret;
}

int SrsRtmpConn::acquire_publish(SrsSource* source, bool is_edge)
{
    int ret = ERROR_SUCCESS;

    if (!source->can_publish(is_edge)) {
        ret = ERROR_SYSTEM_STREAM_BUSY;
        srs_warn("stream %s is already publishing. ret=%d", 
            req->get_stream_url().c_str(), ret);
        return ret;
    }
    
    // when edge, ignore the publish event, directly proxy it.
    if (is_edge) {
        if ((ret = source->on_edge_start_publish()) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "notice edge start publish stream failed. ret=%d", ret);
            return ret;
        }        
    } else {
        if ((ret = source->on_publish()) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "notify publish failed. ret=%d", ret);
            return ret;
        }
    }

    return ret;
}
    
void SrsRtmpConn::release_publish(SrsSource* source, bool is_edge)
{
    // when edge, notice edge to change state.
    // when origin, notice all service to unpublish.
    if (is_edge) {
        source->on_edge_proxy_unpublish();
    } else {
        source->on_unpublish();
    }
}

int SrsRtmpConn::handle_publish_message(SrsSource* source, SrsCommonMessage* msg, bool is_fmle, bool vhost_is_edge)
{
    int ret = ERROR_SUCCESS;
    
    // process publish event.
    if (msg->header.is_amf0_command() || msg->header.is_amf3_command()) {
        SrsPacket* pkt = NULL;
        if ((ret = rtmp->decode_message(msg, &pkt)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "fmle decode unpublish message failed. ret=%d", ret);
            return ret;
        }
        //srs_trace("decode_message SrsAutoFree(SrsPacket, pkt:%p)", pkt);
        SrsAutoFree(SrsPacket, pkt);
        
        // for flash, any packet is republish.
        if (!is_fmle) {
            // flash unpublish.
            // TODO: maybe need to support republish.
            srs_trace("flash flash publish finished.");
            return ERROR_CONTROL_REPUBLISH;
        }

        // for fmle, drop others except the fmle start packet.
        if (dynamic_cast<SrsFMLEStartPacket*>(pkt)) {
            SrsFMLEStartPacket* unpublish = dynamic_cast<SrsFMLEStartPacket*>(pkt);
            int64_t begin = get_local_timestamp();
            
            ret = rtmp->fmle_unpublish(res->stream_id, unpublish->transaction_id);
            srs_trace("client control unpublish, sn:%s, peer ip:%s, last ping message duration:%" PRId64 "ms, send unpublish time:%" PRId64 "ms\n", req->devicesn.c_str(), ip.c_str(), get_local_timestamp() - m_llast_ping_timestamp, get_local_timestamp() - begin);
            if (ret != ERROR_SUCCESS) {
                return ret;
            }
            return ERROR_CONTROL_REPUBLISH;
        }

        srs_trace("fmle ignore AMF0/AMF3 command message.");
        return ret;
    }
	
	// heatbeat msg
	if(msg->header.message_type == RTMP_MSG_UserControlMessage)
    {
        srs_info("ping msg\n");
        m_llast_ping_timestamp = get_local_timestamp();
    }

    // video, audio, data message
    if ((ret = process_publish_message(source, msg, vhost_is_edge)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "fmle process publish message failed. ret=%d", ret);
        return ret;
    }
    
    return ret;
}

int SrsRtmpConn::process_publish_message(SrsSource* source, SrsCommonMessage* msg, bool vhost_is_edge)
{
    int ret = ERROR_SUCCESS;
    //srs_trace("msg.size:%d, pts:%"PRId64"", msg->size, msg->header.timestamp);
    // for edge, directly proxy message to origin.
    if (vhost_is_edge) {
        if ((ret = source->on_edge_proxy_publish(msg)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "edge publish proxy msg failed. ret=%d", ret);
            return ret;
        }
        return ret;
    }
    
    // process audio packet
    if (msg->header.is_audio()) {
        if ((ret = source->on_audio(msg)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "source process audio message failed. ret=%d", ret);
            return ret;
        }
        return ret;
    }
    // process video packet
    if (msg->header.is_video()) {
        //srs_trace("process_publish_message on_video");
        if ((ret = source->on_video(msg)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "source process video message failed. ret=%d", ret);
            return ret;
        }
        return ret;
    }
    
    // process aggregate packet
    if (msg->header.is_aggregate()) {
        if ((ret = source->on_aggregate(msg)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "source process aggregate message failed. ret=%d", ret);
            return ret;
        }
        return ret;
    }
    
    // process onMetaData
    if (msg->header.is_amf0_data() || msg->header.is_amf3_data()) {
        SrsPacket* pkt = NULL;
        if ((ret = rtmp->decode_message(msg, &pkt)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "decode onMetaData message failed. ret=%d", ret);
            return ret;
        }
        SrsAutoFree(SrsPacket, pkt);
    
        if (dynamic_cast<SrsOnMetaDataPacket*>(pkt)) {
            SrsOnMetaDataPacket* metadata = dynamic_cast<SrsOnMetaDataPacket*>(pkt);
            // remove by dawson

            
            handle_metadata(metadata);

            if ((ret = source->on_meta_data(msg, metadata)) != ERROR_SUCCESS) {
                tag_error(get_device_sn(req, 0), "source process onMetaData message failed. ret=%d", ret);
                return ret;
            }

            //srs_trace("process onMetaData message success.");
            return ret;
        }
        
        srs_info("ignore AMF0/AMF3 data message.");
        return ret;
    }
    
    return ret;
}

int SrsRtmpConn::process_play_control_msg(SrsConsumer* consumer, SrsCommonMessage* msg)
{
    int ret = ERROR_SUCCESS;
    
    if (!msg) {
        srs_verbose("ignore all empty message.");
        return ret;
    }
    SrsAutoFree(SrsCommonMessage, msg);
    
    if (!msg->header.is_amf0_command() && !msg->header.is_amf3_command()) {
        srs_info("ignore all message except amf0/amf3 command.");
        return ret;
    }
    
    SrsPacket* pkt = NULL;
    if ((ret = rtmp->decode_message(msg, &pkt)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "decode the amf0/amf3 command packet failed. ret=%d", ret);
        return ret;
    }
    srs_info("decode the amf0/amf3 command packet success.");
    
    SrsAutoFree(SrsPacket, pkt);
    
    // for jwplayer/flowplayer, which send close as pause message.
    // @see https://github.com/ossrs/srs/issues/6
    SrsCloseStreamPacket* close = dynamic_cast<SrsCloseStreamPacket*>(pkt);
    if (close) {
        ret = ERROR_CONTROL_RTMP_CLOSE;
        srs_trace("system control message: rtmp close stream. ret=%d", ret);
        return ret;
    }
    
    // call msg,
    // support response null first,
    // @see https://github.com/ossrs/srs/issues/106
    // TODO: FIXME: response in right way, or forward in edge mode.
    SrsCallPacket* call = dynamic_cast<SrsCallPacket*>(pkt);
    if (call) {
        // only response it when transaction id not zero,
        // for the zero means donot need response.
        if (call->transaction_id > 0) {
            SrsCallResPacket* res = new SrsCallResPacket(call->transaction_id);
            LB_ADD_MEM(res, sizeof(SrsCallResPacket));
            res->command_object = SrsAmf0Any::null();
            res->response = SrsAmf0Any::null();
            if ((ret = rtmp->send_and_free_packet(res, 0)) != ERROR_SUCCESS) {
                if (!srs_is_system_control_error(ret) && !srs_is_client_gracefully_close(ret)) {
                    srs_warn("response call failed. ret=%d", ret);
                }
                return ret;
            }
        }
        return ret;
    }
    
    // pause
    SrsPausePacket* pause = dynamic_cast<SrsPausePacket*>(pkt);
    if (pause) {
        if ((ret = rtmp->on_play_client_pause(res->stream_id, pause->is_pause)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "rtmp process play client pause failed. ret=%d", ret);
            return ret;
        }

        if ((ret = consumer->on_play_client_pause(pause->is_pause)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "consumer process play client pause failed. ret=%d", ret);
            return ret;
        }
        srs_info("process pause success, is_pause=%d, time=%d.", pause->is_pause, pause->time_ms);
        return ret;
    }
    
    // other msg.
    srs_info("ignore all amf0/amf3 command except pause and video control.");
    return ret;
}

void SrsRtmpConn::change_mw_sleep(int sleep_ms)
{
    if (!mw_enabled) {
        return;
    }
    
    // get the sock buffer size.
    int fd = st_netfd_fileno(stfd);
    int onb_sbuf = 0;
    socklen_t sock_buf_size = sizeof(int);
    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &onb_sbuf, &sock_buf_size);
    
#ifdef SRS_PERF_MW_SO_SNDBUF
    // the bytes:
    //      4KB=4096, 8KB=8192, 16KB=16384, 32KB=32768, 64KB=65536,
    //      128KB=131072, 256KB=262144, 512KB=524288
    // the buffer should set to sleep*kbps/8,
    // for example, your system delivery stream in 1000kbps,
    // sleep 800ms for small bytes, the buffer should set to:
    //      800*1000/8=100000B(about 128KB).
    // other examples:
    //      2000*3000/8=750000B(about 732KB).
    //      2000*5000/8=1250000B(about 1220KB).
    int kbps = 5000;
    int socket_buffer_size = sleep_ms * kbps / 8;

    // socket send buffer, system will double it.
    int nb_sbuf = socket_buffer_size / 2;
    
    // override the send buffer by macro.
    #ifdef SRS_PERF_SO_SNDBUF_SIZE
    nb_sbuf = SRS_PERF_SO_SNDBUF_SIZE / 2;
    #endif
    
    // set the socket send buffer when required larger buffer
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &nb_sbuf, sock_buf_size) < 0) {
        srs_warn("set sock SO_SENDBUF=%d failed.", nb_sbuf);
    }
    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &nb_sbuf, &sock_buf_size);
    
    srs_trace("mw changed sleep %d=>%d, max_msgs=%d, esbuf=%d, sbuf %d=>%d, realtime=%d", 
        mw_sleep, sleep_ms, SRS_PERF_MW_MSGS, socket_buffer_size,
        onb_sbuf, nb_sbuf, realtime);
#else
    srs_trace("mw changed sleep %d=>%d, max_msgs=%d, sbuf %d, realtime=%d", 
        mw_sleep, sleep_ms, SRS_PERF_MW_MSGS, onb_sbuf, realtime);
#endif
        
    mw_sleep = sleep_ms;
}

void SrsRtmpConn::set_sock_options()
{
    bool nvalue = _srs_config->get_tcp_nodelay(req->vhost);
    if (nvalue != tcp_nodelay) {
        tcp_nodelay = nvalue;
#ifdef SRS_PERF_TCP_NODELAY
        int fd = st_netfd_fileno(stfd);

        socklen_t nb_v = sizeof(int);

        int ov = 0;
        getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ov, &nb_v);

        int v = tcp_nodelay;
        // set the socket send buffer when required larger buffer
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, nb_v) < 0) {
            srs_warn("set sock TCP_NODELAY=%d failed.", v);
        }
        getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, &nb_v);

        srs_info("set TCP_NODELAY %d=>%d", ov, v);
#else
        srs_warn("SRS_PERF_TCP_NODELAY is disabled but tcp_nodelay configed.");
#endif
    }
}

int SrsRtmpConn::check_edge_token_traverse_auth()
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(req);
    
    st_netfd_t stsock = NULL;
    SrsConfDirective* conf = _srs_config->get_vhost_edge_origin(req->vhost);
    for (int i = 0; i < (int)conf->args.size(); i++) {
        if ((ret = connect_server(i, &stsock)) == ERROR_SUCCESS) {
            break;
        }
    }
    if (ret != ERROR_SUCCESS) {
        srs_warn("token traverse connect failed. ret=%d", ret);
        return ret;
    }
    
    srs_assert(stsock);
    SrsStSocket* io = new SrsStSocket(stsock);
    LB_ADD_MEM(io, sizeof(SrsStSocket));
    SrsRtmpClient* client = new SrsRtmpClient(io);
    LB_ADD_MEM(client, sizeof(SrsRtmpClient));
    
    ret = do_token_traverse_auth(client);

    srs_freep(client);
    srs_freep(io);
    srs_close_stfd(stsock);

    return ret;
}

int SrsRtmpConn::connect_server(int origin_index, st_netfd_t* pstsock)
{
    int ret = ERROR_SUCCESS;
    
    SrsConfDirective* conf = _srs_config->get_vhost_edge_origin(req->vhost);
    srs_assert(conf);
    
    // select the origin.
    std::string server = conf->args.at(origin_index % conf->args.size());
    origin_index = (origin_index + 1) % conf->args.size();
    
    std::string s_port = SRS_CONSTS_RTMP_DEFAULT_PORT;
    int port = ::atoi(SRS_CONSTS_RTMP_DEFAULT_PORT);
    size_t pos = server.find(":");
    if (pos != std::string::npos) {
        s_port = server.substr(pos + 1);
        server = server.substr(0, pos);
        port = ::atoi(s_port.c_str());
    }
    
    // open socket.
    st_netfd_t stsock = NULL;
    int64_t timeout = SRS_EDGE_TOKEN_TRAVERSE_TIMEOUT_US;
    if ((ret = srs_socket_connect(server, port, timeout, &stsock)) != ERROR_SUCCESS) {
        srs_warn("edge token traverse failed, tcUrl=%s to server=%s, port=%d, timeout=%"PRId64", ret=%d",
            req->tcUrl.c_str(), server.c_str(), port, timeout, ret);
        return ret;
    }
    srs_info("edge token auth connected, url=%s/%s, server=%s:%d", req->tcUrl.c_str(), req->stream.c_str(), server.c_str(), port);
    
    *pstsock = stsock;
    return ret;
}

int SrsRtmpConn::do_token_traverse_auth(SrsRtmpClient* client)
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(client);

    client->set_recv_timeout(SRS_CONSTS_RTMP_RECV_TIMEOUT_US);
    client->set_send_timeout(SRS_CONSTS_RTMP_SEND_TIMEOUT_US);
    
    if ((ret = client->handshake()) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "handshake with server failed. ret=%d", ret);
        return ret;
    }
    
    // for token tranverse, always take the debug info(which carries token).
    if ((ret = client->connect_app(req->app, req->tcUrl, req, true)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "connect with server failed, tcUrl=%s. ret=%d", req->tcUrl.c_str(), ret);
        return ret;
    }
    
    srs_trace("edge token auth ok, tcUrl=%s", req->tcUrl.c_str());
    
    return ret;
}
int SrsRtmpConn::http_hooks_on_authorize()
{
    int ret = ERROR_SUCCESS;
#ifdef SRS_AUTO_HTTP_CALLBACK
    if (!_srs_config->get_vhost_http_hooks_enabled(req->vhost)) {
        srs_rtsp_debug("http hooks disable\n");
        return ret;
    }
    
    // the http hooks will cause context switch,
    // so we must copy all hooks for the on_connect may freed.
    // @see https://github.com/ossrs/srs/issues/475
    vector<string> hooks;
    SrsConfDirective* conf = NULL;
    if(e_push_stream_type_live == req->streamType)
    {
        conf = _srs_config->get_vhost_config("on_live_authorize", req->vhost.c_str(), "rtmp_http_hooks");
    }
    else{
        conf = _srs_config->get_vhost_on_authorize(req->vhost);
        srs_rtsp_debug("conf:%p = _srs_config->get_vhost_on_authorize(req->vhost:%s)\n", conf, req->vhost.c_str());
        if (!conf) {
            srs_info("ignore the empty http callback: on_authorize");
            return ret;
        }
        
        hooks = conf->args;
    }
    srs_debug("get authorzie http hook conf:%p, streamType:%d\n", conf, req->streamType);
    if(NULL == conf)
    {
        return ret;
    }
    for (int i = 0; i < (int)hooks.size(); i++)
    {
        std::string url = hooks.at(i);
        srs_debug("rtmp authorzie http url:%s\n", url.c_str());
        if ((ret = SrsHttpHooks::on_authorize(url, "application/json", req)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "hook client on_authorize failed. url=%s, ret=%d", url.c_str(), ret);
            return ret;
        }
    }
#endif
    return ret;
}

int SrsRtmpConn::http_hooks_on_play_authorize()
{
    if(req)
    {
        return http_hooks_on_play_action(req->vhost, req->devicesn, "rtmp", req->token, "authorize");
    }
    return -1;
/*    int ret = ERROR_SUCCESS;
#ifdef SRS_AUTO_HTTP_CALLBACK
    if(!_srs_config->get_bool_config("enabled", false, req->vhost.c_str(), "rtmp_http_hooks"))
    {
        srs_rtsp_debug("rtsp http hooks disable\n");
        return 0;
    }

    std::vector<std::string> vallist = _srs_config->get_string_config_list("on_play_authorize", req->vhost.c_str(), "rtmp_http_hooks");
    for(size_t i = 0; i < vallist.size(); i++)
    {
        ret = SrsHttpHooks::on_play_action(vallist[i], "application/json", req->devicesn, "rtmp", req->token, "authorize");
        srs_rtsp_debug("ret:%d = SrsHttpHooks::on_play_action(vallist[i]:%s, \"application/json\", req->devicesn:%s, \"rtmp\", req->token:%s, \"authorize\")\n", ret, vallist[i].c_str(), req->devicesn.c_str(), req->token.c_str());
        SRS_CHECK_RESULT(ret);
    }
#endif

    return ret;*/
}

int SrsRtmpConn::http_hooks_on_connect()
{
    int ret = ERROR_SUCCESS;
    
#ifdef SRS_AUTO_HTTP_CALLBACK
    if (!_srs_config->get_vhost_http_hooks_enabled(req->vhost)) {
        return ret;
    }
    
    // the http hooks will cause context switch,
    // so we must copy all hooks for the on_connect may freed.
    // @see https://github.com/ossrs/srs/issues/475
    vector<string> hooks;
    
    if (true) {
        SrsConfDirective* conf = _srs_config->get_vhost_on_connect(req->vhost);
        
        if (!conf) {
            srs_info("ignore the empty http callback: on_connect");
            return ret;
        }
        
        hooks = conf->args;
    }
    
    for (int i = 0; i < (int)hooks.size(); i++) {
        std::string url = hooks.at(i);
        if ((ret = SrsHttpHooks::on_connect(url, "application/json", req)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "hook client on_connect failed. url=%s, ret=%d", url.c_str(), ret);
            return ret;
        }
    }
#endif

    return ret;
}

void SrsRtmpConn::http_hooks_on_play_close()
{
    if(req)
    {
        http_hooks_on_play_action(req->vhost, req->devicesn, "rtmp", req->token, "close");
    }
/*    int ret = ERROR_SUCCESS;
#ifdef SRS_AUTO_HTTP_CALLBACK
    if(!_srs_config->get_bool_config("enabled", false, req->vhost.c_str(), "rtmp_http_hooks"))
    {
        srs_rtsp_debug("rtsp http hooks disable\n");
    }

    std::vector<std::string> vallist = _srs_config->get_string_config_list("on_play_close", req->vhost.c_str(), "rtmp_http_hooks");
    for(size_t i = 0; i < vallist.size(); i++)
    {
        ret = SrsHttpHooks::on_play_action(vallist[i], "application/json", req->devicesn, "rtmp", req->token, "close");
        if(ERROR_SUCCESS != ret)
        {
            srs_error("ret:%d = SrsHttpHooks::on_play_action(vallist[i]:%s, \"application/json\", req->devicesn:%s, \"rtmp\", req->token:%s, \"close\") failed", ret, vallist[i].c_str(), req->devicesn.c_str(), req->token.c_str());
        }
        //SRS_CHECK_RESULT(ret);
    }
#endif*/
}

void SrsRtmpConn::http_hooks_on_close()
{
#ifdef SRS_AUTO_HTTP_CALLBACK
    if (!_srs_config->get_vhost_http_hooks_enabled(req->vhost)) {
        srs_trace("%s http hook disable", req->vhost.c_str());
        return;
    }
    
    // the http hooks will cause context switch,
    // so we must copy all hooks for the on_connect may freed.
    // @see https://github.com/ossrs/srs/issues/475
    vector<string> hooks;
    
    if (true) {
        SrsConfDirective* conf = _srs_config->get_vhost_on_close(req->vhost);
        
        if (!conf) {
            srs_trace("ignore the empty http callback: on_close");
            return;
        }
        
        hooks = conf->args;
    }
    
    for (int i = 0; i < (int)hooks.size(); i++) {
        std::string url = hooks.at(i);
        int ret = -1;
        for(int i = 0; i < 3 && ret != 0; i++)
        {
            ret = SrsHttpHooks::on_close(url, "application/json", req, kbps->get_send_bytes(), kbps->get_recv_bytes());
            if(0 != ret)
            {
                srs_trace("SrsHttpHooks::on_close failed, ret:%d\n", ret);
                st_usleep(100*1000);
            }
        }
        //SrsHttpHooks::on_close(url, req, kbps->get_send_bytes(), kbps->get_recv_bytes());
    }
#endif
}

int SrsRtmpConn::on_authorize()
{
    int ret = -1;
    if(SrsRtmpConnPlay == client_type)
    {
        ret = http_hooks_on_play_authorize();
    }
    else
    {
        ret = http_hooks_on_authorize();
    }
    
    //srs_rtsp_debug("ret:%d = on_authorize(), client_type:%d\n", ret, client_type);
    return ret;
}

int SrsRtmpConn::on_connect()
{
    return http_hooks_on_connect();
}

void SrsRtmpConn::on_close()
{
    srs_rtsp_debug("on_close begin\n");
    if(SrsRtmpConnPlay == client_type)
    {
        http_hooks_on_play_close();
    }
    else
    {
        if(is_http_hooks_close_enable())
        {
            http_hooks_on_close();
            //srs_trace("http_hooks_on_close end\n");
        }
        else
        {
            //srs_rtsp_debug("on_close write_database_on_close begin\n");
            write_database_on_close();
            //srs_trace("write_database_on_close end\n");
        }
    }
    
}

int SrsRtmpConn::write_database_on_close()
{
    int ret = 0;
    if(NULL == req)
    {
        srs_error("Invalid parameter, req:%p\n", req);
        return -1;
    }

    if(NULL == m_pdb_conn_mgr)
    {
        m_pdb_conn_mgr = database_connection_manager::get_inst(m_slocal_ip.c_str());
        ret = m_pdb_conn_mgr->connect_database_from_config(RTMP_CONNECT_DB_CONF, req->vhost.c_str(), "database");
        SRS_CHECK_RESULT(ret);
    }

    if(m_pdb_conn_mgr && m_pdb_conn_mgr->exist_database(RTMP_CONNECT_DB_CONF))
    {
        //char buf[1024] = {0};
        stringstream ss;
        ss << "UPDATE " << RTMP_CONN_INFO_TABLE_NAME << ", " << RTMP_STORAGE_SPACE_INFO_NAME;
        ss << " SET " << RTMP_CONN_INFO_TABLE_NAME << ".connection_status=" << 2 << ", " << RTMP_CONN_INFO_TABLE_NAME << ".disconnect_type=" << req->disconnect_type <<", " <<  RTMP_CONN_INFO_TABLE_NAME << ".disconnect_time=\""<<get_datetime(true) <<"\", " << RTMP_STORAGE_SPACE_INFO_NAME << ".available=1 ";
        ss << "WHERE " << RTMP_CONN_INFO_TABLE_NAME << ".rtmp_app_name=\"" << req->app << "\" AND " << RTMP_CONN_INFO_TABLE_NAME << ".rtmp_stream_name=\"" << req->stream << "\" AND " << RTMP_STORAGE_SPACE_INFO_NAME << ".storage_space_no=" << RTMP_CONN_INFO_TABLE_NAME << ".storage_space_no";
        string cmd = ss.str();
        // connect status: 0: not connect, 1: connected, 2: disconnect, disconnect_type: 0:client disconnect, 1: timeout, 2: server disconnect, 3: server abort
        //char* cmd_fmt = "UPDATE cos_connection, cos_storage_space SET cos_connection.connection_status=%d, cos_connection.disconnect_type=%d, cos_connection.disconnect_time=\"%s\", cos_storage_space.available=%d WHERE cos_connection.rtmp_app_name=\"%s\" AND cos_connection.rtmp_stream_name=\"%s\" AND cos_storage_space.storage_space_no=cos_connection.storage_space_no;";
        //sprintf(buf, cmd_fmt, 2, req->disconnect_type, get_datetime(true).c_str(), 1, req->app.c_str(), req->stream.c_str());
        /*char* pfmt = "UPDATE cos_connection, cos_storage_space SET cos_connection.connection_status=%d, cos_storage_space.available=%d, cos_connection.disconnect_at=\"%s\" WHERE cos_connection.app_name=\"%s\" AND cos_connection.rtmp_stream_name=\"%s\" AND cos_storage_space.storage_space_no=cos_connection.storage_space_no;"
        string cmd = "hmset " + key;
        for(map<string, string>::const_iterator it = fieldmap.begin(); it != fieldmap.end(); it++)
        {
            cmd += " " + it->first + " " + it->second;
            //srs_trace("cmd:%s", cmd.c_str());
        }*/
        //srs_trace("cmd:%s\n", cmd.c_str());
        ret = m_pdb_conn_mgr->send_command(RTMP_CONNECT_DB_CONF, cmd);
        SRS_CHECK_RESULT(ret);
    }

    return ret;
}

int SrsRtmpConn::http_hooks_on_publish()
{
    int ret = ERROR_SUCCESS;
    
#ifdef SRS_AUTO_HTTP_CALLBACK
    if (!_srs_config->get_vhost_http_hooks_enabled(req->vhost)) {
        return ret;
    }
    
    // the http hooks will cause context switch,
    // so we must copy all hooks for the on_connect may freed.
    // @see https://github.com/ossrs/srs/issues/475
    vector<string> hooks;
    
    if (true) {
        SrsConfDirective* conf = _srs_config->get_vhost_on_publish(req->vhost);
        
        if (!conf) {
            srs_info("ignore the empty http callback: on_publish");
            return ret;
        }
        
        hooks = conf->args;
    }
    
    for (int i = 0; i < (int)hooks.size(); i++) {
        std::string url = hooks.at(i);
        if ((ret = SrsHttpHooks::on_publish(url, req)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "hook client on_publish failed. url=%s, ret=%d", url.c_str(), ret);
            return ret;
        }
    }
#endif

    return ret;
}

void SrsRtmpConn::http_hooks_on_unpublish()
{
#ifdef SRS_AUTO_HTTP_CALLBACK
    if (!_srs_config->get_vhost_http_hooks_enabled(req->vhost)) {
        return;
    }
    
    // the http hooks will cause context switch,
    // so we must copy all hooks for the on_connect may freed.
    // @see https://github.com/ossrs/srs/issues/475
    vector<string> hooks;
    
    if (true) {
        SrsConfDirective* conf = _srs_config->get_vhost_on_unpublish(req->vhost);
        
        if (!conf) {
            srs_info("ignore the empty http callback: on_unpublish");
            return;
        }
        
        hooks = conf->args;
    }
    
    for (int i = 0; i < (int)hooks.size(); i++) {
        std::string url = hooks.at(i);
        SrsHttpHooks::on_unpublish(url, req);
    }
#endif
}

int SrsRtmpConn::http_hooks_on_play()
{
    int ret = ERROR_SUCCESS;
    
#ifdef SRS_AUTO_HTTP_CALLBACK
    if (!_srs_config->get_vhost_http_hooks_enabled(req->vhost)) {
        return ret;
    }
    
    // the http hooks will cause context switch,
    // so we must copy all hooks for the on_connect may freed.
    // @see https://github.com/ossrs/srs/issues/475
    vector<string> hooks;
    
    if (true) {
        SrsConfDirective* conf = _srs_config->get_vhost_on_play(req->vhost);
        
        if (!conf) {
            srs_info("ignore the empty http callback: on_play");
            return ret;
        }
        
        hooks = conf->args;
    }
    
    for (int i = 0; i < (int)hooks.size(); i++) {
        std::string url = hooks.at(i);
        if ((ret = SrsHttpHooks::on_play(url, req)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "hook client on_play failed. url=%s, ret=%d", url.c_str(), ret);
            return ret;
        }
    }
#endif

    return ret;
}

void SrsRtmpConn::http_hooks_on_stop()
{
#ifdef SRS_AUTO_HTTP_CALLBACK
    if (!_srs_config->get_vhost_http_hooks_enabled(req->vhost)) {
        return;
    }
    
    // the http hooks will cause context switch,
    // so we must copy all hooks for the on_connect may freed.
    // @see https://github.com/ossrs/srs/issues/475
    vector<string> hooks;
    
    if (true) {
        SrsConfDirective* conf = _srs_config->get_vhost_on_stop(req->vhost);
        
        if (!conf) {
            srs_info("ignore the empty http callback: on_stop");
            return;
        }
        
        hooks = conf->args;
    }
    
    for (int i = 0; i < (int)hooks.size(); i++) {
        std::string url = hooks.at(i);
        SrsHttpHooks::on_stop(url, req);
    }
#endif

    return;
}

bool SrsRtmpConn::is_http_hooks_close_enable()
{
    if (!_srs_config->get_vhost_http_hooks_enabled(req->vhost)) {
        srs_trace("%s http hook disable", req->vhost.c_str());
        return false;
    }
    
    SrsConfDirective* conf = _srs_config->get_vhost_on_close(req->vhost);
    
    return conf ? true : false;
}

int SrsRtmpConn::handle_metadata(SrsOnMetaDataPacket* metadata)
{
    if(!metadata || !metadata->metadata)
    {
        tag_error(get_device_sn(req, 0), "invalid metadata prt, !metadata:%p || !metadata->metadata:%p", metadata, metadata->metadata);
        return -1;
    }

    if (!metadata->metadata->get_property("type"))
    {
        srs_warn("invalid metadata, get_property(type) failed!");
        for(int i = 0; i < metadata->metadata->count(); i++)
        {
            std::string key = metadata->metadata->key_at(i);
            srs_trace("metadata key:%s\n", key.c_str());
        }

        if(metadata->metadata->get_property("videocodecid"))
        {
            int videocodecid = (int)metadata->metadata->get_property("videocodecid")->to_number();
            srs_trace("videocodecid:%d\n", videocodecid);
        }

        return 0;
    }
    int type = (int)metadata->metadata->get_property("type")->to_number();
    switch(type)
    {
        case METADATA_TYPE_STREAM_START:
        {
            if(rtmp)
            {
                std::string datetime;
                SrsAmf0Any* prop = metadata->metadata->get_property("datetime");
                if(prop && prop->is_string())
                //if(metadata->metadata->is_string())
                {
                    datetime = metadata->metadata->get_property("datetime")->to_str();
                }
                else
                {
                    struct tm *ptr;
                    time_t lt;
                    char str[80];
                    lt=time(NULL);
                    ptr=localtime(&lt);
                    char buf[100] = {0};
                    strftime(buf, 100, "%Y%m%d-%H%M%S", ptr);
                    datetime = buf;
                }

                write_data_cfg wdc;
                wdc.enc_record_data_path = _srs_config->get_string_config("srs_enc_record_data_path", NULL);
                wdc.dec_record_data_path = _srs_config->get_string_config("srs_dec_record_data_path", NULL);
                wdc.write_h264_data_path = _srs_config->get_string_config("srs_write_h264_data_path", NULL);
                wdc.write_aac_data_path = _srs_config->get_string_config("srs_write_aac_data_path", NULL);
                wdc.enc_record_data_path = srs_string_replace(wdc.enc_record_data_path, "[date]", datetime);
                wdc.dec_record_data_path = srs_string_replace(wdc.dec_record_data_path, "[date]", datetime);
                wdc.write_h264_data_path = srs_string_replace(wdc.write_h264_data_path, "[date]", datetime);
                wdc.write_aac_data_path = srs_string_replace(wdc.write_aac_data_path, "[date]", datetime);
                //std::string datetime = metadata->metadata->get_property("type")->to_str();
                rtmp->on_stream_start(&wdc);
                //srs_trace("wdc.enc_record_data_path:%s, wdc.dec_record_data_path:%s, wdc.write_h264_data_path:%s, wdc.write_aac_data_path:%s\n", wdc.enc_record_data_path.c_str(), wdc.dec_record_data_path.c_str(), wdc.write_h264_data_path.c_str(), wdc.write_aac_data_path.c_str());
            }
        }
        break;
        case METADATA_TYPE_STREAM_STOP:
        {
            if(rtmp)
            {
                rtmp->on_stream_stop();
            }
        }
        break;
        case METADATA_TYPE_VIDEO_ENCRYPT:
        {
            int venctype = 0;
            int skipbytes = 0;
            int rsaenctype = 0;
            string vencstring;
            if(metadata->metadata->get_property("venctype"))
            {
                venctype = (int)metadata->metadata->get_property("venctype")->to_number();
            }
            if(metadata->metadata->get_property("skipbytes"))
            {
                skipbytes = metadata->metadata->get_property("skipbytes")->to_number();
            }
            if(metadata->metadata->get_property("vkeyenctype"))
            {
                 req->naesKeyEncType = rsaenctype = (int)metadata->metadata->get_property("vkeyenctype")->to_number();
            }
            if(metadata->metadata->get_property("vencstring"))
            {
                string vencstr = metadata->metadata->get_property("vencstring")->to_str();
#ifdef RSA_ENCRYPT_AES_KEY
                vencstring = decrypt_aes_key(rsaenctype, vencstr.c_str(), vencstr.length());
                //vencstring
                /*if(1 == rsaenctype)//rsa encrypt
                {
                    char decbuf[256] = {0};
                    int dec_buf_len = 256;
                    rsaenc rsa_dec;
                    int declen = rsa_dec.private_key_decrypt(prikey, vencstr.c_str(), vencstr.length(), decbuf, dec_buf_len);
                    if(declen > 0)
                    {
                        vencstring = decbuf;
                    }
                    //aencstring = rsa_decrypt(prikey, aencstr.c_str(), aencstr.length());
                    srs_trace("vencstr:%s, vencstr:%d, declen:%d, vencstring:%s", vencstr.c_str(), vencstr.length(), declen, vencstring.c_str());
                }
                else
                {
                    vencstring = vencstr;
                }*/
#endif
            }
            srs_info("video encrypt, venctype:%d, vencstring:%s, skipbytes:%d, vkeyenctype:%d", venctype, vencstring.c_str(), skipbytes, rsaenctype);
            if(venctype > 0 && rtmp && !vencstring.empty())
            {
                //srs_trace("rtmp:%p->InitEncrypt(type:%d, venctype:%d, vencstring:%s, skipbytes:%d)", rtmp, type, venctype, vencstring.c_str(), skipbytes);
                return rtmp->InitEncrypt(type, (int)venctype, vencstring.c_str(), skipbytes);
            }
        }
        break;
        case METADATA_TYPE_AUDIO_ENCRYPT:
        {
            int aenctype = 0;
            int skipbytes = 0;
            int rsaenctype = 0;
            string aencstring;
            if(metadata->metadata->get_property("aenctype"))
            {
                aenctype = (int)metadata->metadata->get_property("aenctype")->to_number();
            }
            if(metadata->metadata->get_property("skipbytes"))
            {
                skipbytes = metadata->metadata->get_property("skipbytes")->to_number();
            }
            if(metadata->metadata->get_property("akeyenctype"))
            {
                 rsaenctype = (int)metadata->metadata->get_property("akeyenctype")->to_number();
            }
            if(metadata->metadata->get_property("aencstring"))
            {
                string aencstr = metadata->metadata->get_property("aencstring")->to_str();
#ifdef RSA_ENCRYPT_AES_KEY
                aencstring = decrypt_aes_key(rsaenctype, aencstr.c_str(), aencstr.length());
                /*if(1 == rsaenctype)//rsa encrypt
                {
                    char decbuf[256] = {0};
                    int dec_buf_len = 256;
                    rsaenc rsa_dec;
                    int declen = rsa_dec.private_key_decrypt(prikey, aencstr.c_str(), aencstr.length(), decbuf, dec_buf_len);
                    if(declen > 0)
                    {
                        aencstring = decbuf;
                    }
                    //aencstring = rsa_decrypt(prikey, aencstr.c_str(), aencstr.length());
                    srs_trace("aencstr:%s, aenclen:%d, declen:%d, aencstring:%s", aencstr.c_str(), aencstr.length(), declen, aencstring.c_str());
                }
                else
                {
                    aencstring = aencstr;
                }*/
#endif
            }
            srs_info("audio encrypt, aenctype:%d, aencstring:%s, skipbytes:%d, akeyenctype:%d", aenctype, aencstring.c_str(), skipbytes, rsaenctype);
            if(aenctype > 0 && rtmp && !aencstring.empty())
            {
                //srs_trace("rtmp->InitEncrypt(type:%d, aenctype:%d, aencstring:%s, skipbytes:%d)", type, aenctype, aencstring.c_str(), skipbytes);
                return rtmp->InitEncrypt(type, aenctype, aencstring.c_str(), skipbytes);
            }
        }
        break;
        case METADATA_TYPE_STREAM_BITRATE:
        {
            int vbitrate = 0;
            int abitrate = 0;
            string aencstring;
            if(metadata->metadata->get_property("vbitrate"))
            {
                vbitrate = (int)metadata->metadata->get_property("vbitrate")->to_number();
            }
            if(metadata->metadata->get_property("abitrate"))
            {
                abitrate = (int)metadata->metadata->get_property("abitrate")->to_number();
            }
            srs_trace("SDK vbitrate:%d, abitrate:%d", vbitrate, abitrate);
        }
        break;
        case METADATA_TYPE_STREAM_DROP_FRAME:
        {
            int vdropframe = 0;
            int adropframe = 0;
            string aencstring;
            if(metadata->metadata->get_property("vdropframe"))
            {
                vdropframe = (int)metadata->metadata->get_property("vdropframe")->to_number();
            }
            if(metadata->metadata->get_property("adropframe"))
            {
                adropframe = (int)metadata->metadata->get_property("adropframe")->to_number();
            }
            srs_trace("SDK vdropframe:%d, adropframe:%d", vdropframe, adropframe);
        }
        break;
        case METADATA_TYPE_IPC_STREAM_DISCONNECT:
        {
            int vconnect = 0;
            int aconnect = 0;
            //string aencstring;
            if(metadata->metadata->get_property("vconnect"))
            {
                vconnect = (int)metadata->metadata->get_property("vconnect")->to_number();
            }
            if(metadata->metadata->get_property("aconnect"))
            {
                aconnect = (int)metadata->metadata->get_property("aconnect")->to_number();
            }
            srs_trace("SDK vconnect:%d, aconnect:%d", vconnect, aconnect);
        }
        break;
        case METADATA_TYPE_TIGGER_TYPE_CHANGE:
        {
            int old_tigger_type = 0;
            int new_tigger_type = 0;
            //string aencstring;
            if(metadata->metadata->get_property("old_tigger_type"))
            {
                old_tigger_type = (int)metadata->metadata->get_property("old_tigger_type")->to_number();
            }
            if(metadata->metadata->get_property("new_tigger_type"))
            {
                new_tigger_type = (int)metadata->metadata->get_property("new_tigger_type")->to_number();
            }
            //srs_trace("tigger type change, old_tigger_type:%d, new_tigger_type:%d", old_tigger_type, new_tigger_type);
        }
        break;
        default:
            srs_warn("Invalid metadata type:%d", type);
        break;
    }

    return ERROR_SUCCESS;
}
#ifdef SRS_AUTO_FORWARD_WEBRTC
int SrsRtmpConn::send_metadate(SrsOnMetaDataPacket* pmetadata)
{
    int ret = -1;
    srs_trace("send metadata(pmetadata:%p) rtmp:%p", pmetadata, rtmp);
    if(rtmp && pmetadata)
    {
         ret = rtmp->send_and_free_packet(pmetadata, 0);
         srs_trace("ret:%d = rtmp->send_and_free_packet(pmetadata:%p, 0)", ret, pmetadata);
    }
    return -1;
}
#endif
int SrsRtmpConn::load_write_data_config()
{
    // add by dawson for video and audio data write test
    int ret = ERROR_SUCCESS;
    if(_srs_config)
    {
        std::string datetime = generate_datetime();
        std::string avcencpath;
        std::string avcpath;
        std::string aacencpath;
        std::string aacpath;
#ifdef ENABLE_WRITE_VIDEO_STREAM
        std::string avc_enc_fmt = _srs_config->get_h264_enc_data_write_path();
        std::string avc_fmt = _srs_config->get_h264_data_write_path();

        if(!avc_enc_fmt.empty())
        {
            avcencpath = srs_string_replace(avc_enc_fmt, "[date]", datetime);
            srs_trace("avcencpath:%s = srs_string_replace(avc_enc_fmt:%s, [date], datetime:%s)", avcencpath.c_str(), avc_enc_fmt.c_str(), datetime.c_str());
        }

        if(!avc_fmt.empty())
        {
            avcpath = srs_string_replace(avc_fmt, "[date]", datetime);
            srs_trace("avcpath:%s = srs_string_replace(avc_fmt:%s, [date], datetime:%s)", avcpath.c_str(), avc_fmt.c_str(), datetime.c_str());
        }
        srs_trace("avc_enc_fmt:%s, avcencpath:%s, avc_fmt:%s, avcpath:%s", avc_enc_fmt.c_str(), avcencpath.c_str(), avc_fmt.c_str(), avcpath.c_str());
        if(!avcencpath.empty() || !avcpath.empty())
        {
            ret = rtmp->SetVideoWriteDataPath(avcencpath, avcpath);
            srs_trace("ret:%d = rtmp->SetVideoWriteDataPath(avcencpath:%s, avcpath:%s)", ret, avcencpath.c_str(), avcpath.c_str());
        }
        
#endif
#ifdef ENABLE_WRITE_AUDIO_STREAM
        std::string aac_enc_fmt = _srs_config->get_aac_enc_data_write_path();
        std::string aac_fmt = _srs_config->get_aac_data_write_path();
        
        if(!aac_enc_fmt.empty())
        {
            aacencpath = srs_string_replace(aac_enc_fmt, "[date]", datetime);
            srs_trace("aacencpath:%s = srs_string_replace(aac_enc_fmt:%s, [date], datetime:%s)", aacencpath.c_str(), aac_enc_fmt.c_str(), datetime.c_str());
        }
        
        if(!aac_fmt.empty())
        {
            aacpath = srs_string_replace(aac_fmt, "[date]", datetime);
            srs_trace("aacpath:%s = srs_string_replace(aac_fmt:%s, [date], datetime:%s)", aacpath.c_str(), aac_fmt.c_str(), datetime.c_str());
        }
        srs_trace("aac_enc_fmt:%s, aacencpath:%s, aac_fmt:%s, aacpath:%s", aac_enc_fmt.c_str(), aacencpath.c_str(), aac_fmt.c_str(), aacpath.c_str());
        if(!aacencpath.empty() || !aacpath.empty())
        {
            srs_trace("before rtmp:%p->SetAudioWriteDataPath(aacencpath, aacpath)", rtmp);
            //ret = rtmp->SetAudioWriteDataPath(aacencpath, aacpath);
            srs_trace("ret:%d = rtmp->SetAudioWriteDataPath(aacencpath:%s, aacpath:%s)", ret, aacencpath.c_str(), aacpath.c_str());
        }
        srs_verbose("end ret:%d", ret);
#endif
    }

    return ret;
}

int SrsRtmpConn::authorize_check(SrsRtmpConnType type)
{
    int ret = ERROR_SUCCESS;
    int rtmp_auth = 0;
    if(!req->srsForwardHostName.empty())
    {
        return 0;
    }
    if(SrsRtmpConnPlay == type)
    {
        rtmp_auth = _srs_config->get_int_config("auth_type", 0, req->vhost.c_str(), HTTP_HOOKS_ON_PLAY_CONF_NAME);
        //srs_trace("rtmp_auth:%d = _srs_config->get_int_config(rtmp_play_auth, 0, req->vhost.c_str():%s, %s)", rtmp_auth, req->vhost.c_str(), HTTP_HOOKS_ON_PLAY_CONF_NAME);
    }
    else
    {
        rtmp_auth = _srs_config->get_int_config("rtmp_push_auth", 0, req->vhost.c_str(), RTMP_HTTP_HOOKS_CONF_NAME);
        //srs_trace("rtmp_auth:%d = _srs_config->get_int_config(rtmp_push_auth, 1, req->vhost.c_str():%s, %s)", rtmp_auth, req->vhost.c_str(), RTMP_HTTP_HOOKS_CONF_NAME);
    }
    if(rtmp_auth < 0 || rtmp_auth > 2)
    {
        tag_error(get_device_sn(req, 0), "Invalid rtmp authorize type %d, connect type %d", rtmp_auth, type);
        return ERROR_RTMP_TOKEN_AUTH_FAIL;
    }
    //req->eauth_type = (e_auth_type)rtmp_auth;
    //srs_trace("req->eauth_type:%d, rtmp_auth:%d\n", req->eauth_type, rtmp_auth);
    switch(req->eauth_type)
    {
        case e_auth_type_no_token:
        {
            if(rtmp_auth == 2)
            {
                tag_error(get_device_sn(req, 0), "rtmp connect type %d, rtmp_auth:%d, no token error, authorize failed", type, rtmp_auth);
                return ERROR_RTMP_CONNECT_WITHOUT_TOKEN;
            }
            req->userid = "dawson";
            break;
        }
        case e_auth_type_success:
        {
            break;
        }
        case e_auth_type_failed:
        {
            if(1 == rtmp_auth || 2 == rtmp_auth)
            {
                return ERROR_RTMP_TOKEN_AUTH_FAIL;
            }
            break;
        }
        case e_auth_type_no_server:
        {
            srs_warn("warning, no token authorize server!");
            break;
        }
        default:
        tag_error(get_device_sn(req, 0), "invalid auth type %d", req->eauth_type);
        assert(0);
        return ERROR_RTMP_INVALID_AUTH_TYPE;
        break;
    }
    srs_info("token authorize success, connect type:%d, rtmp_auth %d", type, rtmp_auth);
    return ret;
}

std::string SrsRtmpConn::decrypt_aes_key(int enc_type, const char* enc_buf, int enc_len)
{
    std::string aeskey;
    srs_info("decrypt_aes_key(enc_type:%d, enc_buf:%p, enc_len:%d)\n", enc_type, enc_buf, enc_len);
    if(SV_KEY_ENC_TYPE_NONE == enc_type)
    {
        aeskey.append(enc_buf, enc_len);
    }
    else if(SV_KEY_ENC_TYPE_RSA & enc_type || enc_type & SV_KEY_ENC_TYPE_BASE64)//(enc_type == (SV_KEY_ENC_TYPE_RSA|SV_KEY_ENC_TYPE_BASE64))
    {
        aeskey.append(enc_buf, enc_len);
        if(enc_type & SV_KEY_ENC_TYPE_BASE64)
        {
            uint8_t rsa_enc[256] = {0};
            int rsa_enc_len = srs_av_base64_decode(rsa_enc, aeskey.c_str(), 256);
            //srs_trace("rsa_enc_len:%d = srs_av_base64_decode()\n", rsa_enc_len);
            if(rsa_enc_len > 0)
            {
                aeskey.clear();
                aeskey.append((char*)rsa_enc, rsa_enc_len);
            }
            else
            {
                aeskey.clear();
                tag_error(get_device_sn(req, 0), "rsa_enc_len:%d = srs_av_base64_decode(rsa_enc, enc_str.c_str():%s, enc_str.length():%d) failed\n", rsa_enc_len, aeskey.c_str(), aeskey.size());
                return aeskey;
            }
            
        }

        if(SV_KEY_ENC_TYPE_RSA & enc_type)
        {
            char dec_buf[256] = {0};
            rsaenc rsa_dec;
            int declen  = rsa_dec.private_key_decrypt(prikey, (const char*)aeskey.c_str(), aeskey.size(), dec_buf, 256);
            //srs_trace("declen:%d  = rsa_dec.private_key_decrypt\n", declen);
            if(declen <= 0)
            {
                tag_error(get_device_sn(req, 0), "declen:%d = rsa_dec.private_key_decrypt(prikey, (const char*)aeskey.c_str():%p, aeskey.size():%ld, dec_buf:%s, 256)\n", declen, aeskey.c_str(), aeskey.size(), dec_buf);
                aeskey.clear();
            }
            else
            {
                aeskey.clear();
                aeskey.append(dec_buf, declen);
            }
        }
        /*uint8_t rsa_enc[256] = {0};
        int rsa_enc_len = srs_av_base64_decode(rsa_enc, enc_buf, enc_len);
        if(rsa_enc_len <= 0)
        {
            tag_error(get_device_sn(req, 0), "rsa_enc_len:%d = srs_av_base64_decode(rsa_enc, b64_enc_buf:%s, b64_enc_len:%d)\n", rsa_enc_len , enc_buf, enc_len);
        }
        rsaenc rsa_dec;
        char decbuf[256] = {0};
        int dec_buf_len = 256;
        int declen  = rsa_dec.private_key_decrypt(prikey, (const char*)rsa_enc, rsa_enc_len, decbuf, dec_buf_len);
        if(declen <= 0)
        {
            tag_error(get_device_sn(req, 0), "declen:%d = rsa_dec.private_key_decrypt(prikey, (const char*)rsa_enc:%p, rsa_enc_len:%d, decbuf:%s, dec_buf_len:%d)\n", declen, rsa_enc, rsa_enc_len, decbuf, dec_buf_len);
        }

        aes_key = decbuf;*/
        //srs_trace("decoder aeskey:%s success\n", aeskey.c_str());
    }
    else
    {
        tag_error(get_device_sn(req, 0), "Invalid enctype:%d\n", enc_type);
    }

    return aeskey;
}
/*#define HASH_RTMP_APP_FIELD             "rtmpAppName"
#define HASH_RTMP_STREAM_FIELD          "rtmpStreamName"
#define HASH_RECORD_START_TIME_FIELD    "mediaRecordStartTime"
#define HASH_TIME_ZONE_FIELD            "timeZone"
#define HASH_RTMP_TIGGER_TYPE_FIELD     "tiggerType"
#define HASH_RTMP_SEGMENT_ALARM_TIME    "alarmTime"
#define HASH_RTMP_SERVER_HOST_NAME      "serverHostName"
#define HASH_RTMP_SERVER_PORT           "serverPort"
#define HASH_RTMP_APP_KEY               "appKey"
#define HASH_RTMP_USER_ID               "userId"
#define HASH_RTMP_TIMESTAMP             "timeStamp"*/
int SrsRtmpConn::rtmp_connnection_change(int connected)
{
    int ret = 0;
    if(!write_rtmp_conn_enalbe())
    {
        //srs_trace("disable write rtmp connection to db, connected%d, req->streamType:%d\n", connected, req->streamType);
        return 0;
    }
    //srs_trace("rtmp_connnection_change(connected:%d), client_type:%d\n", connected, client_type);
    if(SrsRtmpConnPlay >= client_type)
    {
        //srs_trace("rtmp_push_connnection client_type:%d\n", client_type);
        return 0;
    }
    string key = m_slocal_ip + ":" + long_to_string((long)m_nport) + ":" + req->devicesn;

    if(NULL == m_pdb_conn_mgr)
    {
        m_pdb_conn_mgr = database_connection_manager::get_inst(m_slocal_ip.c_str());
        m_pdb_conn_mgr->connect_database_from_config(HLS_RECORD_DB_CONF, req->vhost.c_str(), "database");
        m_pdb_conn_mgr->flush_namespace(HLS_RECORD_DB_CONF, m_slocal_ip.c_str());
        //srs_rtsp_debug("m_pdb_conn_mgr->connect_database_from_config(HLS_RECORD_DB_CONF, preq->vhost.c_str(), database)", preq->vhost.c_str());
    }
    if(m_pdb_conn_mgr && m_pdb_conn_mgr->exist_database(HLS_RECORD_DB_CONF))
    {
        string cmd;
        if(connected)
        {
            long ts = get_timestamp();
            map<string, string> hashmap;
            hashmap[HASH_RTMP_APP_FIELD]            = req->app;
            hashmap[HASH_RTMP_STREAM_FIELD]         = req->stream;
            hashmap[HASH_RTMP_SERVER_HOST_NAME]     = m_slocal_ip;
            hashmap[HASH_RTMP_SERVER_PORT]          = long_to_string((long)m_nport);
            hashmap[HASH_RTMP_APP_KEY]              = req->appkey;
            hashmap[HASH_RTMP_USER_ID]              = req->userid;
            hashmap[HASH_RTMP_TIMESTAMP]            = long_to_string(ts);
            //srs_trace("rtmp_conn key:%s, app:%s, stream:%s, m_slocal_ip:%s, m_nport:%d, appkey:%s, userid:%s, timestamp:%ld", key.c_str(), req->app.c_str(), req->stream.c_str(), m_slocal_ip.c_str(), m_nport, req->appkey.c_str(), req->userid.c_str(), ts);
            cmd = "hmset " + key;
            for(map<string, string>::const_iterator it = hashmap.begin(); it != hashmap.end(); it++)
            {
                cmd += " " + it->first + " " + it->second;
                //srs_trace("cmd:%s", cmd.c_str());
            }
        }
        else
        {
            cmd = "del " + key;
        }
        
        ret = m_pdb_conn_mgr->send_command(HLS_RECORD_DB_CONF, cmd);
        srs_trace("ret:%d = m_pdb_conn_mgr->send_command(HLS_RECORD_DB_CONF, cmd:%s)\n", ret,  cmd.c_str());
    }

    return ret;
}

bool SrsRtmpConn::write_rtmp_conn_enalbe()
{
    std::vector<int> streamTypeList = _srs_config->get_int_config_list("rtmp_conn_write_db_type", req->vhost.c_str(), "database");
    for(size_t i = 0; i < streamTypeList.size(); i++)
    {
        if(req && req->streamType == streamTypeList[i])
        {
            return true;
        }
    }

    return false;
}
