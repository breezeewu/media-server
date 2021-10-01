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

#include <srs_app_hls.hpp>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <algorithm>
#include <sstream>
using namespace std;

#include <srs_kernel_error.hpp>
#include <srs_kernel_codec.hpp>
#include <srs_rtmp_amf0.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_app_config.hpp>
#include <srs_app_source.hpp>
#include <srs_core_autofree.hpp>
#include <srs_rtmp_stack.hpp>
#include <srs_app_pithy_print.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_kernel_codec.hpp>
#include <srs_kernel_file.hpp>
#include <srs_protocol_buffer.hpp>
#include <srs_kernel_ts.hpp>
#include <srs_app_utility.hpp>
#include <srs_app_http_hooks.hpp>
#include <srs_app_db_conn.hpp>
#ifdef TS_SLICE_WRITE_REDIS
#include <srs_app_redis.hpp>
#include <srs_protocol_json.hpp>
#endif

// drop the segment when duration of ts too small.
#define SRS_AUTO_HLS_SEGMENT_MIN_DURATION_MS 100
// when hls timestamp jump, reset it.
#define SRS_AUTO_HLS_SEGMENT_TIMESTAMP_JUMP_MS 300

// fragment plus the deviation percent.
#define SRS_HLS_FLOOR_REAP_PERCENT 0.3
// reset the piece id when deviation overflow this.
#define SRS_JUMP_WHEN_PIECE_DEVIATION 20

/**
 * * the HLS section, only available when HLS enabled.
 * */
#ifdef SRS_AUTO_HLS

SrsHlsCacheWriter::SrsHlsCacheWriter(bool write_cache, bool write_file)
{
    should_write_cache = write_cache;
    should_write_file = write_file;
}

SrsHlsCacheWriter::~SrsHlsCacheWriter()
{
}

int SrsHlsCacheWriter::open(string file)
{
    if (!should_write_file) {
        return ERROR_SUCCESS;
    }

    return impl.open(file);
}

void SrsHlsCacheWriter::close()
{
    if (!should_write_file) {
        return;
    }

    impl.close();
}

bool SrsHlsCacheWriter::is_open()
{
    if (!should_write_file) {
        return true;
    }

    return impl.is_open();
}

int64_t SrsHlsCacheWriter::tellg()
{
    if (!should_write_file) {
        return 0;
    }

    return impl.tellg();
}

int SrsHlsCacheWriter::write(void* buf, size_t count, ssize_t* pnwrite)
{
    if (should_write_cache) {
        if (count > 0) {
            data.append((char*)buf, count);
        }
    }

    if (should_write_file) {
        return impl.write(buf, count, pnwrite);
    }

    return ERROR_SUCCESS;
}

string SrsHlsCacheWriter::cache()
{
    return data;
}

SrsHlsSegment::SrsHlsSegment(SrsTsContext* c, bool write_cache, bool write_file, SrsCodecAudio ac, SrsCodecVideo vc)
{
    duration = 0;
    sequence_no = 0;
    segment_start_dts = 0;
    is_sequence_header = false;
    writer = new SrsHlsCacheWriter(write_cache, write_file);
    LB_ADD_MEM(writer, sizeof(SrsHlsCacheWriter));
    muxer = new SrsTSMuxer(writer, c, ac, vc);
    max_ts_dur = 90*90000*2;
    LB_ADD_MEM(muxer, sizeof(SrsTSMuxer));
}

SrsHlsSegment::~SrsHlsSegment()
{
    srs_freep(muxer);
    srs_freep(writer);
}

int SrsHlsSegment::update_duration(int64_t current_frame_dts)
{
    // we use video/audio to update segment duration,
    // so when reap segment, some previous audio frame will
    // update the segment duration, which is nagetive,
    // just ignore it.
    if (current_frame_dts < segment_start_dts) {
        // for atc and timestamp jump, reset the start dts.
        if (current_frame_dts < segment_start_dts - SRS_AUTO_HLS_SEGMENT_TIMESTAMP_JUMP_MS * 90) {
            //srs_warn("hls timestamp jump %"PRId64"=>%"PRId64, segment_start_dts, current_frame_dts);
            segment_start_dts = current_frame_dts;
        }
        return ERROR_SUCCESS;
    }
	
    if(current_frame_dts - segment_start_dts >= max_ts_dur * 90000 * 2)
    {
        srs_warn("current dts:%"PRId64" - segment_start_dts:%"PRId64" = %"PRId64" >= max_ts_dur:%"PRId64" * 90000 * 2, current dts abnormal!\n", current_frame_dts, segment_start_dts, current_frame_dts - segment_start_dts, max_ts_dur);
        return ERROR_HLS_TS_ABNORMAL;
    }
    duration = (current_frame_dts - segment_start_dts) / 90000.0;
    srs_assert(duration >= 0);
    
    return ERROR_SUCCESS;
}

SrsDvrAsyncCallOnHls::SrsDvrAsyncCallOnHls(int c, SrsRequest* r, string p, string t, string m, string mu, int s, double d)
{
    req = r->copy();
    cid = c;
    path = p;
    ts_url = t;
    m3u8 = m;
    m3u8_url = mu;
    seq_no = s;
    duration = d;
}

SrsDvrAsyncCallOnHls::~SrsDvrAsyncCallOnHls()
{
    srs_freep(req);
}

int SrsDvrAsyncCallOnHls::call()
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
        SrsConfDirective* conf = _srs_config->get_vhost_on_hls(req->vhost);
        
        if (!conf) {
            srs_info("ignore the empty http callback: on_hls");
            return ret;
        }
        
        hooks = conf->args;
    }
    
    for (int i = 0; i < (int)hooks.size(); i++) {
        std::string url = hooks.at(i);
        if ((ret = SrsHttpHooks::on_hls(cid, url, req, path, ts_url, m3u8, m3u8_url, seq_no, duration)) != ERROR_SUCCESS) {
            srs_error("hook client on_hls failed. url=%s, ret=%d", url.c_str(), ret);
            return ret;
        }
    }
#endif
    
    return ret;
}

string SrsDvrAsyncCallOnHls::to_string()
{
    return "on_hls: " + path;
}

SrsDvrAsyncCallOnHlsNotify::SrsDvrAsyncCallOnHlsNotify(int c, SrsRequest* r, string u)
{
    cid = c;
    req = r->copy();
    ts_url = u;
}

SrsDvrAsyncCallOnHlsNotify::~SrsDvrAsyncCallOnHlsNotify()
{
    srs_freep(req);
}

int SrsDvrAsyncCallOnHlsNotify::call()
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
        SrsConfDirective* conf = _srs_config->get_vhost_on_hls_notify(req->vhost);
        
        if (!conf) {
            srs_info("ignore the empty http callback: on_hls_notify");
            return ret;
        }
        
        hooks = conf->args;
    }
    
    int nb_notify = _srs_config->get_vhost_hls_nb_notify(req->vhost);
    for (int i = 0; i < (int)hooks.size(); i++) {
        std::string url = hooks.at(i);
        if ((ret = SrsHttpHooks::on_hls_notify(cid, url, req, ts_url, nb_notify)) != ERROR_SUCCESS) {
            srs_error("hook client on_hls_notify failed. url=%s, ret=%d", url.c_str(), ret);
            return ret;
        }
    }
#endif
    
    return ret;
}

string SrsDvrAsyncCallOnHlsNotify::to_string()
{
    return "on_hls_notify: " + ts_url;
}

SrsHlsMuxer::SrsHlsMuxer()
{
    req = NULL;
    hls_fragment = hls_window = 0;
    hls_aof_ratio = 1.0;
    deviation_ts = 0;
    hls_cleanup = true;
    hls_wait_keyframe = true;
    previous_floor_ts = 0;
    accept_floor_ts = 0;
    hls_ts_floor = false;
    max_td = 0;
    _sequence_no = 0;
    current = NULL;
    acodec = SrsCodecAudioReserved1;
    vcodec = SrsCodecVideoReserved;
    should_write_cache = false;
    should_write_file = true;
     bm3u8_generate = false;
    async = new SrsAsyncCallWorker();
    LB_ADD_MEM(async, sizeof(SrsAsyncCallWorker));
    context = new SrsTsContext();
    LB_ADD_MEM(context, sizeof(SrsTsContext));
#ifdef TS_SLICE_WRITE_REDIS
    predishandle = NULL;
#endif
    m_pdb_conn_mgr = NULL;
}

SrsHlsMuxer::~SrsHlsMuxer()
{
    // add by dawson for generate empty m3u8file
    if(segments.size() <= 0 && bm3u8_generate)
    {
        srs_trace("hls segment is empty, delete m3u8 file if exist, m3u8:%s", m3u8.c_str());
        if(0 == access(m3u8.c_str(), F_OK))
        {
            srs_trace("remove(m3u8:%s)", m3u8.c_str());
            remove(m3u8.c_str());
        }
    }
    // for ts slice write redis
#ifdef TS_SLICE_WRITE_REDIS
    /*if(predishandle)
    {
        predishandle->disConnect();
        LB_DEL(predishandle);
        //delete predishandle;
        //predishandle = NULL;
    }*/
#endif
    // add end
    std::vector<SrsHlsSegment*>::iterator it;
    for (it = segments.begin(); it != segments.end(); ++it) {
        SrsHlsSegment* segment = *it;
        //srs_trace("%s segment->full_path:%s, segment->uri:%s", segment->full_path.c_str(), segment->uri.c_str());
        srs_freep(segment);
    }
    segments.clear();
    
    srs_freep(current);
    srs_freep(req);
    srs_freep(async);
    srs_freep(context);
}

void SrsHlsMuxer::dispose()
{
    if (should_write_file) {
        std::vector<SrsHlsSegment*>::iterator it;
        for (it = segments.begin(); it != segments.end(); ++it) {
            SrsHlsSegment* segment = *it;
            if (unlink(segment->full_path.c_str()) < 0) {
                srs_warn("dispose unlink path failed, file=%s.", segment->full_path.c_str());
            }
            srs_freep(segment);
        }
        segments.clear();
        
        if (current) {
            std::string path = current->full_path + ".tmp";
            if (unlink(path.c_str()) < 0) {
                srs_warn("dispose unlink path failed, file=%s", path.c_str());
            }
            srs_freep(current);
        }
        
        if (unlink(m3u8.c_str()) < 0) {
            srs_warn("dispose unlink path failed. file=%s", m3u8.c_str());
        }
    }
    
    // TODO: FIXME: support hls dispose in HTTP cache.
    
    srs_trace("gracefully dispose hls %s", req? req->get_stream_url().c_str() : "");
}

int SrsHlsMuxer::sequence_no()
{
    return _sequence_no;
}

string SrsHlsMuxer::ts_url()
{
    return current? current->uri:"";
}

double SrsHlsMuxer::duration()
{
    return current? current->duration:0;
}

int SrsHlsMuxer::deviation()
{
    // no floor, no deviation.
    if (!hls_ts_floor) {
        return 0;
    }
    
    return deviation_ts;
}

int SrsHlsMuxer::initialize()
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = async->start()) != ERROR_SUCCESS) {
        return ret;
    }
    
    return ret;
}

int SrsHlsMuxer::update_config(SrsRequest* r, string entry_prefix,
    string path, string m3u8_file, string ts_file, double fragment, double window,
    bool ts_floor, double aof_ratio, bool cleanup, bool wait_keyframe
) {
    int ret = ERROR_SUCCESS;
    //struct timeval tv;

    srs_freep(req);
    req = r->copy();

    hls_entry_prefix = entry_prefix;
    hls_path = path;
    hls_ts_file = ts_file;
    hls_fragment = fragment;
    hls_aof_ratio = aof_ratio;
    hls_ts_floor = ts_floor;
    hls_cleanup = cleanup;
    hls_wait_keyframe = wait_keyframe;
    previous_floor_ts = 0;
    accept_floor_ts = 0;
    hls_window = window;
    deviation_ts = 0;
    // add bu dawson for ts slice write redis
    if(req->datetime.empty())
    {
        req->datetime = get_time();
        srs_warn("req->datetime is empty, get time from local server!");
    }

#ifdef TS_SLICE_WRITE_REDIS
    //std::string ip = _srs_config->get_vhost_hls_redis_ip(req->vhost);
    //srs_trace("predishandle = CSrsRedisHandler::GetInst()");
    //on_update_config(req);
    _sequence_no = 0;
    //srs_trace("req->datetime:%s, req->llstart_timestamp:%"PRId64" _sequence_no:%d", req->datetime.c_str(), req->llstart_timestamp, _sequence_no);

    std::vector<SrsHlsSegment*>::iterator it;
    for (it = segments.begin(); it != segments.end(); ++it) {
        SrsHlsSegment* segment = *it;
        //srs_trace("segment->full_path:%s, segment->uri:%s", segment->full_path.c_str(), segment->uri.c_str());
        srs_freep(segment);
        //srs_trace("after srs_freep(segment)");
    }

    segments.clear();
    //srs_trace("after clear");
#endif
    //add end
    // generate the m3u8 dir and path.
    
    m3u8_url = srs_path_build_stream(m3u8_file, req->vhost, req->app, req->stream, req->datetime, req->appkey, req->userid, req->devicesn);
    //srs_trace("m3u8_url:%s = srs_path_build_stream(m3u8_file:%s, req->vhost:%s, req->app:%s, req->stream:%s, req->datetime:%s, req->appkey:%s, req->devicesn:%s)", m3u8_url.c_str(), m3u8_file.c_str(), req->vhost.c_str(), req->app.c_str(), req->stream.c_str(), req->datetime.c_str(), req->appkey.c_str(), req->devicesn.c_str());
    m3u8 = path + "/" + m3u8_url;

    // when update config, reset the history target duration.
    max_td = (int)(fragment * _srs_config->get_hls_td_ratio(r->vhost));
    
    // TODO: FIXME: refine better for SRS2 only support disk.
    should_write_cache = false;
    should_write_file = true;
    
    // create m3u8 dir once.
    m3u8_dir = srs_path_dirname(m3u8);
    if (should_write_file && (ret = srs_create_dir_recursively(m3u8_dir)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "create app dir %s failed. ret=%d", m3u8_dir.c_str(), ret);
        return ret;
    }
    srs_info("create m3u8 dir %s ok", m3u8_dir.c_str());
    //srs_trace("%s m3u8_dir:%s\n m3u8_url:%s\nm3u8:%s", __FUNCTION__, m3u8_dir.c_str(), m3u8_url.c_str(), m3u8.c_str());
    return ret;
}

int SrsHlsMuxer::segment_open(int64_t segment_start_dts)
{
    //srs_trace("%s segment_start_dts:%"PRId64, __FUNCTION__, segment_start_dts);
    int ret = ERROR_SUCCESS;
    
    if (current) {
        srs_warn("ignore the segment open, for segment is already open.");
        return ret;
    }
    
    // when segment open, the current segment must be NULL.
    srs_assert(!current);

    // load the default acodec from config.
    SrsCodecAudio default_acodec = SrsCodecAudioAAC;
    if (true) {
        std::string default_acodec_str = _srs_config->get_hls_acodec(req->vhost);
        if (default_acodec_str == "mp3") {
            default_acodec = SrsCodecAudioMP3;
            srs_info("hls: use default mp3 acodec");
        } else if (default_acodec_str == "aac") {
            default_acodec = SrsCodecAudioAAC;
            srs_info("hls: use default aac acodec");
        } else if (default_acodec_str == "an") {
            default_acodec = SrsCodecAudioDisabled;
            srs_info("hls: use default an acodec for pure video");
        } else {
            srs_warn("hls: use aac for other codec=%s", default_acodec_str.c_str());
        }
    }

    // load the default vcodec from config.
    SrsCodecVideo default_vcodec = SrsCodecVideoAVC;
    if (true) {
        std::string default_vcodec_str = _srs_config->get_hls_vcodec(req->vhost);
        if (default_vcodec_str == "h264") {
            default_vcodec = SrsCodecVideoAVC;
            srs_info("hls: use default h264 vcodec");
        } else if (default_vcodec_str == "vn") {
            default_vcodec = SrsCodecVideoDisabled;
            srs_info("hls: use default vn vcodec for pure audio");
        } else {
            srs_warn("hls: use h264 for other codec=%s", default_vcodec_str.c_str());
        }
    }
    
    // new segment.
    current = new SrsHlsSegment(context, should_write_cache, should_write_file, default_acodec, default_vcodec);
    LB_ADD_MEM(current, sizeof(SrsHlsSegment));
    current->sequence_no = _sequence_no++;
    current->segment_start_dts = segment_start_dts;
    current->max_ts_dur = max_td * 90000 * 2;
    // generate filename.
    std::string ts_file = hls_ts_file;
    ts_file = srs_path_build_stream(ts_file, req->vhost, req->app, req->stream, req->datetime, req->appkey, req->userid, req->devicesn);
    //srs_trace("ts_file:%s, req->userid:%s, segment_start_dts:%"PRId64"", ts_file.c_str(), req->userid.c_str(), segment_start_dts);
    if (hls_ts_floor) {
        // accept the floor ts for the first piece.
        int64_t current_floor_ts = (int64_t)(srs_update_system_time_ms() / (1000 * hls_fragment));
        if (!accept_floor_ts) {
            accept_floor_ts = current_floor_ts - 1;
        } else {
            accept_floor_ts++;
        }
        
        // jump when deviation more than 10p
        if (accept_floor_ts - current_floor_ts > SRS_JUMP_WHEN_PIECE_DEVIATION) {
            srs_warn("hls: jmp for ts deviation, current=%"PRId64", accept=%"PRId64, current_floor_ts, accept_floor_ts);
            accept_floor_ts = current_floor_ts - 1;
        }
        
        // when reap ts, adjust the deviation.
        deviation_ts = (int)(accept_floor_ts - current_floor_ts);
        
        // dup/jmp detect for ts in floor mode.
        if (previous_floor_ts && previous_floor_ts != current_floor_ts - 1) {
            srs_warn("hls: dup/jmp ts, previous=%"PRId64", current=%"PRId64", accept=%"PRId64", deviation=%d",
                     previous_floor_ts, current_floor_ts, accept_floor_ts, deviation_ts);
        }
        previous_floor_ts = current_floor_ts;
        
        // we always ensure the piece is increase one by one.
        std::stringstream ts_floor;
        ts_floor << accept_floor_ts;
        ts_file = srs_string_replace(ts_file, "[timestamp]", ts_floor.str());
        
        // TODO: FIMXE: we must use the accept ts floor time to generate the hour variable.
        ts_file = srs_path_build_timestamp(ts_file);
    } else {
        ts_file = srs_path_build_timestamp(ts_file);
    }

    if (true) {
        std::stringstream ss;
        ss << current->sequence_no;
        ts_file = srs_string_replace(ts_file, "[seq]", ss.str());
    }
    current->full_path = hls_path + "/" + ts_file;
    srs_info("hls: generate ts path %s, tmpl=%s, floor=%d", ts_file.c_str(), hls_ts_file.c_str(), hls_ts_floor);
    
    // the ts url, relative or absolute url.
    std::string ts_url = current->full_path;
    if (srs_string_starts_with(ts_url, m3u8_dir)) {
        ts_url = ts_url.substr(m3u8_dir.length());
    }
    while (srs_string_starts_with(ts_url, "/")) {
        ts_url = ts_url.substr(1);
    }
    current->uri += hls_entry_prefix;
    if (!hls_entry_prefix.empty() && !srs_string_ends_with(hls_entry_prefix, "/")) {
        current->uri += "/";
        
        // add the http dir to uri.
        string http_dir = srs_path_dirname(m3u8_url);
        if (!http_dir.empty()) {
            current->uri += http_dir + "/";
        }
    }
    current->uri += ts_url;
    
    // create dir recursively for hls.
    std::string ts_dir = srs_path_dirname(current->full_path);
    if (should_write_file && (ret = srs_create_dir_recursively(ts_dir)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "create app dir %s failed. ret=%d", ts_dir.c_str(), ret);
        return ret;
    }
    srs_info("create ts dir %s ok", ts_dir.c_str());
    
    // open temp ts file.
    std::string tmp_file = current->full_path + ".tmp";
    if ((ret = current->muxer->open(tmp_file.c_str())) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "open hls muxer failed. ret=%d", ret);
        return ret;
    }
#ifdef TS_SLICE_WRITE_REDIS
    //on_segment_open(tmp_file);
#endif
    srs_info("open HLS muxer success. path=%s, tmp=%s",
        current->full_path.c_str(), tmp_file.c_str());

    // set the segment muxer audio codec.
    // TODO: FIXME: refine code, use event instead.
    if (acodec != SrsCodecAudioReserved1) {
        current->muxer->update_acodec(acodec);
    }
    
    return ret;
}

int SrsHlsMuxer::on_sequence_header()
{
    int ret = ERROR_SUCCESS;
    
    srs_assert(current);
    
    // set the current segment to sequence header,
    // when close the segement, it will write a discontinuity to m3u8 file.
    current->is_sequence_header = true;
    
    return ret;
}

bool SrsHlsMuxer::is_segment_overflow()
{
    srs_assert(current);
    
    // to prevent very small segment.
    if (current->duration * 1000 < 2 * SRS_AUTO_HLS_SEGMENT_MIN_DURATION_MS) {
        return false;
    }
    
    // use N% deviation, to smoother.
    double deviation = hls_ts_floor? SRS_HLS_FLOOR_REAP_PERCENT * deviation_ts * hls_fragment : 0.0;
    srs_info("hls: dur=%.2f, tar=%.2f, dev=%.2fms/%dp, frag=%.2f",
        current->duration, hls_fragment + deviation, deviation, deviation_ts, hls_fragment);
    
    return current->duration >= hls_fragment + deviation;
}

bool SrsHlsMuxer::wait_keyframe()
{
    return hls_wait_keyframe;
}

bool SrsHlsMuxer::is_segment_absolutely_overflow()
{
    // @see https://github.com/ossrs/srs/issues/151#issuecomment-83553950
    srs_assert(current);
    
    // to prevent very small segment.
    if (current->duration * 1000 < 2 * SRS_AUTO_HLS_SEGMENT_MIN_DURATION_MS) {
        return false;
    }
    
    // use N% deviation, to smoother.
    double deviation = hls_ts_floor? SRS_HLS_FLOOR_REAP_PERCENT * deviation_ts * hls_fragment : 0.0;
    srs_info("hls: dur=%.2f, tar=%.2f, dev=%.2fms/%dp, frag=%.2f",
             current->duration, hls_fragment + deviation, deviation, deviation_ts, hls_fragment);
    
    return current->duration >= hls_aof_ratio * hls_fragment + deviation;
}

int SrsHlsMuxer::update_acodec(SrsCodecAudio ac)
{
    srs_assert(current);
    srs_assert(current->muxer);
    acodec = ac;
    return current->muxer->update_acodec(ac);
}

int SrsHlsMuxer::update_vcodec(SrsCodecVideo vc)
{
    srs_assert(current);
    srs_assert(current->muxer);
    vcodec = vc;
    //srs_rtsp_debug("update_vcodec(vc:%d)\n", vc);
    return current->muxer->update_vcodec(vc);
}

SrsCodecAudio SrsHlsMuxer::current_acodec()
{
    srs_assert(current);
    srs_assert(current->muxer);
    return current->muxer->current_acodec();
}

SrsCodecVideo SrsHlsMuxer::current_vcodec()
{
    srs_assert(current);
    srs_assert(current->muxer);
    return current->muxer->current_vcodec();
}

bool SrsHlsMuxer::pure_audio()
{
    return current && current->muxer && current->muxer->video_codec() == SrsCodecVideoDisabled;
}

int SrsHlsMuxer::flush_audio(SrsTsCache* cache)
{
    int ret = ERROR_SUCCESS;

    // if current is NULL, segment is not open, ignore the flush event.
    if (!current) {
        srs_warn("flush audio ignored, for segment is not open.");
        return ret;
    }
    
    if (!cache->audio || cache->audio->payload->length() <= 0) {
        return ret;
    }
    
    // update the duration of segment.
    ret = current->update_duration(cache->audio->pts);
    if(ret != ERROR_SUCCESS)
    {
        srs_warn("audio pts:%"PRId64" abnormal, drop audio frame!", cache->audio->pts);
        return ERROR_SUCCESS;
    }
    if ((ret = current->muxer->write_audio(cache->audio)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // write success, clear and free the msg
    srs_freep(cache->audio);

    return ret;
}

int SrsHlsMuxer::flush_video(SrsTsCache* cache)
{
    int ret = ERROR_SUCCESS;

    // if current is NULL, segment is not open, ignore the flush event.
    if (!current) {
        srs_warn("flush video ignored, for segment is not open.");
        return ret;
    }
    
    if (!cache->video || cache->video->payload->length() <= 0) {
        return ret;
    }
    
    srs_assert(current);
    
    // update the duration of segment.
    current->update_duration(cache->video->dts);
    
    if ((ret = current->muxer->write_video(cache->video)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // write success, clear and free the msg
    srs_freep(cache->video);
    
    return ret;
}

int SrsHlsMuxer::segment_close(string log_desc, bool bunpublish)
{
    int ret = ERROR_SUCCESS;
    //srs_trace("log_desc:%s, bunpublish:%d", log_desc.c_str(), (int)bunpublish);
    if (!current) {
        srs_warn("ignore the segment close, for segment is not open.");
        return ret;
    }
    // when close current segment, the current segment must not be NULL.
    srs_assert(current);

    std::string full_path = current->full_path;
    std::string tmp_file = full_path + ".tmp";
    std::string sval;
    on_update_config(req);
#ifdef TS_SLICE_WRITE_REDIS
    /*if(predishandle)
    {
#ifdef ENABLE_REDIS_HASH_TABLE
        ret = predishandle->delKey(tmp_file);
        srs_trace("ret:%d = predishandle->delKey(tmp_file:%s)", ret, tmp_file.c_str());
#else
        //srs_trace("before  predishandle->getValue(tmp_file, datetime)");
        int rdres = predishandle->getValue(tmp_file, sval);
        srs_trace("rdres:%d = predishandle->getValue(tmp_file:%s, sval:%s)", rdres, tmp_file.c_str(), sval.c_str());
        if(rdres != ERROR_SUCCESS)
        {
            srs_error("rdres:%d = predishandle->getValue(tmp_file.c_str():%s, sval:%s) failed", rdres, tmp_file.c_str(), sval.c_str());
        }
        rdres = predishandle->delKey(tmp_file);
        srs_trace("rdres:%d = predishandle->delKey(tmp_file:%s)", rdres, tmp_file.c_str());
        if(rdres < 0)
        {
            srs_error("rdres:%d = predishandle->delKey(tmp_file:%s) failed", rdres, tmp_file.c_str());
        }
#endif
    }
    */
#endif
    // assert segment duplicate.
    std::vector<SrsHlsSegment*>::iterator it;
    it = std::find(segments.begin(), segments.end(), current);
    srs_assert(it == segments.end());

    // valid, add to segments if segment duration is ok
    // when too small, it maybe not enough data to play.
    // when too large, it maybe timestamp corrupt.
    // make the segment more acceptable, when in [min, max_td * 2], it's ok.
    //if (current->duration * 1000 >= SRS_AUTO_HLS_SEGMENT_MIN_DURATION_MS && (int)current->duration <= max_td * 2)
    if (current->duration * 1000 >= SRS_AUTO_HLS_SEGMENT_MIN_DURATION_MS)
    {
        if(current->duration > max_td * 2)
        {
            srs_error("current->duration:%d > max_td:%d * 2, duration exceed max fragment duration\n", current->duration, max_td);
        }
        segments.push_back(current);
        
        // use async to call the http hooks, for it will cause thread switch.
        SrsDvrAsyncCallOnHls* pdacoh = new SrsDvrAsyncCallOnHls(
            _srs_context->get_id(), req,
            current->full_path, current->uri, m3u8, m3u8_url,
            current->sequence_no, current->duration);
        LB_ADD_MEM(pdacoh, sizeof(SrsDvrAsyncCallOnHls));
        if ((ret = async->execute(pdacoh/*new SrsDvrAsyncCallOnHls(
            _srs_context->get_id(), req,
            current->full_path, current->uri, m3u8, m3u8_url,
            current->sequence_no, current->duration)*/)) != ERROR_SUCCESS)
        {
            tag_error(get_device_sn(req, 0), "ret:%d = async->execute(new SrsDvrAsyncCallOnHls failed", ret);
            return ret;
        }
        
        // use async to call the http hooks, for it will cause thread switch.
        SrsDvrAsyncCallOnHlsNotify* pdacohn = new SrsDvrAsyncCallOnHlsNotify(_srs_context->get_id(), req, current->uri);
        LB_ADD_MEM(pdacohn, sizeof(SrsDvrAsyncCallOnHlsNotify));
        if ((ret = async->execute(pdacohn/*new SrsDvrAsyncCallOnHlsNotify(_srs_context->get_id(), req, current->uri)*/)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(req, 0), "ret:%d = async->execute(new SrsDvrAsyncCallOnHlsNotify failed", ret);
            return ret;
        }
    
        srs_info("%s reap ts segment, sequence_no=%d, uri=%s, duration=%.2f, start=%"PRId64,
            log_desc.c_str(), current->sequence_no, current->uri.c_str(), current->duration, 
            current->segment_start_dts);
    
        // close the muxer of finished segment.
        srs_freep(current->muxer);
        //std::string full_path = current->full_path;
        current = NULL;
        
        // rename from tmp to real path
        //std::string tmp_file = full_path + ".tmp";
        if (should_write_file && rename(tmp_file.c_str(), full_path.c_str()) < 0) {
            ret = ERROR_HLS_WRITE_FAILED;
            tag_error(get_device_sn(req, 0), "rename ts file failed, %s => %s. ret=%d", 
                tmp_file.c_str(), full_path.c_str(), ret);
            return ret;
        }
        srs_trace("rename tmp file to %s\n", full_path.c_str());
    } else {
        // reuse current segment index.
        _sequence_no--;
        
        srs_trace("%s drop ts segment, sequence_no=%d, uri=%s, duration=%.2f, start=%"PRId64"",
            log_desc.c_str(), current->sequence_no, current->uri.c_str(), current->duration, 
            current->segment_start_dts);
        
        // rename from tmp to real path
        std::string tmp_file = current->full_path + ".tmp";
        if (should_write_file) {
            if (unlink(tmp_file.c_str()) < 0) {
                srs_warn("ignore unlink path failed, file=%s.", tmp_file.c_str());
            }
        }
        
        srs_freep(current);
// add by dawson for ts record write redis
/*#ifdef TS_SLICE_WRITE_REDIS
        srs_trace("remove tmp_file");
        if(predishandle)
        {
            ret = predishandle->delKey(tmp_file);
            srs_trace("ret:%d = predishandle->delKey(tmp_file:%s)", ret, tmp_file.c_str());
            if(ret != ERROR_SUCCESS)
            {
                srs_error("ret:%d = predishandle->delKey(tmp_file:%s) failed", ret, tmp_file.c_str());
            }
        }
        srs_trace("after remove");
#endif*/
// add end
    }

    // the segments to remove
    std::vector<SrsHlsSegment*> segment_to_remove;
    
    // shrink the segments.
    double duration = 0;
    int remove_index = -1;
    for (int i = (int)segments.size() - 1; i >= 0; i--) {
        SrsHlsSegment* segment = segments[i];
        duration += segment->duration;
        
        if ((int)duration > hls_window) {
            remove_index = i;
            break;
        }
    }
    for (int i = 0; i < remove_index && !segments.empty(); i++) {
        SrsHlsSegment* segment = *segments.begin();
        segments.erase(segments.begin());
        segment_to_remove.push_back(segment);
    }
    //srs_trace("before on_segment_close");
#ifdef TS_SLICE_WRITE_REDIS
    //on_segment_close(full_path, sval);
#endif
    // refresh the m3u8, donot contains the removed ts
    ret = refresh_m3u8(bunpublish);
    //srs_trace("after refresh_m3u8");
    // remove the ts file.
    for (int i = 0; i < (int)segment_to_remove.size(); i++) {
        SrsHlsSegment* segment = segment_to_remove[i];
        
        if (hls_cleanup && should_write_file) {
            if (unlink(segment->full_path.c_str()) < 0) {
                srs_warn("cleanup unlink path failed, file=%s.", segment->full_path.c_str());
            }
        }
        
        srs_freep(segment);
    }
    segment_to_remove.clear();
    
    // check ret of refresh m3u8
    if (ret != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "refresh m3u8 failed. ret=%d", ret);
        return ret;
    }
    
    return ret;
}

int SrsHlsMuxer::update_request(SrsRequest* preq)
{
    if(preq)
    {
        srs_freep(req);
        req = preq->copy();
        srs_debug("SrsHlsMuxer::update_request, req:%p->tigger_type:%d\n", req, req->eipc_tigger_type);
        return 0;
    }

    return -1;
}

int SrsHlsMuxer::refresh_m3u8(bool beof)
{
    int ret = ERROR_SUCCESS;
    //srs_trace(" end of stream %d", (int)beof);
    // no segments, also no m3u8, return.
    if (segments.size() == 0) {
        return ret;
    }
    
    std::string temp_m3u8 = m3u8 + ".temp";
    if ((ret = _refresh_m3u8(temp_m3u8, beof)) == ERROR_SUCCESS) {
        if (should_write_file && rename(temp_m3u8.c_str(), m3u8.c_str()) < 0) {
            ret = ERROR_HLS_WRITE_FAILED;
            tag_error(get_device_sn(req, 0), "rename m3u8 file failed. %s => %s, ret=%d", temp_m3u8.c_str(), m3u8.c_str(), ret);
        }
    }
    // add by dawson for remove empty m3u8 file
    bm3u8_generate = true;
    // add end
    // remove the temp file.
    if (srs_path_exists(temp_m3u8)) {
        if (unlink(temp_m3u8.c_str()) < 0) {
            srs_warn("ignore remove m3u8 failed, %s", temp_m3u8.c_str());
        }
    }
    
    return ret;
}

int SrsHlsMuxer::_refresh_m3u8(string m3u8_file, bool beof)
{
    int ret = ERROR_SUCCESS;
    //srs_trace("m3u8 url:%s, beof:%d", m3u8_file.c_str(), beof);
    // no segments, return.
    if (segments.size() == 0) {
        return ret;
    }

    SrsHlsCacheWriter writer(should_write_cache, should_write_file);
    if ((ret = writer.open(m3u8_file)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "open m3u8 file %s failed. ret=%d", m3u8_file.c_str(), ret);
        return ret;
    }
    srs_info("open m3u8 file %s success.", m3u8_file.c_str());
    
    // #EXTM3U\n
    // #EXT-X-VERSION:3\n
    // #EXT-X-ALLOW-CACHE:YES\n
    std::stringstream ss;
    ss << "#EXTM3U" << SRS_CONSTS_LF
        << "#EXT-X-VERSION:3" << SRS_CONSTS_LF
        << "#EXT-X-ALLOW-CACHE:YES" << SRS_CONSTS_LF;
    srs_verbose("write m3u8 header success.");
    
    // #EXT-X-MEDIA-SEQUENCE:4294967295\n
    SrsHlsSegment* first = *segments.begin();
    ss << "#EXT-X-MEDIA-SEQUENCE:" << first->sequence_no << SRS_CONSTS_LF;
    srs_verbose("write m3u8 sequence success.");
    
    // iterator shared for td generation and segemnts wrote.
    std::vector<SrsHlsSegment*>::iterator it;
    
    // #EXT-X-TARGETDURATION:4294967295\n
    /**
    * @see hls-m3u8-draft-pantos-http-live-streaming-12.pdf, page 25
    * The Media Playlist file MUST contain an EXT-X-TARGETDURATION tag.
    * Its value MUST be equal to or greater than the EXTINF duration of any
    * media segment that appears or will appear in the Playlist file,
    * rounded to the nearest integer. Its value MUST NOT change. A
    * typical target duration is 10 seconds.
    */
    // @see https://github.com/ossrs/srs/issues/304#issuecomment-74000081
    int target_duration = 0;
    for (it = segments.begin(); it != segments.end(); ++it) {
        SrsHlsSegment* segment = *it;
        target_duration = srs_max(target_duration, (int)ceil(segment->duration));
    }
    target_duration = srs_max(target_duration, max_td);
    
    ss << "#EXT-X-TARGETDURATION:" << target_duration << SRS_CONSTS_LF;
    srs_verbose("write m3u8 duration success.");
    
    // write all segments
    for (it = segments.begin(); it != segments.end(); ++it) {
        SrsHlsSegment* segment = *it;
        
        if (segment->is_sequence_header) {
            // #EXT-X-DISCONTINUITY\n
            ss << "#EXT-X-DISCONTINUITY" << SRS_CONSTS_LF;
            srs_verbose("write m3u8 segment discontinuity success.");
        }
        
        // "#EXTINF:4294967295.208,\n"
        ss.precision(3);
        ss.setf(std::ios::fixed, std::ios::floatfield);
        ss << "#EXTINF:" << segment->duration << ", no desc" << SRS_CONSTS_LF;
        srs_verbose("write m3u8 segment info success.");
        
        // {file name}\n
        ss << segment->uri << SRS_CONSTS_LF;
        srs_verbose("write m3u8 segment uri success.");
    }

    // add by dawson for generate m3u8 file
    if(beof)
    {
        ss << "#EXT-X-ENDLIST";
        //srs_trace("add #EXT-X-ENDLIST");
    }
    // add end

    // write m3u8 to writer.
    std::string m3u8 = ss.str();
    //srs_trace("m3u8:%s", m3u8.c_str());
    if ((ret = writer.write((char*)m3u8.c_str(), (int)m3u8.length(), NULL)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "write m3u8 failed. ret=%d", ret);
        return ret;
    }
    srs_info("write m3u8 %s success.", m3u8_file.c_str());
    
    return ret;
}

SrsHlsCache::SrsHlsCache()
{
    cache = new SrsTsCache();
    LB_ADD_MEM(cache, sizeof(SrsTsCache));
}

SrsHlsCache::~SrsHlsCache()
{
    srs_freep(cache);
}

int SrsHlsCache::on_publish(SrsHlsMuxer* muxer, SrsRequest* req, int64_t segment_start_dts)
{
    int ret = ERROR_SUCCESS;

    std::string vhost = req->vhost;
    std::string stream = req->stream;
    std::string app = req->app;
    
    double hls_fragment = _srs_config->get_hls_fragment(vhost);
    double hls_window = _srs_config->get_hls_window(vhost);
    
    // get the hls m3u8 ts list entry prefix config
    std::string entry_prefix = _srs_config->get_hls_entry_prefix(vhost);
    // get the hls path config
    std::string path = _srs_config->get_hls_path(vhost);
    std::string m3u8_file = _srs_config->get_hls_m3u8_file(vhost);
    std::string ts_file = _srs_config->get_hls_ts_file(vhost);
    bool cleanup = _srs_config->get_hls_cleanup(vhost);
    bool wait_keyframe = _srs_config->get_hls_wait_keyframe(vhost);
    // the audio overflow, for pure audio to reap segment.
    double hls_aof_ratio = _srs_config->get_hls_aof_ratio(vhost);
    // whether use floor(timestamp/hls_fragment) for variable timestamp
    bool ts_floor = _srs_config->get_hls_ts_floor(vhost);
    // the seconds to dispose the hls.
    //int hls_dispose = _srs_config->get_hls_dispose(vhost);
    
    // TODO: FIXME: support load exists m3u8, to continue publish stream.
    // for the HLS donot requires the EXT-X-MEDIA-SEQUENCE be monotonically increase.
    
    // open muxer
    if ((ret = muxer->update_config(req, entry_prefix,
        path, m3u8_file, ts_file, hls_fragment, hls_window, ts_floor, hls_aof_ratio,
        cleanup, wait_keyframe)) != ERROR_SUCCESS
    ) {
        tag_error(get_device_sn(req, 0), "m3u8 muxer update config failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = muxer->segment_open(segment_start_dts)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(req, 0), "m3u8 muxer open segment failed. ret=%d", ret);
        return ret;
    }
    /*srs_trace("hls: win=%.2f, frag=%.2f, prefix=%s, path=%s, m3u8=%s, ts=%s, aof=%.2f, floor=%d, clean=%d, waitk=%d, dispose=%d",
        hls_window, hls_fragment, entry_prefix.c_str(), path.c_str(), m3u8_file.c_str(),
        ts_file.c_str(), hls_aof_ratio, ts_floor, cleanup, wait_keyframe, hls_dispose);*/
    
    return ret;
}

int SrsHlsCache::on_unpublish(SrsHlsMuxer* muxer)
{
    int ret = ERROR_SUCCESS;
    
    if ((ret = muxer->flush_audio(cache)) != ERROR_SUCCESS) {
        srs_error("m3u8 muxer flush audio failed. ret=%d", ret);
        return ret;
    }
    
    if ((ret = muxer->segment_close("unpublish", true)) != ERROR_SUCCESS) {
        return ret;
    }
    
    return ret;
}

int SrsHlsCache::on_sequence_header(SrsHlsMuxer* muxer)
{
    // TODO: support discontinuity for the same stream
    // currently we reap and insert discontinity when encoder republish,
    // but actually, event when stream is not republish, the 
    // sequence header may change, for example,
    // ffmpeg ingest a external rtmp stream and push to srs,
    // when the sequence header changed, the stream is not republish.
    return muxer->on_sequence_header();
}

int SrsHlsCache::write_audio(SrsAvcAacCodec* codec, SrsHlsMuxer* muxer, int64_t pts, SrsCodecSample* sample)
{
    int ret = ERROR_SUCCESS;
    
    // write audio to cache.
    if ((ret = cache->cache_audio(codec, pts, sample)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // reap when current source is pure audio.
    // it maybe changed when stream info changed,
    // for example, pure audio when start, audio/video when publishing,
    // pure audio again for audio disabled.
    // so we reap event when the audio incoming when segment overflow.
    // @see https://github.com/ossrs/srs/issues/151
    // we use absolutely overflow of segment to make jwplayer/ffplay happy
    // @see https://github.com/ossrs/srs/issues/151#issuecomment-71155184
    if (cache->audio && muxer->is_segment_absolutely_overflow()) {
        srs_trace("hls: absolute audio reap segment.");
        if ((ret = reap_segment("audio", muxer, cache->audio->pts)) != ERROR_SUCCESS) {
            return ret;
        }
    }
    
    // for pure audio, aggregate some frame to one.
    if (muxer->pure_audio() && cache->audio) {
        if (pts - cache->audio->start_pts < SRS_CONSTS_HLS_PURE_AUDIO_AGGREGATE) {
            return ret;
        }
    }
    
    // directly write the audio frame by frame to ts,
    // it's ok for the hls overload, or maybe cause the audio corrupt,
    // which introduced by aggregate the audios to a big one.
    // @see https://github.com/ossrs/srs/issues/512
    if ((ret = muxer->flush_audio(cache)) != ERROR_SUCCESS) {
        return ret;
    }
    
    return ret;
}
    
int SrsHlsCache::write_video(SrsAvcAacCodec* codec, SrsHlsMuxer* muxer, int64_t dts, SrsCodecSample* sample)
{
    int ret = ERROR_SUCCESS;
    
    // write video to cache.
    if ((ret = cache->cache_video(codec, dts, sample)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // when segment overflow, reap if possible.
    if (muxer->is_segment_overflow()) {
        // do reap ts if any of:
        //      a. wait keyframe and got keyframe.
        //      b. always reap when not wait keyframe.
        if (!muxer->wait_keyframe() || sample->frame_type == SrsCodecVideoAVCFrameKeyFrame) {
            // reap the segment, which will also flush the video.
            if ((ret = reap_segment("video", muxer, cache->video->dts)) != ERROR_SUCCESS) {
                return ret;
            }
        }
    }
    
    // flush video when got one
    if ((ret = muxer->flush_video(cache)) != ERROR_SUCCESS) {
        srs_error("m3u8 muxer flush video failed. ret=%d", ret);
        return ret;
    }
    
    return ret;
}

int SrsHlsCache::reap_segment(string log_desc, SrsHlsMuxer* muxer, int64_t segment_start_dts)
{
    int ret = ERROR_SUCCESS;
    
    // TODO: flush audio before or after segment?
    // TODO: fresh segment begin with audio or video?

    // close current ts.
    if ((ret = muxer->segment_close(log_desc)) != ERROR_SUCCESS) {
        srs_error("m3u8 muxer close segment failed. ret=%d", ret);
        return ret;
    }
    
    // open new ts.
    if ((ret = muxer->segment_open(segment_start_dts)) != ERROR_SUCCESS) {
        srs_error("m3u8 muxer open segment failed. ret=%d", ret);
        return ret;
    }
    
    // segment open, flush video first.
    if ((ret = muxer->flush_video(cache)) != ERROR_SUCCESS) {
        srs_error("m3u8 muxer flush video failed. ret=%d", ret);
        return ret;
    }
    
    // segment open, flush the audio.
    // @see: ngx_rtmp_hls_open_fragment
    /* start fragment with audio to make iPhone happy */
    if ((ret = muxer->flush_audio(cache)) != ERROR_SUCCESS) {
        srs_error("m3u8 muxer flush audio failed. ret=%d", ret);
        return ret;
    }
    
    return ret;
}

SrsHls::SrsHls()
{
    _req = NULL;
    source = NULL;
    
    hls_enabled = false;
    hls_can_dispose = false;
    last_update_time = 0;

    codec = new SrsAvcAacCodec();
    LB_ADD_MEM(codec, sizeof(SrsAvcAacCodec));
    sample = new SrsCodecSample();
    LB_ADD_MEM(sample, sizeof(SrsCodecSample));
    jitter = new SrsRtmpJitter();
    LB_ADD_MEM(jitter, sizeof(SrsRtmpJitter));
    muxer = new SrsHlsMuxer();
    LB_ADD_MEM(muxer, sizeof(SrsHlsMuxer));
    hls_cache = new SrsHlsCache();
    LB_ADD_MEM(hls_cache, sizeof(SrsHlsCache));
    pprint = SrsPithyPrint::create_hls();
    stream_dts = 0;
}

SrsHls::~SrsHls()
{
    srs_freep(_req);
    srs_freep(codec);
    srs_freep(sample);
    srs_freep(jitter);
    
    srs_freep(muxer);
    srs_freep(hls_cache);
    
    srs_freep(pprint);
}

void SrsHls::dispose()
{
    if (hls_enabled) {
        on_unpublish();
    }
    
    // Ignore when hls_dispose disabled.
    // @see https://github.com/ossrs/srs/issues/865
    int hls_dispose = _srs_config->get_hls_dispose(_req->vhost);
    if (!hls_dispose) {
        return;
    }
    
    muxer->dispose();
}

int SrsHls::cycle()
{
    int ret = ERROR_SUCCESS;
    
    //srs_info("hls cycle for source %d", source->source_id());
    
    if (last_update_time <= 0) {
        last_update_time = srs_get_system_time_ms();
    }
    
    if (!_req) {
        return ret;
    }
    
    int hls_dispose = _srs_config->get_hls_dispose(_req->vhost) * 1000;
    if (hls_dispose <= 0) {
        return ret;
    }
    if (srs_get_system_time_ms() - last_update_time <= hls_dispose) {
        return ret;
    }
    last_update_time = srs_get_system_time_ms();
    
    if (!hls_can_dispose) {
        return ret;
    }
    hls_can_dispose = false;
    
    //srs_info("hls cycle to dispose hls %s, timeout=%dms", _req->get_stream_url().c_str(), hls_dispose);
    dispose();
    
    return ret;
}

int SrsHls::initialize(SrsSource* s, SrsRequest* r)
{
    int ret = ERROR_SUCCESS;

    srs_assert(!_req);
    _req = r->copy();
    codec->set_device_sn(_req->devicesn);
    source = s;
    //srs_rtsp_debug("userid:%s, devicesn:%s", _req->userid.c_str(), _req->devicesn.c_str());
    if ((ret = muxer->initialize()) != ERROR_SUCCESS) {
        return ret;
    }

    return ret;
}

int SrsHls::on_publish(SrsRequest* req, bool fetch_sequence_header)
{
    //srs_trace("hls publish begin\n");
    int ret = ERROR_SUCCESS;
    
    // update the hls time, for hls_dispose.
    last_update_time = srs_get_system_time_ms();
    
    // support multiple publish.
    if (hls_enabled) {
        return ret;
    }
    
    std::string vhost = req->vhost;
    //srs_trace("tigger_type:%d", req->eipc_tigger_type);
    if (!_srs_config->get_hls_enabled(vhost) || !check_tigger_type(req)) {
        //srs_trace("disable hls publish!");
        return ret;
    }
    
    if ((ret = hls_cache->on_publish(muxer, req, stream_dts)) != ERROR_SUCCESS) {
        return ret;
    }
    
    // if enabled, open the muxer.
    hls_enabled = true;
    
    // ok, the hls can be dispose, or need to be dispose.
    hls_can_dispose = true;
    
    // when publish, don't need to fetch sequence header, which is old and maybe corrupt.
    // when reload, we must fetch the sequence header from source cache.
    if (fetch_sequence_header) {
        // notice the source to get the cached sequence header.
        // when reload to start hls, hls will never get the sequence header in stream,
        // use the SrsSource.on_hls_start to push the sequence header to HLS.
        if ((ret = source->on_hls_start()) != ERROR_SUCCESS) {
            tag_error(get_device_sn(_req, 0), "callback source hls start failed. ret=%d", ret);
            return ret;
        }
    }

    return ret;
}

void SrsHls::on_unpublish()
{
    int ret = ERROR_SUCCESS;
    
    // support multiple unpublish.
    if (!hls_enabled) {
        return;
    }

    if ((ret = hls_cache->on_unpublish(muxer)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(_req, 0), "ignore m3u8 muxer flush/close audio failed. ret=%d", ret);
    }
    
    hls_enabled = false;
}

int SrsHls::on_meta_data(SrsAmf0Object* metadata)
{
    int ret = ERROR_SUCCESS;

    if (!metadata) {
        srs_trace("no metadata persent, hls ignored it.");
        return ret;
    }
    
    if (metadata->count() <= 0) {
        srs_trace("no metadata persent, hls ignored it.");
        return ret;
    }
    
    return ret;
}

int SrsHls::on_audio(SrsSharedPtrMessage* shared_audio)
{
    int ret = ERROR_SUCCESS;
    srs_verbose("%s(shared_audio:%p) begin", __FUNCTION__, shared_audio);
    if (!hls_enabled) {
        return ret;
    }
    
    // update the hls time, for hls_dispose.
    last_update_time = srs_get_system_time_ms();

    SrsSharedPtrMessage* audio = shared_audio->copy();
    SrsAutoFree(SrsSharedPtrMessage, audio);
    
    sample->clear();
    if ((ret = codec->audio_aac_demux(audio->payload, audio->size, sample)) != ERROR_SUCCESS) {
        if (ret != ERROR_HLS_TRY_MP3) {
            tag_error(get_device_sn(_req, 0), "hls aac demux audio failed. ret=%d", ret);
            return ret;
        }
        if ((ret = codec->audio_mp3_demux(audio->payload, audio->size, sample)) != ERROR_SUCCESS) {
            tag_error(get_device_sn(_req, 0), "hls mp3 demux audio failed. ret=%d", ret);
            return ret;
        }
    }
    srs_verbose("%s audio decoded, type=%d, codec=%d, cts=%d, size=%d, time=%"PRId64, __FUNCTION__,
        sample->frame_type, codec->audio_codec_id, sample->cts, audio->size, audio->timestamp);
    SrsCodecAudio acodec = (SrsCodecAudio)codec->audio_codec_id;
    
    // ts support audio codec: aac/mp3
    if (acodec != SrsCodecAudioAAC && acodec != SrsCodecAudioMP3) {
        return ret;
    }

    // when codec changed, write new header.
    if ((ret = muxer->update_acodec(acodec)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(_req, 0), "http: ts audio write header failed. ret=%d", ret);
        return ret;
    }
    
    // ignore sequence header
    if (acodec == SrsCodecAudioAAC && sample->aac_packet_type == SrsCodecAudioTypeSequenceHeader) {
        return hls_cache->on_sequence_header(muxer);
    }
    
    // TODO: FIXME: config the jitter of HLS.
    if ((ret = jitter->correct(audio, SrsRtmpJitterAlgorithmOFF)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(_req, 0), "rtmp jitter correct audio failed. ret=%d", ret);
        return ret;
    }
    
    // the dts calc from rtmp/flv header.
    int64_t dts = audio->timestamp * 90;
    
    // for pure audio, we need to update the stream dts also.
    stream_dts = dts;
    // add by dawson for audio write test
#ifdef ENABLE_WRITE_AUDIO_STREAM
    static FILE* pfile = fopen("./objs/nginx/html/ahls.aac", "wb");
    srs_verbose("%s pfile:%p = fopen(ahls.aac, wb)", __FUNCTION__, pfile);
    if(pfile && sample)
    {
        for(int i = 0; i < sample->nb_sample_units; i++)
        {
            if(sample->sample_units[i].size && sample->sample_units[i].bytes)
            {
                fwrite(sample->sample_units[i].bytes, 1, sample->sample_units[i].size, pfile);
                srs_verbose("%s fwrite(sample->sample_units[i].bytes:%p, 1, sample->sample_units[i].size:%d, pfile:%p)", __FUNCTION__, sample->sample_units[i].bytes, sample->sample_units[i].size, pfile);
            }
        }
    }
#endif
    // add end
    if ((ret = hls_cache->write_audio(codec, muxer, dts, sample)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(_req, 0), "hls cache write audio failed. ret=%d", ret);
        return ret;
    }
    srs_verbose("%s end, ret:%d", __FUNCTION__, ret);
    return ret;
}

int SrsHls::on_video(SrsSharedPtrMessage* shared_video, bool is_sps_pps)
{
    int ret = ERROR_SUCCESS;
    srs_verbose("%s(shared_video:%p, is_sps_pps:%d) begin", __FUNCTION__, shared_video, (int)is_sps_pps);
    if (!hls_enabled) {
        return ret;
    }
    //srs_trace("on_video(shared_video:%p, is_sps_pps:%d\n", shared_video, (int)is_sps_pps);
    // update the hls time, for hls_dispose.
    last_update_time = srs_get_system_time_ms();

    SrsSharedPtrMessage* video = shared_video->copy();
    SrsAutoFree(SrsSharedPtrMessage, video);
    
    // user can disable the sps parse to workaround when parse sps failed.
    // @see https://github.com/ossrs/srs/issues/474
    if (is_sps_pps) {
        codec->avc_parse_sps = _srs_config->get_parse_sps(_req->vhost);
    }
    
    sample->clear();
    if ((ret = codec->video_avc_demux(video->payload, video->size, sample)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(_req, 0), "hls codec demux video failed. ret=%d", ret);
        return ret;
    }
    //srs_rtsp_debug("codec->video_codec_id:%d != muxer->current_vcodec():%d, codec:%p, avc_extra_data:%p, avc_extra_size:%d\n", codec->video_codec_id, muxer->current_vcodec(), codec, codec->avc_extra_data, codec->avc_extra_size);
    // add by dawson
    if(codec->video_codec_id != muxer->current_vcodec())
    {
        srs_info("hls muxer update video codec id from %d to %d\n", muxer->current_vcodec(), codec->video_codec_id);
        muxer->update_vcodec((SrsCodecVideo)codec->video_codec_id);
    }
 
    // add end
    srs_info("video decoded, type=%d, codec=%d, avc=%d, cts=%d, size=%d, time=%"PRId64, 
        sample->frame_type, codec->video_codec_id, sample->avc_packet_type, sample->cts, video->size, video->timestamp);
    
    // ignore info frame,
    // @see https://github.com/ossrs/srs/issues/288#issuecomment-69863909
    if (sample->frame_type == SrsCodecVideoAVCFrameVideoInfoFrame) {
        return ret;
    }
    
    if (codec->video_codec_id != SrsCodecVideoAVC && SrsCodecVideoHEVC != codec->video_codec_id) {
        return ret;
    }
    //srs_trace("%s video decoded, type:%d, codec=%d, avc=%d, cts=%d, size=%d,time=%"PRId64, __FUNCTION__, sample->frame_type, codec->video_codec_id, sample->avc_packet_type, sample->cts, video->size, video->timestamp);
    // ignore sequence header
    if (sample->frame_type == SrsCodecVideoAVCFrameKeyFrame
         && sample->avc_packet_type == SrsCodecVideoAVCTypeSequenceHeader) {
        return hls_cache->on_sequence_header(muxer);
    }
    
    // TODO: FIXME: config the jitter of HLS.
    if ((ret = jitter->correct(video, SrsRtmpJitterAlgorithmOFF)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(_req, 0), "rtmp jitter correct video failed. ret=%d", ret);
        return ret;
    }

    int64_t dts = video->timestamp * 90;
    stream_dts = dts;
    if ((ret = hls_cache->write_video(codec, muxer, dts, sample)) != ERROR_SUCCESS) {
        tag_error(get_device_sn(_req, 0), "hls cache write video failed. ret=%d", ret);
        return ret;
    }
    
    // pithy print message.
    hls_show_mux_log();
    srs_verbose("%s end, ret:%d", __FUNCTION__, ret);
    return ret;
}

int SrsHls::update_request(SrsRequest* preq)
{
    if(preq)
    {
        srs_debug("update request, _req:%p->tigger_type:%d, update appkey:%s, old appkey:%s\n", _req, _req->eipc_tigger_type, preq->appkey.c_str(), _req->appkey.c_str());
        srs_freep(_req);
        _req = preq->copy();
        //srs_debug("update request, _req:%p->tigger_type:%d, update appkey:%s, old appkey:%s\n", _req, _req->eipc_tigger_type, preq->appkey.c_str());
        if(muxer)
        {
            return muxer->update_request(preq);
        }

        return 0;
    }

    return -1;
}
void SrsHls::hls_show_mux_log()
{
    pprint->elapse();

    // reportable
    if (pprint->can_print()) {
        // the run time is not equals to stream time,
        // @see: https://github.com/ossrs/srs/issues/81#issuecomment-48100994
        // it's ok.
        srs_info("-> "SRS_CONSTS_LOG_HLS" time=%"PRId64", stream dts=%"PRId64"(%"PRId64"ms), sno=%d, ts=%s, dur=%.2f, dva=%dp",
            pprint->age(), stream_dts, stream_dts / 90, muxer->sequence_no(), muxer->ts_url().c_str(),
            muxer->duration(), muxer->deviation());
    }
}

 bool SrsHls::check_tigger_type(SrsRequest* req)
 {
    SrsConfDirective* pconf = _srs_config->get_vhost_config("ipc_tigger_type", req->vhost.c_str(), "hls");
    //srs_trace("pconf:%p = _srs_config->get_vhost_config(ipc_tigger_type, req->vhost.c_str():%s, hls)", pconf, req->vhost.c_str());
    if(pconf)
    {
        vector<string> vtigtypelist = pconf->args;
        for(unsigned int i = 0; i < vtigtypelist.size(); i++)
        {
            int tigtype = ::atoi(vtigtypelist[i].c_str());
            if(tigtype == req->eipc_tigger_type)
            {
                //srs_trace("tigtype:%d == req->eipc_tigger_type:%d, enable write hls", tigtype, req->eipc_tigger_type);
                return true;
            }
        }
        //srs_trace("req->eipc_tigger_type:%d not in tigger type list", req->eipc_tigger_type);
        return false;
    }
    
    return true;
 }

// add by dawson for ts record write redis
#ifdef TS_SLICE_WRITE_REDIS

std::string SrsHlsMuxer::get_time()
{
        char Year[6] = {0};
        char Month[4] = {0};
        char Day[4] = {0};
        char Hour[4] = {0};
        char Min[4] = {0};
        char Sec[4] = {0};
        char cur_time[256] = {0};
        time_t current_time;
        struct tm* now_time;
        time(&current_time);
        now_time = localtime(&current_time);

        strftime(Year, sizeof(Year), "%Y", now_time);
        strftime(Month, sizeof(Month), "%m", now_time);
        strftime(Day, sizeof(Day), "%d-", now_time);
        strftime(Hour, sizeof(Hour), "%H", now_time);
        strftime(Min, sizeof(Min), "%M", now_time);
        strftime(Sec, sizeof(Sec), "%S", now_time);

        strcat(cur_time, Year);
        strcat(cur_time, Month);
        strcat(cur_time, Day);
        strcat(cur_time, Hour);
        strcat(cur_time, Min);
        strcat(cur_time, Sec);

        return std::string(cur_time);
}
/*
cout<< SRS_JOBJECT_START
            << SRS_JFIELD_STR("name", "srs") << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("version", 100) << SRS_JFIELD_CONT
            << SRS_JFIELD_NAME("features") << SRS_JOBJECT_START
                << SRS_JFIELD_STR("rtmp", "released") << SRS_JFIELD_CONT
                << SRS_JFIELD_STR("hls", "released") << SRS_JFIELD_CONT
                << SRS_JFIELD_STR("dash", "plan")
            << SRS_JOBJECT_END << SRS_JFIELD_CONT
            << SRS_JFIELD_STR("author", "srs team")
        << SRS_JOBJECT_END*/
/*int SrsHlsMuxer::on_segment_open(const std::string& skey)
{
#ifdef ENABLE_REDIS_HASH_TABLE
    if(predishandle)
    {
        map<string, string>     hashmap;
        srs_info("req->app:%s, req->stream:%s, req->llstart_timestamp:%"PRId64", req->timezone:%d, skey:%s", req->app.c_str(), req->stream.c_str(), req->llstart_timestamp, req->timezone,  skey.c_str());
        hashmap[HASH_RTMP_APP_FIELD]            = req->app;
        hashmap[HASH_RTMP_STREAM_FIELD]         = req->stream;
        hashmap[HASH_RECORD_START_TIME_FIELD]   = long_to_string((long)req->llstart_timestamp);
        hashmap[HASH_TIME_ZONE_FIELD]           = long_to_string((long)req->timezone);
        //hashmap[HASH_RTMP_TIGGER_TYPE]        = long_to_string((long)req->bstart_alert);
        //string key = req->app + ":" + req->stream + ":" + req->llstart_timestamp + ".ts"
        int ret = predishandle->setMultiHashValue(skey, hashmap);
        if(ERROR_SUCCESS != ret)
        {
            tag_error(get_device_sn(req, 0), "ret:%d = predishandle->setMultiHashValue(skey:%s, hashmap)", ret, skey.c_str());
            return ret;
        }
        map<string, string>     hashmaplist;
        hashmaplist[HASH_RTMP_APP_FIELD]            = string();
        hashmaplist[HASH_RTMP_STREAM_FIELD]         = string();
        hashmaplist[HASH_RECORD_START_TIME_FIELD]   = string();
        hashmaplist[HASH_TIME_ZONE_FIELD]           = string();
        ret = predishandle->GetMultiHashValue(skey, hashmaplist);
        for(map<string, string>::iterator it = hashmaplist.begin(); it != hashmaplist.end(); it++)
        {
            srs_trace("get field, it->first:%s, it->second:%s", it->first.c_str(), it->second.c_str());
        }
        return ERROR_SUCCESS;
    }
#else
    srs_trace("(skey:%s)", skey.c_str());
    std:string sjsonval, sval;
    std::stringstream jsonst;
    jsonst << SRS_JOBJECT_START << SRS_JFIELD_ORG("alert", (int)req->bstart_alert) << SRS_JFIELD_CONT << SRS_JFIELD_ORG("push_ts", req->llstart_timestamp) << SRS_JFIELD_CONT <<
    SRS_JFIELD_STR("app", req->app) << SRS_JFIELD_CONT << SRS_JFIELD_STR("stream", req->stream) << SRS_JFIELD_CONT << SRS_JFIELD_STR("server_ts", req->datetime) << SRS_JOBJECT_END;
    //sjsonval = jsonst.str();
    //sval = "{ \"alert\":" + req->bstart_alert ? "true":"false" + ", \"push_ts\":" + std::to_string(req->llstart_timestamp) + ", \"app\":\"" + req->app + "\", \"stream\":\"" + req->stream + "\", \"server_ts\":\"" + req->datetime + "\" }";
    //srs_trace("sjsonval:%s\n sval:%s", sjsonval.c_str(), sval.c_str());
    //print_json(sjsonval);
    //print_json(sval);
    
    if(predishandle)
    {
        srs_trace("predishandle->setValue(skey:%s, sjsonval:%s)", skey.c_str(), sjsonval.c_str());
        int ret = predishandle->setValue(skey, sjsonval);
        if(ret != ERROR_SUCCESS)
        {
            tag_error(get_device_sn(_req, 0), "ret:%d = predishandle->setValue(skey:%s, sjsonval:%s) failed", ret, skey.c_str(), sjsonval.c_str());
            return ret;
        }
    }
    if(skey.empty())
    {
        return ERROR_INVALID_REDIS_KEY;
    }
    srs_trace("end");
#endif
    return 0;
}

int SrsHlsMuxer::on_segment_close(const std::string& skey, const std::string& sval)
{
    srs_trace("(skey:%s \n sval:%s)", skey.c_str(), sval.c_str());
    if(predishandle)
    {
#ifdef ENABLE_REDIS_HASH_TABLE
        srs_trace("redis hash table begin");
        string key = req->app + ":" + req->stream + ":" + get_file_name(skey);
        map<string, string> hashmap;
        hashmap[HASH_RTMP_APP_FIELD]            = req->app;
        hashmap[HASH_RTMP_STREAM_FIELD]         = req->stream;
        hashmap[HASH_RECORD_START_TIME_FIELD]   = long_to_string((long)req->llstop_timestamp);
        hashmap[HASH_TIME_ZONE_FIELD]           = long_to_string((long)req->timezone);
        //hashmap[HASH_RTMP_TIGGER_TYPE_FIELD]    = long_to_string((long)req->bstart_alert);
        //predishandle->reconnect();
        int rdres = predishandle->setMultiHashValue(key, hashmap);
        if(rdres != ERROR_SUCCESS)
        {
            predishandle->reconnect();
            rdres = predishandle->setMultiHashValue(key, hashmap);
        }
        //srs_trace("rdres:%d = predishandle->setMultiHashValue(key:%s, hashmap), req->app:%s, req->stream:%s, req->llstop_timestamp:%"PRId64" req->timezone:%d", rdres, key.c_str(), req->app.c_str(), req->stream.c_str(), req->llstop_timestamp, req->timezone);
        return rdres;
#else
        //print_json(sval);
        int rdres = predishandle->setValue(skey, sval);
        srs_trace("rdres:%d = predishandle->setValue(skey.c_str():%s, sval:%s)", rdres, skey.c_str(), sval.c_str());
        if(rdres != ERROR_SUCCESS)
        {
            tag_error(get_device_sn(req, 0), "rdres:%d = predishandle->setValue(skey.c_str():%s, sval:%s) failed", rdres, skey.c_str(), sval.c_str());
        }
        srs_trace("after redis operator, rdres:%d", rdres);
#endif
    }

    return 0;
}*/

void SrsHlsMuxer::print_json(const std::string& sjsonval)
{
    //srs_trace("parser json:%s", sjsonval.c_str());
    int ret = ERROR_SUCCESS;
    SrsJsonAny* info = SrsJsonAny::loads((char*)sjsonval.c_str());
    if (!info) {
        //ret = ERROR_JSON_STRING_PARSER_FAIL;
        srs_error("invalid response info:%p. ret=%d", info, ret);
        return ;
    }
    SrsAutoFree(SrsJsonAny, info);
    
    // response error code in string.
    if (!info->is_object()) {
        /*if (ret != ERROR_SUCCESS) {
            srs_error("invalid response number, info:%p", info);
            return ;
        }*/
        srs_error("invalid object !info->is_object()");
        return ;
    }
    
    // response standard object, format in json: {"code": 0, "data": ""}
    SrsJsonObject* res_info = info->to_object();
    SrsJsonAny* res_code = NULL;
    if ((res_code = res_info->ensure_property_integer("alert")) == NULL) {
        srs_error("invalid response while parser alert without code");
        return ;
    }
    int64_t llalert = res_code->to_integer();
    srs_trace("llalert:%d = res_code->to_integer()", (int)llalert);
    int64_t llpushpts = 0;
    if ((res_code = res_info->ensure_property_integer("push_ts")) == NULL) {
        srs_error("invalid response while parser push_ts without code");
        return ;
    }
   
    llpushpts = res_code->to_integer();
    srs_trace("llpushpts:%"PRId64" = res_code->to_integer()", llpushpts);
    if ((res_code = res_info->ensure_property_string("app")) == NULL) {
        srs_error("invalid response while parser app without code");
        return ;
    }
    string app = res_code->to_str();
    srs_trace("app:%s = res_code->to_str()", app.c_str());
    if ((res_code = res_info->ensure_property_string("stream")) == NULL) {
        srs_error("invalid response while parser stream without code");
        return ;
    }
    string stream = res_code->to_str();
    srs_trace("stream:%s = res_code->to_str()", stream.c_str());
    if ((res_code = res_info->ensure_property_string("server_ts")) == NULL) {
        srs_error("invalid response while parser server_ts without code");
        return ;
    }
    string server_ts = res_code->to_str();
    srs_trace("balert:%"PRId64", llpushpts:%"PRId64", app:%s, stream:%s, server_ts:%s", llalert, llpushpts, app.c_str(), stream.c_str(), server_ts.c_str());
}

int SrsHlsMuxer::on_update_config(SrsRequest* preq)
{
    //srs_trace("redis hash table begin");
    int ret = 0;
    string key = preq->appkey + ":";
    
    if(!preq->userid.empty())
    {
        key = key + preq->userid + ":";
    }
    key = key + preq->devicesn + ":" + preq->datetime + ".ts";
    //srs_trace("key:%s\n", key.c_str());
    map<string, string> hashmap;
    hashmap[HASH_RTMP_APP_FIELD]            = preq->app;
    hashmap[HASH_RTMP_STREAM_FIELD]         = preq->stream;
    hashmap[HASH_RTMP_TIGGER_TYPE_FIELD]    = long_to_string((long)preq->eipc_tigger_type);
    hashmap[HASH_RECORD_START_TIME_FIELD]   = long_to_string((long)preq->llstart_timestamp);
    hashmap[HASH_TIME_ZONE_FIELD]           = long_to_string((long)preq->timezone);
    hashmap[HASH_RTMP_SEGMENT_ALARM_TIME]   = double_to_string((double)preq->dalarm_time, 3);
    hashmap[HASH_RTMP_SEGMENT_DURATION]     = double_to_string((double)preq->duration, 3);
    hashmap[HASH_RTMP_SEGMENT_IMG_TIMESTAMP] = double_to_string((double)preq->dmajorImgTimestamp, 3);
    //srs_trace("key:%s, tigger_type:%d, timezone:%d, alarmtime:%lf, duration:%lf, imgTimestamp:%lf", key.c_str(), preq->eipc_tigger_type, preq->timezone, preq->dalarm_time, preq->duration, preq->dmajorImgTimestamp);
#if 0
    if(NULL == predishandle)
    {
        predishandle = CSrsRedisHandler::get_inst();
    }

    if(predishandle && preq)
    {
        int rdres = predishandle->setMultiHashValue(key, hashmap);
        if(rdres != ERROR_SUCCESS)
        {
            predishandle->reconnect();
            rdres = predishandle->setMultiHashValue(key, hashmap);
        }

        //int rdres = predishandle->setMultiHashValue(key, hashmap);
        //srs_trace("rdres:%d = predishandle->setMultiHashValue(key:%s, hashmap)", rdres, key.c_str());
        return ret;
    }
#else
    if(NULL == m_pdb_conn_mgr)
    {
        m_pdb_conn_mgr = database_connection_manager::get_inst();
        m_pdb_conn_mgr->connect_database_from_config(HLS_RECORD_DB_CONF, preq->vhost.c_str(), "database");
        //srs_rtsp_debug("m_pdb_conn_mgr->connect_database_from_config(HLS_RECORD_DB_CONF, preq->vhost.c_str(), database)", preq->vhost.c_str());
    }
    if(m_pdb_conn_mgr && m_pdb_conn_mgr->exist_database(HLS_RECORD_DB_CONF))
    {
        string cmd = "hmset " + key;
        for(map<string, string>::const_iterator it = hashmap.begin(); it != hashmap.end(); it++)
        {
            cmd += " " + it->first + " " + it->second;
            //srs_trace("cmd:%s", cmd.c_str());
        }
        //srs_trace("key:%s\n cmd:%s\n", key.c_str(), cmd.c_str());
        ret = m_pdb_conn_mgr->exe_command(HLS_RECORD_DB_CONF, cmd);
        srs_trace("ret:%d = m_pdb_conn_mgr->exe_command(HLS_RECORD_DB_CONF, cmd:%s)\n", ret, cmd.c_str());
    }
#endif
    return -1;
}
#endif
// add end
#endif


