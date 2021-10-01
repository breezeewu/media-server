#include <srs_http_stack.hpp>
#include <srs_app_source.hpp>
#include <srs_protocol_json.hpp>
#include <srs_app_http_api.hpp>
#include <srs_core_autofree.hpp>
#include <string>
//#ifdef SRS_AUTO_FORWARD_WEBRTC
#define STREAMING_MEDIA_HTTP_ERROR_CODE_BASE                12216000
#define HTTP_CONTROL_ERROR_CODE_DEIVCE_OFFLINE              STREAMING_MEDIA_HTTP_ERROR_CODE_BASE + 1
#define HTTP_CONTROL_ERROR_SEND_METADATA_FAIL               STREAMING_MEDIA_HTTP_ERROR_CODE_BASE + 2
class SunHttpHandle:public ISrsHttpHandler
{
public:
    SunHttpHandle()
    {
        srs_trace("SunHttpHandle construct");
    }
    ~SunHttpHandle()
    {

    }

    virtual int serve_http(ISrsHttpResponseWriter* w, ISrsHttpMessage* r)
    {
        int ret = 0;
        std::string http_path = r->path();
        srs_trace("w:%p, r:%p, http_path:%s", w, r, http_path.c_str());
        if("/api/sun/control/device/query" == http_path)
        {
            ret = query_connection_info(w, r);
        }
        else if("/api/sun/control/device/live" == http_path)
        {
            ret = notify_device_live_show(w, r);
        }
        else
        {
            srs_error("Invalid http path:%s", http_path.c_str());
        }
        return ret;
    }

protected:
    int query_connection_info(ISrsHttpResponseWriter* w, ISrsHttpMessage* r)
    {
        std::string body;
        int ret = r->body_read_all(body);
        if(ret != ERROR_SUCCESS)
        {
            srs_error("query connection info read body failed! body:%s\n", body.c_str());
            return ret;
        }
        srs_trace("load body:%s", body.c_str());
        SrsJsonAny* info = SrsJsonAny::loads((char*)body.c_str());
        if (!info) {
            ret = ERROR_JSON_STRING_PARSER_FAIL;
            srs_error("invalid webrtc server request info:%p. ret=%d", body.c_str(), ret);
            return ret;
        }
        SrsAutoFree(SrsJsonAny, info);
    
        // response error code in string.
        if (!info->is_object()) {
            srs_error("invalid object !info->is_object()");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
    
        // response standard object, format in json: {"code": 0, "data": ""}
        SrsJsonObject* res_info = info->to_object();
    #if 1
        std::string deviceid;
        ret = res_info->get_string_value("deviceID", deviceid);
        if(ERROR_SUCCESS != ret)
        {
            srs_error("ret:%d = res_info->get_string_value(deviceID, deviceid:%s) failed", ret, deviceid.c_str());
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
    #else
        SrsJsonAny* res_code = NULL;
        if ((res_code = res_info->ensure_property_string("deviceID")) == NULL) {
            srs_error("invalid response while parser stateCode failed");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        if(!res_code->is_string())
        {
            srs_error("Invalid deviceID format, not string!");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        std::string deviceID = res_code->to_str();
#endif
        srs_trace("deviceid:%s", deviceid.c_str());
        /*if(deviceID.empty())
        {
            srs_error("Invalid webrtc device request, empty deviceid\n");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }*/
        std::stringstream ss;
        SrsRequest* preq = SrsSource::query_device_info(deviceid);
        if(preq)
        {
            
            ss << SRS_JFIELD_ERROR(200) << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("appName", preq->app) << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("streamName", preq->stream) << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("deviceID", preq->devicesn) << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("message", "online") << SRS_JFIELD_CONT;
        }
        else
        {
            // device offline
            ss << SRS_JFIELD_ERROR(HTTP_CONTROL_ERROR_CODE_DEIVCE_OFFLINE) << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("message", "offline") << SRS_JFIELD_CONT;
        }

        srs_trace("http response:%s", ss.str().c_str());
        return srs_api_response(w, r, ss.str());
    }

    int notify_device_live_show(ISrsHttpResponseWriter* w, ISrsHttpMessage* r)
    {
        std::string body;
        int ret = r->body_read_all(body);
        if(ret != ERROR_SUCCESS)
        {
            srs_error("query connection info read body failed! body:%s\n", body.c_str());
            return ret;
        }
        srs_trace("load body:%s", body.c_str());
        SrsJsonAny* info = SrsJsonAny::loads((char*)body.c_str());
        if (!info) {
            ret = ERROR_JSON_STRING_PARSER_FAIL;
            srs_error("invalid webrtc server request info:%p. ret=%d", body.c_str(), ret);
            return ret;
        }
        SrsAutoFree(SrsJsonAny, info);
        srs_trace("info:%p", info);
        // response error code in string.
        if (!info->is_object()) {
            srs_error("invalid object !info->is_object()");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        
        // response standard object, format in json: {"code": 0, "data": ""}
        SrsJsonObject* res_info = info->to_object();
        srs_trace("res_info:%p", res_info);
        if(!res_info)
        {
            srs_error("invalid request, parser body object error\n");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
#if 1
        std::string deviceID;
        std::string token;
        int tigger_type = -1;
        int opflag = -1;
        ret = res_info->get_string_value("deviceID", deviceID);
        if(ERROR_SUCCESS != ret)
        {
            srs_error("ret:%d = res_info->get_string_value(deviceID, deviceid:%s) failed", ret, deviceID.c_str());
            return ERROR_JSON_STRING_PARSER_FAIL;
        }

        ret = res_info->get_string_value("token", token);
        if(ERROR_SUCCESS != ret)
        {
            srs_error("ret:%d = res_info->get_string_value(token, token:%s) failed", ret, token.c_str());
            return ERROR_JSON_STRING_PARSER_FAIL;
        }

        ret = res_info->get_int_value("tigger_type", tigger_type);
        if(ERROR_SUCCESS != ret)
        {
            srs_error("ret:%d = res_info->get_int_value(tigger_type, tigger_type:%d) failed", ret, tigger_type);
            return ERROR_JSON_STRING_PARSER_FAIL;
        }

        ret = res_info->get_int_value("operator_flag", opflag);
        if(ERROR_SUCCESS != ret)
        {
            srs_error("ret:%d = res_info->get_int_value(operator_flag, opflag:%d) failed", ret, opflag);
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
#else
        SrsJsonAny* res_code = NULL;
        if ((res_code = res_info->ensure_property_string("deviceID")) == NULL) {
            srs_error("invalid request while parser deviceID failed");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        if(!res_code->is_string())
        {
            srs_error("Invalid deviceID format, not string!");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
    
        std::string deviceID = res_code->to_str();

        // parser token
        if ((res_code = res_info->ensure_property_string("token")) == NULL) {
            srs_error("invalid request while parser token failed");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        
        if(!res_code->is_string())
        {
            srs_error("Invalid token format, not string!");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }

        std::string token = res_code->to_str();
        if(!res_code->is_integer())
        {
            srs_error("Invalid tigger_type format, not integer!");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        // parser token
        if ((res_code = res_info->ensure_property_integer("tigger_type")) == NULL) {
            srs_error("invalid request while parser tigger_type failed");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }

        if(!res_code->is_integer())
        {
            srs_error("Invalid tigger_type format, not integer!");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        //std::string token = res_code->to_str();
        int tigger_type = res_code->to_integer();
        // parser enalbe flag
        if ((res_code = res_info->ensure_property_integer("operator_flag")) == NULL) {
            srs_error("invalid request while parser operator_flag failed");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }

        if(!res_code->is_integer())
        {
            srs_error("Invalid operator_flag format, not integer!");
            return ERROR_JSON_STRING_PARSER_FAIL;
        }
        int opflag = res_code->to_integer();
#endif
        srs_trace("control device: deviceID:%s, token:%s, tigger_type:%d, opflag:%d", deviceID.c_str(), token.c_str(), tigger_type, opflag);
        // check token
        // check token end
        std::string message;
        std::stringstream ss;
        SrsSource* psource = SrsSource::find_srssource_by_deviceid(deviceID);
        srs_trace("psource:%p = SrsSource::find_srssource_by_deviceid(deviceID:%s)\n", psource, deviceID.c_str());
        if(psource)
        {
            ret = psource->notify_live_show(deviceID, tigger_type, opflag);
        }
        else
        {
            ret = -1;
            message = "device offline";
        }

        if(ERROR_SUCCESS == ret)
        {
            ss << SRS_JFIELD_ERROR(200) << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("deviceID", deviceID) << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("message", "OK") << SRS_JFIELD_CONT;
        }
        else if(!message.empty())
        {
            ss << SRS_JFIELD_ERROR(HTTP_CONTROL_ERROR_SEND_METADATA_FAIL) << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("deviceID", deviceID) << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("message", message) << SRS_JFIELD_CONT;
        }
        else
        {
            ss << SRS_JFIELD_ERROR(HTTP_CONTROL_ERROR_SEND_METADATA_FAIL) << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("deviceID", deviceID) << SRS_JFIELD_CONT
            << SRS_JFIELD_ORG("message", "Send metadata failed") << SRS_JFIELD_CONT;
        }
        srs_trace("http response:%s", ss.str().c_str());
        return srs_api_response(w, r, ss.str());
    }
};
//#endif