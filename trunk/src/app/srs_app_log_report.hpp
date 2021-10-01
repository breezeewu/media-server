#ifndef __SRS_APP_LOG_REPORT_H__
#define __SRS_APP_LOG_REPORT_H__

//#include "hiredis\hiredis.h" 
//#include <hiredis/hiredis.h>
#include <string>
#include <map>

#include <queue>
//#define SRS_LOG_REPORT_WITH_LAZY_THREAD
#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
#include "sv_thread.h"
#include "autholock.h"
#else
#include <srs_app_thread.hpp>
#endif

#define NEW_LOG_INFO_RECORD
#ifdef NEW_LOG_INFO_RECORD
#define SRS_LOG_INFO_GMT_TIMESTAMP          "timestamp"
#define SRS_LOG_INFO_DEVICE_SN              "devicesn"
#define SRS_LOG_INFO_TIME_ZONE              "timezone"
#define SRS_LOG_INFO_ERROR_CODE             "err_code"
#define SRS_LOG_INFO_ERROR_MSG              "err_msg"
#define SRS_LOG_INFO_ERROR_REASON            "reason"
#define SRS_LOG_INFO_SRS_HOST_NAME          "host_name"
#define SRS_LOG_INFO_SOURCE_FILE            "src_file"
#define SRS_LOG_INFO_SOURCE_FUNC            "src_func"
#define SRS_LOG_INFO_SOURCE_LINE            "src_line"
#define SrS_LOG_INFO_LOG_FILE_NAME          "log_name"
typedef struct srs_log_report_info
{
    std::string     timestamp;
    std::string     devicesn;
    std::string     timezone;
    std::string     err_code;
    std::string     err_msg;
    std::string     reason;
    std::string     hostname;
    std::string     src_file;
    std::string     src_func;
    std::string     src_line;
    std::string     log_name;
    std::string     user_id;
};
#else
#define MYSQL_EI_ERROR_ID               "error_id"
#define MYSQL_EI_TIMESTAMP              "timestamp"
#define MYSQL_EI_DEVICE_SN              "device_sn"
#define MYSQL_EI_HOST_NAME              "host_name"
#define MYSQL_EI_TIME_ZONE              "time_zone"
#define MYSQL_EI_ERROR_GMT_TIME         "error_gmt_time"
#define MYSQL_EI_ERROR_CODE             "error_code"
#define MYSQL_EI_ERROR_REASON           "error_reason"
#define MYSQL_EI_ERROR_MSG              "error_message"
#define MYSQL_EI_SOURCE_FILE            "source_file"
#define MYSQL_EI_SOURCE_FUNC            "source_func"
#define MYSQL_EI_SOURCE_LINE            "source_line"
#define MYSQL_EI_LOG_FILE_NAME          "log_file_name"
#define MYSQL_EI_LOG_GMT_TIME           "log_gmt_time"
typedef struct srs_log_report_info
{
    std::string     timestamp;
    std::string     device_sn;
    std::string     host_name;
    std::string     time_zone;
    std::string     gmt_time;
    std::string     error_code;
    std::string     error_reason;
    std::string     message;
    std::string     source_file;
    std::string     source_func;
    std::string     source_line;
    std::string     log_file_name;
    std::string     log_gmt_time;
} report_info;
#endif
#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
class SrsLogReport
#else
class SrsLogReport:public internal::ISrsThreadHandler
#endif
{
private:
    SrsLogReport();
public:
    ~SrsLogReport();

    static SrsLogReport* get_inst();

    static void destroy_inst();

    virtual int start();

    virtual void stop();

#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
    virtual THREAD_RETURN ThreadProc();
#else
    virtual void on_thread_start();

    virtual int cycle();

    virtual void on_thread_stop();
#endif
#ifdef NEW_LOG_INFO_RECORD
int add_msg(const char* ptimestamp,
            const char* deivcesn,
            int timezone,
            int err_code,
            const char* preason,
            const char* perr_msg,
            const char* phost_name,
            const char* psrc_file,
            const char* psrc_func,
            int nsrc_line,
            const char* plog_name
            );
#else
    int add_msg(int64_t timestamp,
                const char* pdev_sn, 
                const char* phost_name,
                const char* gmt_time,
                int         err_code, 
                const char* perr_reason,
                const char* perr_msg, 
                const char* psrc_file, 
                const char* psrc_func, 
                int         src_line, 
                const char* plog_file_name, 
                const char* plog_gmt_time);
#endif
    int get_msg_count();

private:

    srs_log_report_info* get_msg();

    std::string report_key_to_string(int value);

    std::string report_key_to_string(int64_t value);

    std::string report_key_to_string(std::string value);
    
    std::string report_key_to_string(const char* pvalue);

    int load_log_report_config();

    int write_command(srs_log_report_info* pri);

    int write_vcommand(srs_log_report_info* pri);

private:
    static SrsLogReport*        m_plog_report;
#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
    CCriSec                     m_mutex;
#endif

    std::queue<srs_log_report_info*>   m_vinfo_list;

    int                         m_nmax_count;

    class idatabase_api*            m_pidb;

    // log report parameter
    bool                        m_benable_log_report;
    int                         m_ndatabase_type;
    std::string                 m_sdb_server_ip;
    std::string                 m_sdb_pwd;
    int                         m_ndb_server_port;
    int                         m_ndb_index;
    int                         m_nexpire_time;
    std::string                 m_suser_name;
    std::string                 m_sdb_name;
    std::string                 m_sdb_table_name;
    bool                        m_brunning;

#ifndef SRS_LOG_REPORT_WITH_LAZY_THREAD
    internal::SrsThread*                  m_pst_thread;
#endif
};

#endif