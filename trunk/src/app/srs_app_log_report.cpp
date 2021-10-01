#include <srs_app_log_report.hpp>
#include <lbsp_database_redis.hpp>
//#include <lbsc_database_mysql.hpp>
//#include <srs_app_mysql_db.hpp>
#include <srs_core.hpp>
#include <srs_kernel_log.hpp>
#include <srs_kernel_error.hpp>
#include <srs_app_config.hpp>
#include <string>
#include <cstring>
#include <iostream>
SrsLogReport* SrsLogReport::m_plog_report(NULL);

#define MYSQL_SERVER_DEFAULT_PORT           3306
#define REDIS_SERVER_DEFAULT_PORT           6379
#define DATABASE_DEFAULT_IP                 "127.0.0.1"
#define DATABASE_REDIS_TYPE                 0
#define DATABASE_MYSQL_TYPE                 1
SrsLogReport::SrsLogReport()
{
    m_nmax_count            = 1000;
    m_pidb                  = NULL;
    m_benable_log_report    = false;
    m_ndatabase_type        = 0;
    m_ndb_server_port       = 0;
    m_ndb_index             = 0;
    m_nexpire_time          = 0;
    m_brunning              = 0;
#ifndef SRS_LOG_REPORT_WITH_LAZY_THREAD
    m_pst_thread            = NULL;
#endif
}

SrsLogReport::~SrsLogReport()
{
    if(m_plog_report)
    {
#ifndef SRS_LOG_REPORT_WITH_LAZY_THREAD
        if(m_pst_thread)
        {
            m_pst_thread->stop();
        }
        srs_freep(m_pst_thread);
#endif
        //delete m_plog_report;
        //m_plog_report = NULL;
    }
}

SrsLogReport* SrsLogReport::get_inst()
{
    if(NULL == m_plog_report)
    {
        m_plog_report = new SrsLogReport();
        LB_ADD_MEM(m_plog_report, sizeof(SrsLogReport));
        m_plog_report->load_log_report_config();
        /*if(m_plog_report->m_benable_log_report)
        {
            m_plog_report->start();
        }*/
    }
    return m_plog_report;
}


void SrsLogReport::destroy_inst()
{
    if(m_plog_report)
    {
        srs_freep(m_plog_report);
    }
}

int SrsLogReport::start()
{
#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
    return Run();
#else
    if(m_benable_log_report)
    {
        if(NULL == m_pst_thread)
        {
            m_pst_thread = new internal::SrsThread("log report", this, 0, true);
            LB_ADD_MEM(m_pst_thread, sizeof(internal::SrsThread));
        }

        return m_pst_thread->start();
    }
    else
    {
        return ERROR_SUCCESS;
    }

#endif
}

void SrsLogReport::stop()
{
#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
    return Stop();
#else
    if(m_pst_thread)
    {
        m_brunning = 0;
        m_pst_thread->stop();
        srs_freep(m_pst_thread);
    }

    while(m_vinfo_list.size() > 0)
    {
        srs_log_report_info* pri = m_vinfo_list.front();
        m_vinfo_list.pop();
        srs_freep(pri);
    }
    //m_vinfo_list.clear();
#endif
}

#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
THREAD_RETURN SrsLogReport::ThreadProc()
{
    if(!m_benable_log_report)
    {
        srs_trace("log report has been disable in config file\n");
        return NULL;
    }
    srs_trace("SrsLogReport::ThreadProc begin, m_ndatabase_type:%d\n", m_ndatabase_type);
    int ret = 0;
    if(DATABASE_MYSQL_TYPE == m_ndatabase_type)
    {
        m_pidb = new CRedisDB();
        LB_ADD_MEM(m_pidb, sizeof(CRedisDB));
        //connect(const char* ip, int port, const char* pwd, int idx)
        ret = m_pidb->connect(m_sdb_server_ip.c_str(), m_ndb_server_port, m_sdb_pwd.c_str(), m_ndb_index);
        srs_trace("ret:%d = redis db connect(m_sdb_server_ip.c_str():%s, m_ndb_server_port:%d, m_sdb_pwd.c_str():%s, m_ndb_index:%d)\n", ret, m_sdb_server_ip.c_str(), m_ndb_server_port, m_sdb_pwd.c_str(), m_ndb_index);
    }
    else
    {
        m_pidb = new CMySqlDB();
        LB_ADD_MEM(m_pidb, sizeof(CMySqlDB));
        //int connect(const char* ip, int port, const char* username, const char* pwd, const char* pdbname)
        ret = m_pidb->conenct(m_sdb_server_ip.c_str(), m_ndb_server_port, m_suser_name.c_str(), m_sdb_pwd.c_str(), m_sdb_name.c_str());
        srs_trace("ret:%d = mysql db connect(m_sdb_server_ip.c_str():%s, m_ndb_server_port:%d, m_suser_name.c_str():%s, m_sdb_pwd.c_str():%s)\n", ret, m_sdb_server_ip.c_str(), m_ndb_server_port, m_suser_name.c_str().c_str(), m_sdb_pwd.c_str());
    }
    if(ret < 0)
    {
        srs_warn("%s connect failed, ret:%d\n", m_ndatabase_type == 0 ? "redis" : "mysql", ret);
        return NULL;
    }
    while(m_bRun)
    {
        if(get_msg_count() <= 0)
        {
            st_usleep(10000);
            continue;
        }

        report_info* pri = get_msg();
        if(pri)
        {
            
            ret = m_pidb->writedb(pri);
            srs_trace("ret:%d = m_pidb->writedb(pri:%p)\n", ret, pri);
            srs_freep(pri);
            //delete pri;
        }
    }

    srs_trace("SrsLogReport::ThreadProc end\n");
}
#else
void SrsLogReport::on_thread_start()
{
    if(!m_benable_log_report)
    {
        srs_trace("log report has been disable in config file\n");
        return ;
    }
    srs_trace("m_ndatabase_type:%d\n", m_ndatabase_type);
    int ret = 0;
    if(DATABASE_REDIS_TYPE == m_ndatabase_type)
    {
        if(m_pidb)
        {
            m_pidb->close();
            srs_freep(m_pidb);
        }
        m_pidb = new redis_database(m_ndb_index, m_nexpire_time);
        LB_ADD_MEM(m_pidb, sizeof(redis_database));
        //connect(const char* ip, int port, const char* pwd, int idx)
        ret = m_pidb->connect(m_sdb_server_ip.c_str(), m_ndb_server_port, m_sdb_pwd.c_str());
        //srs_trace("ret:%d = redis db connect(m_sdb_server_ip.c_str():%s, m_ndb_server_port:%d, m_sdb_pwd.c_str():%s)\n", ret, m_sdb_server_ip.c_str(), m_ndb_server_port, m_sdb_pwd.c_str());
    }

    if(ret != ERROR_SUCCESS)
    {
        if(m_pidb)
        {
            m_pidb->close();
            srs_freep(m_pidb);
        }
         m_pst_thread->stop_loop();
        srs_warn("%s connect failed, ret:%d\n", m_ndatabase_type == 0 ? "redis" : "mysql", ret);
    }
    srs_trace("log report on_thread_start, ret:%d\n", ret);
}

int SrsLogReport::cycle()
{
    int ret = 0;
    srs_assert(m_benable_log_report);
    if(get_msg_count() <= 0)
    {
        st_usleep(300000);
        return ERROR_SUCCESS;
    }

    m_pidb->start_transaction();

    while(get_msg_count() > 0)
    {
        srs_log_report_info* pri = get_msg();
        //srs_trace("before et = writedb(pri:%p)\n", pri);
        ret = write_vcommand(pri);
        //srs_trace("ret:%d = m_pidb->writedb(pri:%p), get_msg_count():%d\n", ret, pri, get_msg_count());
        //delete pri;
        srs_freep(pri);
    };
    m_pidb->commit_transaction();

    return ret;
}

void SrsLogReport::on_thread_stop()
{
    if(m_pidb)
    {
        m_pidb->close();
        srs_freep(m_pidb);
        //delete m_pidb;
        //m_pidb = NULL;
    }
    m_benable_log_report = false;
    srs_trace("disable log report becase of log report thread stop!\n");
}
#endif
#ifdef NEW_LOG_INFO_RECORD
int SrsLogReport::add_msg(const char* ptimestamp,
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
            )
{
    if(!m_benable_log_report)
    {
        //srs_trace("log report has been disable in config file\n");
        return DATABASE_CODE_SUCCESS;
    }
    if(NULL == ptimestamp)
    {
        lbtrace("ptimestamp:%s, deivcesn, ", ptimestamp);
        return DATABASE_CODE_INVALID_PARAMETEER;
    }
    //srs_trace("ptimestamp:%s, deivcesn, ", ptimestamp);
    //lbtrace("addmsg(ptimestamp:%p, deivcesn:%s, timezone:%d, err_code:%d, perr_msg:%s, preason:%s, phost_name:%s, psrc_file:%s, psrc_func:%s, nsrc_line:%d, plog_name:%s)\n", 
    //ptimestamp, deivcesn, timezone, err_code, perr_msg, preason, phost_name, psrc_file, psrc_func, nsrc_line, plog_name);
    srs_log_report_info* pri = new srs_log_report_info;
    LB_ADD_MEM(pri, sizeof(srs_log_report_info));
    pri->timestamp = report_key_to_string(ptimestamp);
    pri->devicesn = report_key_to_string(deivcesn);
    pri->timezone = report_key_to_string(timezone);
    pri->err_code = report_key_to_string(err_code);
    pri->err_msg = report_key_to_string(perr_msg);
    pri->reason = report_key_to_string(preason);
    pri->hostname = report_key_to_string(phost_name);
    pri->src_file = report_key_to_string(psrc_file);
    pri->src_func = report_key_to_string(psrc_func);
    pri->src_line = report_key_to_string(nsrc_line);
    pri->log_name = report_key_to_string(plog_name);

    m_vinfo_list.push(pri);

    return 0;
}

int SrsLogReport::write_command(srs_log_report_info* pri)
 {
    if(NULL == pri || NULL == m_pidb)
    {
        srs_warn("NULL == pri:%p || NULL == m_pidb:%p\n", pri, m_pidb);
        return -1;
    }
#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
    CAutoLock lock(m_mutex);
#endif
    int ret = 0;
    std::map<std::string, std::string> rilist;
    
    rilist[SRS_LOG_INFO_DEVICE_SN] = pri->devicesn;
    rilist[SRS_LOG_INFO_TIME_ZONE] = pri->timezone;
    rilist[SRS_LOG_INFO_ERROR_CODE] = pri->err_code;
    rilist[SRS_LOG_INFO_ERROR_MSG] = pri->err_msg;
    rilist[SRS_LOG_INFO_ERROR_REASON] = pri->reason;
    rilist[SRS_LOG_INFO_SRS_HOST_NAME] = pri->hostname;
    rilist[SRS_LOG_INFO_SOURCE_FILE] = pri->src_file;
    rilist[SRS_LOG_INFO_SOURCE_FUNC] = pri->src_func;
    rilist[SRS_LOG_INFO_SOURCE_LINE] = pri->src_line;
    rilist[SrS_LOG_INFO_LOG_FILE_NAME] = pri->log_name;
    char* pparam = NULL;
    if(DATABASE_MYSQL_TYPE == m_ndb_index)
    {
        rilist[SRS_LOG_INFO_GMT_TIMESTAMP] = pri->timestamp;
        pparam = (char*)m_sdb_table_name.c_str();
        //ret = m_pidb->insert(rilist, m_sdb_table_name.c_str());
    }
    else if(DATABASE_REDIS_TYPE == m_ndb_index)
    {
        //rilist[SRS_LOG_INFO_GMT_TIMESTAMP] = pri->timestamp;
        //ret = m_pidb->insert(rilist,  pri->timestamp.c_str());
        pparam = (char*)pri->timestamp.c_str();
    }
    ret = m_pidb->insert(rilist, pparam);
    srs_trace("ret:%d = m_pidb->insert(rilist, pparam:%s), m_ndb_index:%d\n", ret, pparam, m_ndb_index);
    return ret;
 }

 int SrsLogReport::write_vcommand(srs_log_report_info* pri)
 {
     int ret = -1;
    if(NULL == pri)
    {
        srs_warn("Invalid parameter, pri:%p\n", pri);
        return DATABASE_CODE_INVALID_PARAMETEER;
    }
    
    if(NULL == m_pidb)
    {
        srs_warn("redis db not connected, m_pidb:%p\n", m_pidb);
        return DATABASE_CODE_DB_NOT_CONNECTED;
    }
    
    ret = m_pidb->vcommand("HMSET %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s", 
    pri->timestamp.c_str(), 
    SRS_LOG_INFO_DEVICE_SN, pri->devicesn.c_str(), 
    SRS_LOG_INFO_TIME_ZONE, pri->timezone.c_str(), 
    SRS_LOG_INFO_ERROR_CODE, pri->err_code.c_str(),
    SRS_LOG_INFO_ERROR_MSG, pri->err_msg.c_str(),
    SRS_LOG_INFO_ERROR_REASON, pri->reason.c_str(),
    SRS_LOG_INFO_SRS_HOST_NAME, pri->hostname.c_str(),
    SRS_LOG_INFO_SOURCE_FILE, pri->src_file.c_str(),
    SRS_LOG_INFO_SOURCE_FUNC, pri->src_func.c_str(),
    SRS_LOG_INFO_SOURCE_LINE, pri->src_line.c_str(),
    SrS_LOG_INFO_LOG_FILE_NAME, pri->log_name.c_str()
    );

    if(DATABASE_CODE_SUCCESS != ret)
    {
        srs_warn("ret:%d = m_pidb->vcommand(HMSET %s) failed!", ret, pri->timestamp.c_str());
        m_pidb->trace_error();
        return ret;
    }

    ret = m_pidb->vcommand("EXPIRE %s %d", pri->timestamp.c_str(), m_nexpire_time);
    if(DATABASE_CODE_SUCCESS != ret)
    {
        srs_warn("ret:%d = m_pidb->vcommand(EXPIRE %s %d) failed!", ret, pri->timestamp.c_str(), m_nexpire_time);
        m_pidb->trace_error();
        return ret;
    }
    return ret;
 }
#else
int SrsLogReport::add_msg(int64_t timestamp,
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
            const char* plog_gmt_time)
{
    srs_trace("(timestamp:%"PRId64", pdev_sn:%s, phost_name:%s, gmt_time:%s, err_code:%d, perr_reason:%s, perr_msg:%s, psrc_file:%s, psrc_func:%s, src_line:%d, plog_file_name:%s, plog_gmt_time:%s)\n", 
    timestamp, pdev_sn, phost_name, gmt_time, err_code, perr_reason, perr_msg,
    psrc_file, psrc_func, src_line, plog_file_name, plog_gmt_time);
#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
    CAutoLock lock(m_mutex);
#endif
    if(m_vinfo_list.size() >= m_nmax_count)
    {
        srs_warn("m_vinfo_list.size():%d >= m_nmax_count:%d, log report failed\n", (int)m_vinfo_list.size(), m_nmax_count);
        return -1;
    }

    report_info* pri = new report_info();
    LB_ADD_MEM(pri, sizeof(report_info));
    if(0 == timestamp)
    {
        pri->timestamp = report_key_to_string(get_time_stamp());
    }
    else
    {
         pri->timestamp = report_key_to_string(timestamp);
    }
    
    pri->device_sn = report_key_to_string(pdev_sn);
    pri->host_name = report_key_to_string(phost_name);
    pri->gmt_time = report_key_to_string(gmt_time);
    pri->error_code = report_key_to_string(err_code);
    pri->time_zone = report_key_to_string(get_time_zone());
    pri->error_reason = report_key_to_string(perr_reason);
    pri->message = report_key_to_string(perr_msg);
    pri->source_file = report_key_to_string(psrc_file);
    pri->source_func = report_key_to_string(psrc_func);
    pri->source_line = report_key_to_string(src_line);
    pri->log_file_name = report_key_to_string(plog_file_name);
    pri->log_gmt_time = report_key_to_string(plog_gmt_time);
    m_vinfo_list.push(pri);
    srs_trace("add_msg end");
    return 0;
}

int SrsLogReport::writedb(srs_log_report_info* pri)
 {
    if(NULL == pri || NULL == m_pidb)
    {
        srs_warn("NULL == pri:%p || NULL == m_pidb:%p\n", pri, m_pidb);
        return -1;
    }
#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
    CAutoLock lock(m_mutex);
#endif
    int ret = 0;
    std::map<std::string, std::string> rilist;
    
    rilist[MYSQL_EI_DEVICE_SN] = pri->device_sn;
    rilist[MYSQL_EI_HOST_NAME] = pri->host_name;

    rilist[MYSQL_EI_TIME_ZONE] = pri->time_zone;
    rilist[MYSQL_EI_ERROR_GMT_TIME] = pri->gmt_time;

    rilist[MYSQL_EI_ERROR_CODE] = pri->error_code;
    rilist[MYSQL_EI_ERROR_REASON] = pri->error_reason;
    rilist[MYSQL_EI_ERROR_MSG] = pri->message;

    rilist[MYSQL_EI_SOURCE_FILE] = pri->source_file;
    rilist[MYSQL_EI_SOURCE_FUNC] = pri->source_func;
    rilist[MYSQL_EI_SOURCE_LINE] = pri->source_line;

    rilist[MYSQL_EI_LOG_FILE_NAME] = pri->log_file_name;
    rilist[MYSQL_EI_LOG_GMT_TIME] = pri->log_gmt_time;
    char* pparam = NULL;
    if(DATABASE_MYSQL_TYPE == m_ndb_index)
    {
        rilist[MYSQL_EI_TIMESTAMP] = pri->timestamp;
        pparam = (char*)m_sdb_table_name.c_str();
        //ret = m_pidb->insert(rilist, m_sdb_table_name.c_str());
    }
    else if(DATABASE_REDIS_TYPE == m_ndb_index)
    {
        rilist[MYSQL_EI_TIMESTAMP] = pri->timestamp;
        //ret = m_pidb->insert(rilist,  pri->timestamp.c_str());
        pparam = (char*)pri->timestamp.c_str();
    }
    ret = m_pidb->insert(rilist, pparam);
    srs_trace("ret:%d = m_pidb->insert(rilist, pparam:%s), m_ndb_index:%d\n", ret, pparam, m_ndb_index);
    return ret;
 }
#endif
srs_log_report_info* SrsLogReport::get_msg()
{
#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
    CAutoLock lock(m_mutex);
#endif
    if(m_vinfo_list.size() > 0)
    {
        srs_log_report_info* pri = m_vinfo_list.front();
        m_vinfo_list.pop();
        return pri;
    }
    return NULL;
}

int SrsLogReport::get_msg_count()
{
#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
    CAutoLock lock(m_mutex);
#endif
    return m_vinfo_list.size();
}

std::string SrsLogReport::report_key_to_string(int value)
{
    std::string strval;
    char strbuf[256] = {0};
    sprintf(strbuf, "%d", value);
    strval = strbuf;

    return strval;
}

std::string SrsLogReport::report_key_to_string(int64_t value)
{
    char strbuf[256] = {0};
    sprintf(strbuf, "%"PRId64"", value);

    return std::string(strbuf);
}

std::string SrsLogReport::report_key_to_string(std::string value)
{
    if(!value.empty())
    {
        return value;//std::string("\"") + value + std::string("\"");
    }
    
    return std::string();
}
std::string SrsLogReport::report_key_to_string(const char* pvalue)
{
    if(pvalue)
    {
        return std::string(pvalue);//std::string("\"") + std::string(pvalue) + std::string("\"");
    }
    
    return std::string();
}
 int SrsLogReport::load_log_report_config()
 {
#ifdef SRS_LOG_REPORT_WITH_LAZY_THREAD
    CAutoLock lock(m_mutex);
#endif
     m_benable_log_report = _srs_config->get_bool_config("enabled", false, SRS_CONSTS_RTMP_DEFAULT_VHOST, "log_report");
     srs_info("load log report config:%d\n", (int)m_benable_log_report);
     if(m_benable_log_report)
     {
        m_ndatabase_type = _srs_config->get_int_config("database_type", 0, SRS_CONSTS_RTMP_DEFAULT_VHOST, "log_report");
        m_sdb_server_ip = _srs_config->get_string_config("database_ip", "127.0.0.1", SRS_CONSTS_RTMP_DEFAULT_VHOST, "log_report");
        m_ndb_server_port   = _srs_config->get_int_config("database_port", 0, SRS_CONSTS_RTMP_DEFAULT_VHOST, "log_report");
        m_sdb_pwd = _srs_config->get_string_config("database_pwd", "", SRS_CONSTS_RTMP_DEFAULT_VHOST, "log_report");
        m_ndb_index = _srs_config->get_int_config("database_index", 0, SRS_CONSTS_RTMP_DEFAULT_VHOST, "log_report");
        m_nexpire_time  = _srs_config->get_int_config("expire_time", 0, SRS_CONSTS_RTMP_DEFAULT_VHOST, "log_report");
        m_suser_name = _srs_config->get_string_config("database_user_name", "root", SRS_CONSTS_RTMP_DEFAULT_VHOST, "log_report");
        m_sdb_name = _srs_config->get_string_config("database_name", "srs_err_info", SRS_CONSTS_RTMP_DEFAULT_VHOST, "log_report");
        m_sdb_table_name = _srs_config->get_string_config("databse_table_name", "err_info", SRS_CONSTS_RTMP_DEFAULT_VHOST, "log_report");
        srs_trace("log report enable, db_type:%d, ip:%s, port:%d, pwd:%s, idx:%d, user_name:%s, dbname:%s, tableName:%s\n", m_ndatabase_type, m_sdb_server_ip.c_str(), m_ndb_server_port, m_sdb_pwd.c_str(), m_ndb_index, m_suser_name.c_str(), m_sdb_name.c_str(), m_sdb_table_name.c_str());
        return 0;
     }
    else
    {
        srs_trace("log report disable!\n");
    }
    
     return -1;
}

 