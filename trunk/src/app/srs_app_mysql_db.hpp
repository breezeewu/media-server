#pragma once
#include "mysql/mysql.h"
#include <stdio.h>
#include <string>
#include <inttypes.h>
#include <sys/time.h>
#include "srs_app_db_api.hpp"
//#include <srs_app_log.hpp>
#define __STDC_FORMAT_MACROS


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

#ifndef srs_trace
#define srs_trace printf
#endif
#ifndef srs_error
#define srs_error printf
#endif


class CMySqlDB:public IDataBase
{
public: 
    CMySqlDB()
    {
        m_pmysql = NULL;
    }

public:
    ~CMySqlDB()
    {

    }

    static CMySqlDB* get_inst()
    {
        return &m_mysql;
    }
    // connect to database
    virtual int connect(const char* ip, int port, const char* username, const char* pwd, const char* pdbname)
    {
        srs_trace("connect(ip:%s, port:%d), m_pmysql:%p\n", ip, port, m_pmysql);
	    close();
        if(NULL == ip)
        {
            m_sip = "127.0.0.1";
        }
        else
        {
            m_sip = ip;
        }

        if(NULL == username || NULL == pdbname)
        {
            srs_error("Invalid parameter, username:%s, dbname:%s\n", username, pdbname);
            return -1;
        }

        m_suser_name = username;
        m_sdb_name = pdbname;

        if(NULL == pwd)
        {
            m_spwd = "";
        }
        else
        {
            m_spwd = pwd;
        }
        m_pmysql = new MYSQL;
        MYSQL* pmysql = mysql_init(m_pmysql);
        srs_trace("pmysql:%p = mysql_init(m_pmysql:%p)\n", pmysql, m_pmysql);
        if(NULL == pmysql)
        {
            dump_error();
            srs_error("pmysql:%p = mysql_init(&m_mysql)", pmysql);
            close();
			return -1;
        }
        pmysql = mysql_real_connect(m_pmysql, m_sip.c_str(), username, pwd, pdbname, port, NULL, 0);
        srs_trace("pmysql:%p = mysql_real_connect(m_pmysql:%p)\n", pmysql, m_pmysql);
        if(NULL == pmysql)
        {
            dump_error();
            srs_error("pmysql:%p = mysql_real_connect(m_pmysql:%p, ip:%s, username:%s, pwd:%s, dbname:%s, port:%d, NULL, 0)\n", pmysql, m_pmysql, m_sip.c_str(), username, pwd, pdbname, port);
            close();
			return -1;
        }
        
        return 0;
    }

    int insert(const char* ptable, 
                const char* pdev_sn, 
                const char* phost_name, 
                int err_code, 
                const char* perr_reason,
                const char* perr_msg, 
                const char* psrc_file, 
                const char* psrc_func, 
                int src_line, 
                const char* plog_file_name, 
                const char* plog_gmt_time)
    {
        char sql_cmd[1024];
        snprintf(sql_cmd, 1024, "INSERT INTO %s(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) VALUE(%"PRId64",\"%s\",\"%s\",%d,\"%s\",%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%d\",\"%s\",\"%s\");",
        //snprintf(sql_cmd, 1024, "INSERT INTO %s('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s') VALUE('%s','%s','%s',%d,'%s','%s','%s',%d,'%s',%d);",
        ptable,
        MYSQL_EI_TIMESTAMP,
        MYSQL_EI_DEVICE_SN,
        MYSQL_EI_HOST_NAME,
        MYSQL_EI_TIME_ZONE,
        MYSQL_EI_ERROR_GMT_TIME,
        MYSQL_EI_ERROR_CODE,
        MYSQL_EI_ERROR_REASON,
        MYSQL_EI_ERROR_MSG,
        MYSQL_EI_SOURCE_FILE,
        MYSQL_EI_SOURCE_FUNC,
        MYSQL_EI_SOURCE_LINE,
        MYSQL_EI_LOG_FILE_NAME,
        MYSQL_EI_LOG_GMT_TIME,
        get_time_stamp(),
        pdev_sn, 
        phost_name,
        get_time_zone(),
        get_gmt_time().c_str(), 
        err_code,
        perr_reason,
        perr_msg, 
        psrc_file, 
        psrc_func, 
        src_line, 
        plog_file_name,
        plog_gmt_time);
        int ret = mysql_query(m_pmysql, sql_cmd);
        srs_trace("ret:%d = mysql_query(m_pmysql:%p, sql_cmd:%s)\n", ret, m_pmysql, sql_cmd);
        if(ret != 0)
        {
            dump_error();
            srs_error("ret:%d = mysql_query(m_pmysql:%p, sql_cmd:%s)\n", ret, m_pmysql, sql_cmd);
        }
        return ret;
    }

    // insert a record to database
    virtual int insert(std::map<std::string, std::string>& vallist, const char* ptable)
    {
        srs_trace("%s(%s)\n", __FUNCTION__, ptable);
        if(NULL == ptable)
        {
            srs_error("Invalid parameter, ptable:%p\n", ptable);
            return -1;
        }

        std::string cmd_fields = "INSERT INTO " + std::string(ptable) + "(";
        std::string cmd_valuses = ") VALUE(";
        std::map<std::string, std::string>::iterator it = vallist.begin();
        for(; it != vallist.end(); it++)
        {
            cmd_fields += it->first + ",";
            cmd_valuses += it->second + ",";
        }

        char ts[128] = {0};
        snprintf(ts, 128, "%"PRId64",", get_time_stamp());
        char tz[128] = {0};
        snprintf(tz, 128, "%d", get_time_zone());
        cmd_fields += MYSQL_EI_TIMESTAMP + std::string(",");
        cmd_fields += MYSQL_EI_ERROR_GMT_TIME + std::string(",");
        cmd_fields += std::string(MYSQL_EI_TIME_ZONE);
        cmd_valuses += ts;
        cmd_valuses += std::string("\"")+get_gmt_time() +std::string("\"")+ std::string(",");
        cmd_valuses += tz;
        std::string mysql_cmd = cmd_fields + cmd_valuses + ");";
        int ret = query(mysql_cmd.c_str());
        srs_trace("ret:%d = query(mysql_cmd.c_str():%s)\n", ret, mysql_cmd.c_str());
        if(ret != 0)
        {
            dump_error();
        }

        return ret;
    }

    // updae a database record
    /*******************************************************************************
     * UPDATE语法
     * UPDATE [LOW_PRIORITY] [IGNORE] table_name 
     * SET 
     * column_name1 = expr1,
     * column_name2 = expr2,
        ...
     * WHERE
     * condition;
     *******************************************************************************/
    virtual int update(std::map<std::string, std::string>& condition_list, std::map<std::string, std::string>& update_list, const char* ptable)
    {
        srs_trace("%s(%s)\n", __FUNCTION__, ptable);
        std::string mysql_cmd = "UPDATE " + std::string(ptable) + " SET ";
        //std::string cmd_valuses = ") VALUE(" + ptable + "(";
        std::map<std::string, std::string>::iterator it = update_list.begin();
        for(; it != update_list.end(); it++)
        {
            /*if(it != update_list.begin())
            {
                mysql_cmd += ",";
            }*/
            mysql_cmd +=  it->first + " = " + it->second + ",";
        }
        char gmt_time[128] = {0};
        snprintf(gmt_time, 128, "\"%s\"", get_gmt_time().c_str());
        mysql_cmd += std::string(MYSQL_EI_ERROR_GMT_TIME) + std::string(" = ") + std::string(gmt_time);

        mysql_cmd += " WHERE ";
        it = condition_list.begin();
        for(; it != condition_list.end(); it++)
        {
            if(it != condition_list.begin())
            {
                mysql_cmd += ",";
            }
            mysql_cmd +=  it->first + " = " + it->second;
        }
        mysql_cmd += ";";
        int ret = query(mysql_cmd.c_str());
        return ret;
    }

    // delete a database record
    // DELETE FROM table_name [WHERE Clause]
    virtual int del(std::map<std::string, std::string>& condition_list, const char* ptable)
    {
        srs_trace("%s(%s)\n", __FUNCTION__, ptable);
        std::string mysql_cmd = "DELETE FROM " + std::string(ptable) + " WHERE ";
        std::map<std::string, std::string>::iterator it = condition_list.begin();
        for(; it != condition_list.end(); it++)
        {
            if(it != condition_list.begin())
            {
                mysql_cmd += ",";
            }
            mysql_cmd +=  it->first + " = " + it->second;
        }
        mysql_cmd += ";";
        int ret = query(mysql_cmd.c_str());
        return ret;
    }

    // query database
    virtual int query(const char* psql_cmd)
    {
        if(NULL == m_pmysql || NULL == psql_cmd)
        {
            srs_error("Invalid parameter, m_pmysql:%p, sqlcmd:%p\n", m_pmysql, psql_cmd);
            return -1;
        }
        int ret = mysql_query(m_pmysql, psql_cmd);
        srs_trace("ret:%d = query(mysql_cmd.c_str():%s)\n", ret, psql_cmd);
        if(ret != 0)
        {
            dump_error();
        }

        return ret;
    }

    // start stansaction
    virtual int start_transaction()
    {
        char* sql_cmd = "START TRANSACTION";
        return query(sql_cmd);
    }

    // rollback stansaction
    virtual int rollback_transaction()
    {
        mysql_rollback(m_pmysql);
    }

    // commit stansaction
    virtual int commit_transaction()
    {
        char* sql_cmd = "COMMIT";
        return query(sql_cmd);
    }

    // close database connection
    virtual void close()
    {
        srs_trace("sql close m_pmysql:%p\n", m_pmysql);
        if(m_pmysql)
        {
                mysql_close(m_pmysql);
                delete m_pmysql;
                m_pmysql = NULL;
        }
        srs_trace("close end\n");
    }

     // get database error code
    virtual int get_error_code()
    {
        return mysql_errno(m_pmysql);
    }

    // get database error message
    virtual std::string get_error_message()
    {
        return std::string(mysql_error(m_pmysql));
    }

    virtual void dump_error()
    {
        srs_trace("error code:%d, error msg:%s\n", get_error_code(), get_error_message().c_str());
    }
    int64_t get_time_stamp()
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        int64_t curtime = (int64_t)tv.tv_sec*1000 + tv.tv_usec/1000;
        return curtime;
    }

    int get_time_zone()
    {
        time_t t1, t2;
        struct tm *tm_local, *tm_utc;
        time(&t1);
        t2 = t1;
        tm_local = localtime(&t1);
        t1 = mktime(tm_local);
        tm_utc = gmtime(&t2);
        t2 = mktime(tm_utc);
        timezone = (t1 - t2) / 60;
        return timezone;
    }

    std::string get_gmt_time()
    {
        time_t t1, t2;
        struct tm *tm_utc;
        time(&t1);
        tm_utc = gmtime(&t1);
        char gmt_tmie[128] = {0};
        snprintf(gmt_tmie, 128, "%d-%d-%d %d:%d:%d", tm_utc->tm_year + 1900, 1 + tm_utc->tm_mon, tm_utc->tm_mday, tm_utc->tm_hour, tm_utc->tm_min, tm_utc->tm_sec);

        return std::string(gmt_tmie);
    }
private:
static CMySqlDB   m_mysql;
    MYSQL*          m_pmysql;
    std::string     m_sip;
    std::string     m_nport;
    std::string     m_suser_name;
    std::string     m_spwd;
    std::string     m_sdb_name;
};