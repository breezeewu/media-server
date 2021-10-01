#pragma once
#include <stdio.h>
#include <string>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/time.h>
#include "mysql/mysql.h"
#include <lbsi_database_api.hpp>
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


class mysql_database:public idatabase_api
{

protected:
    MYSQL*          m_pmysql;
    std::string     m_sip;
    int             m_nport;
    std::string     m_suser_name;
    std::string     m_spwd;
    std::string     m_sdb_name;
    //static mysql_database* m_pmysql;
public: 
    mysql_database(const char* puser_name, const char* pdb_name)
    {
        //m_pmysql = NULL;
        if(puser_name)
        {
            m_suser_name = puser_name;
        }
        
        if(pdb_name)
        {
            m_sdb_name = pdb_name;
        }
        m_pmysql = NULL;
        m_nport = DATABASE_MYSQL_DEFAULT_PORT;
    }

public:
    ~mysql_database()
    {
        close();
    }

    /***************************************************************************************************************************************************
*   @descripe: connect to database server
*   @param     ip:  database server ip
*   @param     port:database server port
*   @param     pwd: database server connection password
*   @return    0:success, else failed
****************************************************************************************************************************************************/
virtual int connect(const char* ip, int port, const char* pwd)
{
        lbdebug("connect(ip:%s, port:%d, pwd:%s), m_pmysql:%p\n", ip, port, pwd, m_pmysql);
	    close();
        if(NULL == ip)
        {
            m_sip = "127.0.0.1";
        }
        else
        {
            m_sip = ip;
        }
        if(port <= 0)
        {
            m_nport = 32;
        }
        else
        {
            m_nport = port;
        }
        
        if(m_suser_name.empty() || m_sdb_name.empty())
        {
            srs_error("Invalid parameter, m_suser_name.c_str():%s, m_sdb_name.c_str():%s\n", m_suser_name.c_str(), m_sdb_name.c_str());
            return DATABASE_CODE_INVALID_PARAMETEER;
        }

        if(NULL == pwd)
        {
            m_spwd = "";
        }
        else
        {
            m_spwd = pwd;
        }
        m_pmysql = new MYSQL;
        LB_ADD_MEM(m_pmysql, sizeof(MYSQL));
        MYSQL* pmysql = mysql_init(m_pmysql);
        lbdebug("pmysql:%p = mysql_init(m_pmysql:%p)\n", pmysql, m_pmysql);
        if(NULL == m_pmysql)
        {
            trace_error();
            srs_error("pmysql:%p = mysql_init(&m_mysql)", pmysql);
            close();
			return -DATABASE_CODE_CONNECT_ERROR;
        }
        m_pmysql = mysql_real_connect(pmysql, m_sip.c_str(), m_suser_name.c_str(), pwd, m_sdb_name.c_str(), m_nport, NULL, 0);
        lbtrace("m_pmysql:%p = mysql_real_connect(pmysql:%p, m_sip.c_str():%s, m_suser_name.c_str():%s, pwd:%s, m_sdb_name.c_str():%s, m_nport:%d, NULL, 0)\n", m_pmysql, pmysql, m_sip.c_str(), m_suser_name.c_str(), pwd, m_sdb_name.c_str(), m_nport);
        if(NULL == m_pmysql)
        {
            trace_error();
            srs_error("m_pmysql:%p = mysql_real_connect(pmysql:%p, ip:%s, username:%s, pwd:%s, dbname:%s, port:%d, NULL, 0)\n", m_pmysql, pmysql, m_sip.c_str(), m_suser_name.c_str(), pwd, m_sdb_name.c_str(), port);
            close();
			return -DATABASE_CODE_CONNECT_ERROR;
        }
        
        return DATABASE_CODE_SUCCESS;
}

/***************************************************************************************************************************************************
*   @descripe: insert record to database indicator(table or key)
*   @param     fv_map: record map with fieid-value map list, for string value, you should input "\"...\"" at string begin and end, such as /"hello!/"
*   @param     pindicator:  record indicator, for key value database, pindicator is a record key, for RDB(relational Database), pindicator is a table name of which this record indicate to.
*   @return    0:success, else failed
****************************************************************************************************************************************************/
virtual int insert(std::map<std::string, std::string>& fv_map, const char* ptable)
{
        if(NULL == ptable)
        {
            srs_error("Invalid parameter, ptable:%p\n", ptable);
            return -1;
        }

        std::string cmd_fields = "INSERT INTO " + std::string(ptable) + "(";
        std::string cmd_valuses = ") VALUE(";
        std::map<std::string, std::string>::iterator it = fv_map.begin();
        for(; it != fv_map.end(); it++)
        {
            cmd_fields += it->first + ",";
            cmd_valuses += it->second + ",";
        }

        std::string mysql_cmd = cmd_fields + cmd_valuses + ");";
        int ret = command(mysql_cmd.c_str());
        //srs_trace("ret:%d = query(mysql_cmd.c_str():%s)\n", ret, mysql_cmd.c_str());
        if(ret != 0)
        {
            trace_error();
        }

        return ret;
}

    // updae a database record
/***************************************************************************************************************************************************
*   @descripe: updae a database record
*   @param     condition_fv_map:  update condition with field-value map
*   @param     update_fv_map: filed-value map of which need update
*   @param     pindicator: record indicator, for key value database, pindicator is a record key, for RDB(relational Database), pindicator is a table name of which this record indicate to.
*   @return    0:success, else failed
****************************************************************************************************************************************************/
virtual int update(std::map<std::string, std::string>& condition_fv_map,  std::map<std::string, std::string>& update_fv_map, const char* ptable)
{
        //srs_trace("%s(%s)\n", __FUNCTION__, ptable);
        std::string mysql_cmd = "UPDATE " + std::string(ptable) + " SET ";
        //std::string cmd_valuses = ") VALUE(" + ptable + "(";
        std::map<std::string, std::string>::iterator it = update_fv_map.begin();
        for(; it != update_fv_map.end(); it++)
        {
            /*if(it != update_list.begin())
            {
                mysql_cmd += ",";
            }*/
            mysql_cmd +=  it->first + " = " + it->second + ",";
        }
        //char gmt_time[128] = {0};
        //snprintf(gmt_time, 128, "\"%s\"", get_gmt_time().c_str());
        //mysql_cmd += std::string(MYSQL_EI_ERROR_GMT_TIME) + std::string(" = ") + std::string(gmt_time);

        mysql_cmd += " WHERE ";
        it = condition_fv_map.begin();
        for(; it != condition_fv_map.end(); it++)
        {
            if(it != condition_fv_map.begin())
            {
                mysql_cmd += ",";
            }
            mysql_cmd +=  it->first + " = " + it->second;
        }
        mysql_cmd += ";";
        int ret = command(mysql_cmd.c_str());
        return ret;
}

/***************************************************************************************************************************************************
*   @descripe: insert record to database indicator(table or key)
*   @param     condition_fv_map: condition filed-value map of which need to delete
*   @param     pindicator:  record indicator, for key value database, pindicator is a record key, for RDB(relational Database), pindicator is a table name of which this record indicate to.
*   @return    0:success, else failed
****************************************************************************************************************************************************/
virtual int del(std::map<std::string, std::string>& condition_fv_map, const char* ptable)
{
    //srs_trace("%s(%s)\n", __FUNCTION__, ptable);
    std::string mysql_cmd = "DELETE FROM " + std::string(ptable) + " WHERE ";
    std::map<std::string, std::string>::iterator it = condition_fv_map.begin();
    for(; it != condition_fv_map.end(); it++)
    {
        if(it != condition_fv_map.begin())
        {
            mysql_cmd += ",";
        }
        mysql_cmd +=  it->first + " = " + it->second;
    }
    mysql_cmd += ";";
    int ret = command(mysql_cmd.c_str());
    return ret;
}

/***************************************************************************************************************************************************
*   @descripe: exec command immediate
*   @param     pcmd: database command to exec
*   @return    0:success, else failed
****************************************************************************************************************************************************/
virtual int command(const char* pcmd)
{
    if(NULL == m_pmysql || NULL == pcmd)
    {
        srs_error("Invalid parameter, m_pmysql:%p, sqlcmd:%p\n", m_pmysql, pcmd);
        return -1;
    }
    int ret = mysql_query(m_pmysql, pcmd);
    lbdebug("ret:%d = mysql_query(m_pmysql:%p, mysql_cmd.c_str():%s)\n", ret, m_pmysql, pcmd);
    if(DATABASE_CODE_SUCCESS != ret)
    {
        lberror("ret:%d = mysql_query(m_pmysql:%p, pcmd:%s) failed", ret, m_pmysql, pcmd);
        trace_error();
    }

        return ret;
}

/***************************************************************************************************************************************************
*   @descripe: exec command immediate
*   @param     pfmt command format string
*   @param     ...: varable parameter
*   @return    0:success, else failed
****************************************************************************************************************************************************/
virtual int vcommand(const char* pfmt, ...)
{
    char buf[1024] = {0};
    int cmd_len = 0;
    va_list ap;
    va_start(ap, pfmt);
    // we reserved 1 bytes for the new line.
    cmd_len += vsnprintf(buf + cmd_len, 1024 - cmd_len, pfmt, ap);
    va_end(ap);

    return command(buf);
}
/***************************************************************************************************************************************************
*   @descripe: start a stansaction
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int start_transaction()
    {
        const char* sql_cmd = "START TRANSACTION";
        return command(sql_cmd);
    }

/***************************************************************************************************************************************************
*   @descripe: rollback a stansaction
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int rollback_transaction()
    {
        bool ret = mysql_rollback(m_pmysql);

        return ret ? DATABASE_CODE_SUCCESS : DATABASE_CODE_EXE_COMMAND_ERROR;
    }

/***************************************************************************************************************************************************
*   @descripe: commit a stansaction
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int commit_transaction()
    {
        const char* sql_cmd = "COMMIT";
        return command(sql_cmd);
    }

/***************************************************************************************************************************************************
*   @descripe: close database connection
*   @return    none
****************************************************************************************************************************************************/
    virtual void close()
    {
        //srs_trace("sql close m_pmysql:%p\n", m_pmysql);
        if(m_pmysql)
        {
                mysql_close(m_pmysql);
                srs_freep(m_pmysql);
                //delete m_pmysql;
                //m_pmysql = NULL;
        }
        //srs_trace("close end\n");
    }

/***************************************************************************************************************************************************
*   @descripe: get last error code
*   @return    last error code
****************************************************************************************************************************************************/
    virtual int error_code()
    {
        if(m_pmysql)
        {
            return mysql_errno(m_pmysql);
        }
        return DATABASE_CODE_DB_NOT_CONNECTED;
    }

/***************************************************************************************************************************************************
*   @descripe: get last error message
*   @return    last error message string
****************************************************************************************************************************************************/
    virtual std::string error_message()
    {
        std::string err_msg;
        if(m_pmysql)
        {
            err_msg = mysql_error(m_pmysql);
        }

        return err_msg;
    }

/***************************************************************************************************************************************************
*   @descripe: trace last error
*   @return    none
****************************************************************************************************************************************************/
    virtual void trace_error()
    {
        lbtrace("error code:%d, error msg:%s\n", error_code(), mysql_error(m_pmysql));
    }
};