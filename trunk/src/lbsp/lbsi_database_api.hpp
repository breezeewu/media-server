#pragma once
//#define REDIS_TEST
#ifndef REDIS_TEST
#include <srs_kernel_log.hpp>
#else
#define LB_ADD_MEM
#define LB_RM_MEM
#define srs_freep(p) if(p){ delete p; p = NULL;}
#endif
#include <string>
#include <map>
#include <stdio.h>

#ifndef lbdebug
#define lbdebug srs_debug
#endif
#ifndef lbtrace
#define lbtrace srs_trace
#endif
#ifndef lbwarn
#define lbwarn srs_warn
#endif
#ifndef lberror
#define lberror srs_error
#endif
#define DATABASE_TYPE_REDIS                 0
#define DATABASE_TYPE_MYSQL                 1
#define DATABASE_REDIS_DEFAULT_PORT         6379
#define DATABASE_MYSQL_DEFAULT_PORT         3306
#define DATABASE_CODE_SUCCESS               0
#define DATABASE_CODE_ERROR_BASE                  1000
#define DATABASE_CODE_EXE_COMMAND_ERROR     DATABASE_CODE_ERROR_BASE + 1
#define DATABASE_CODE_CONTEXT_ERROR         DATABASE_CODE_ERROR_BASE + 2
#define DATABASE_CODE_REPLY_ERROR           DATABASE_CODE_ERROR_BASE + 3
#define DATABASE_CODE_CONNECT_ERROR         DATABASE_CODE_ERROR_BASE + 4
#define DATABASE_CODE_INVALID_PARAMETEER    DATABASE_CODE_ERROR_BASE + 5
#define DATABASE_CODE_DB_NOT_CONNECTED      DATABASE_CODE_ERROR_BASE + 6

#define lbcheck_ptr(ptr, ret) if(NULL == ptr) { return ret;};
#ifndef lbcheck_result_return
#define lbcheck_result_return(ret) if(0 > ret) {lberror("%s:%d, %s check result failed, ret:%d\n", __FILE__, __LINE__, __FUNCTION__, ret); return ret;}
#endif
#ifdef lbcheck_result_break
#define lbcheck_result_break(ret) if(0 > ret) {lberror("%s:%d, %s check result failed, ret:%d, break!\n", __FILE__, __LINE__, __FUNCTION__, ret); break;}
#endif
class idatabase_api
{
public:
    virtual ~idatabase_api(){}

/***************************************************************************************************************************************************
*   @descripe: connect to database server
*   @param     ip:  database server ip
*   @param     port:database server port
*   @param     pwd: database server connection password
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int connect(const char* ip, int port, const char* pwd) = 0;

/***************************************************************************************************************************************************
*   @descripe: insert record to database indicator(table or key)
*   @param     fv_map: record map with fieid-value map list, for string value, you should input "\"...\"" at string begin and end, such as /"hello!/"
*   @param     pindicator:  record indicator, for key value database, pindicator is a record key, for RDB(relational Database), pindicator is a table name of which this record indicate to.
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int insert(std::map<std::string, std::string>& fv_map, const char* pindicator) = 0;

    // updae a database record
/***************************************************************************************************************************************************
*   @descripe: updae a database record
*   @param     condition_fv_map:  update condition with field-value map
*   @param     update_fv_map: filed-value map of which need update
*   @param     pindicator: record indicator, for key value database, pindicator is a record key, for RDB(relational Database), pindicator is a table name of which this record indicate to.
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int update(std::map<std::string, std::string>& condition_fv_map,  std::map<std::string, std::string>& update_fv_map, const char* pindicator) = 0;

/***************************************************************************************************************************************************
*   @descripe: insert record to database indicator(table or key)
*   @param     condition_fv_map: condition filed-value map of which need to delete
*   @param     pindicator:  record indicator, for key value database, pindicator is a record key, for RDB(relational Database), pindicator is a table name of which this record indicate to.
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int del(std::map<std::string, std::string>& condition_fv_map, const char* pindicator) = 0;

/***************************************************************************************************************************************************
*   @descripe: exec command immediate
*   @param     pcmd: database command to exec
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int command(const char* pcmd) = 0;

/***************************************************************************************************************************************************
*   @descripe: exec command immediate
*   @param     pfmt command format string
*   @param     ...: varable parameter
*   @return    0:success, else failed
****************************************************************************************************************************************************/
virtual int vcommand(const char* pfmt, ...) = 0;

/***************************************************************************************************************************************************
*   @descripe: start a stansaction
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int start_transaction() = 0;

/***************************************************************************************************************************************************
*   @descripe: rollback a stansaction
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int rollback_transaction() = 0;

/***************************************************************************************************************************************************
*   @descripe: commit a stansaction
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int commit_transaction() = 0;

/***************************************************************************************************************************************************
*   @descripe: close database connection
*   @return    none
****************************************************************************************************************************************************/
    virtual void close() = 0;

/***************************************************************************************************************************************************
*   @descripe: get last error code
*   @return    last error code
****************************************************************************************************************************************************/
    virtual int error_code() = 0;

/***************************************************************************************************************************************************
*   @descripe: get last error message
*   @return    last error message string
****************************************************************************************************************************************************/
    virtual std::string error_message() = 0;

/***************************************************************************************************************************************************
*   @descripe: trace last error
*   @return    none
****************************************************************************************************************************************************/
    virtual void trace_error() = 0;
};