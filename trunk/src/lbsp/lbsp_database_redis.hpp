#include <hiredis/hiredis.h>
#include <stdio.h>
#include <map>
#include <string>
#include <lbsi_database_api.hpp>

class IRedisDatabaseAPI:public idatabase_api
{
public:
    virtual redisReply* begin_enum_namespace(const char* pnamespace) = 0;

    //virtual int enum_next_key(redisReply** ppreply) = 0;
    //virtual std::string enum_next_key() = 0;

    virtual void end_enum_namespace(redisReply* preply) = 0;

    virtual int get_field_map(std::string key, std::map<std::string, std::string>& field_map) = 0;

    virtual void flush_namespace(const char* pnamespace) = 0;

    virtual void* begin_command(const char* pcmd) = 0;

    virtual int get_result_count(void* powner) = 0;

    virtual int get_string_value(void* powner, std::string& val, int index = 0) = 0;

    virtual int get_int_value(void* powner, int& val, int index = 0) = 0;

    virtual void end_command(void* powner) = 0;

    virtual int query_string_value(const char* pcmd, std::string& value) = 0;

    virtual int query_int_value(const char* pcmd, int& value) = 0;
};

// lazy bear stdarding class redis database
class redis_database:public IRedisDatabaseAPI
{
protected:
    int                 m_nport;
    int                 m_nindex;
    int                 m_nexpire_time;
    int                 m_nlast_error_code;
    std::string         m_sip;
    std::string         m_spwd;
    std::string         m_slast_error;
    redisContext*       m_predis_ctx;
    redisReply*         m_predis_reply;
    bool                m_btranscation;

public:
    redis_database(int index, int expire_time = 0)
    {
        m_nindex            = index;
        m_nexpire_time      = expire_time;
        m_nlast_error_code  = 0;
        m_nport             = DATABASE_REDIS_DEFAULT_PORT;
        m_predis_ctx        = NULL;
        m_predis_reply      = NULL;
        m_btranscation      = false;
    }

    ~redis_database()
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
        int ret = 0;
        char cmd[256] = {0};
        if(NULL == ip)
        {
            m_sip = "127.0.0.1";
        }
        else
        {
            m_sip = ip;
        }

        m_nport = port;

        if(pwd)
        {
            m_spwd = pwd;
        }
        else
        {
            m_spwd.clear();
        }

        lbdebug("redisConnect connect(ip:%s, port:%d, pwd:%s)\n", ip, port, pwd);
        // connect redis database
        m_predis_ctx = redisConnect(m_sip.c_str(), port);
        lbtrace("m_predis_ctx:%p = redisConnect(m_sip.c_str():%s, port:%d)\n", m_predis_ctx, m_sip.c_str(), port);
        if(NULL == m_predis_ctx)
        {
            lbwarn("m_predis_ctx:%p = redisConnect(m_sip.c_str():%s, port:%d)\n", m_predis_ctx, m_sip.c_str(), port);
            return DATABASE_CODE_INVALID_PARAMETEER;
        }
        LB_ADD_MEM(m_predis_ctx, sizeof(long));
        // auhtorize password 
        
        if(!m_spwd.empty())
        {
            sprintf(cmd, "AUTH %s", m_spwd.c_str());
            ret = command(cmd);
            lbdebug("ret:%d = command(cmd:%s)\n", ret, cmd);
            if(DATABASE_CODE_SUCCESS != ret)
            {
                LB_RM_MEM(m_predis_ctx);
                redisFree(m_predis_ctx);
                m_predis_ctx = NULL;
                lberror("redis authorize password failed\n");
                return ret;
            }
        }

        // select database index
        sprintf(cmd, "SELECT %d", m_nindex);
        ret = command(cmd);
        lbcheck_result_return(ret);
        lbdebug("ret:%d = command(cmd:%s)\n", ret, cmd);
        return ret;
    }

/***************************************************************************************************************************************************
*   @descripe: insert record to database indicator(table or key)
*   @param     fv_map: record map with fieid-value map list, for string value, you should input "\"...\"" at string begin and end, such as /"hello!/"
*   @param     pindicator:  record indicator, for key value database, pindicator is a record key, for RDB(relational Database), pindicator is a table name of which this record indicate to.
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int insert(std::map<std::string, std::string>& fv_map, const char* pindicator)
    {
        if(NULL == pindicator || fv_map.size() <= 0)
        {
            lbwarn("Invalid parameter pindicator:%s, fv_map.size():%s\n", pindicator, fv_map.size());
            return DATABASE_CODE_INVALID_PARAMETEER;
        }

        std::string cmd_str = "HMSET " + std::string(pindicator) + " ";
        //std::string cmd_valuses = ") VALUE(";
        std::map<std::string, std::string>::iterator it = fv_map.begin();
        for(; it != fv_map.end(); it++)
        {
            cmd_str += " " + it->first + " ";
            cmd_str += " " + it->second;
        }
        
        int ret = command(cmd_str.c_str());
        if(DATABASE_CODE_SUCCESS != ret)
        {
            return ret;
        }
        char cmd[256] = {0};
        sprintf(cmd, "EXPIRE %s %d", pindicator, m_nexpire_time);
        ret = command(cmd);

        return ret;
    }

/***************************************************************************************************************************************************
*   @descripe: updae a database record
*   @param     condition_fv_map:  update condition with field-value map
*   @param     update_fv_map: filed-value map of which need update
*   @param     pindicator: record indicator, for key value database, pindicator is a record key, for RDB(relational Database), pindicator is a table name of which this record indicate to.
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int update(std::map<std::string, std::string>& condition_fv_map,  std::map<std::string, std::string>& update_fv_map, const char* pindicator)
    {
        if(NULL == pindicator || update_fv_map.size() <= 0)
        {
            lbwarn("Invalid parameter pindicator:%s, update_fv_map.size():%s\n", pindicator, update_fv_map.size());
            return DATABASE_CODE_INVALID_PARAMETEER;
        }
        //lbtrace("%s(%s)\n", __FUNCTION__, pindicator);
        std::string cmd_argc = "HMSET " + std::string(pindicator) + " ";
        std::map<std::string, std::string>::iterator it = update_fv_map.begin();
        for(; it != update_fv_map.end(); it++)
        {
            cmd_argc += " " + it->first + " ";
            cmd_argc += " " + it->second;
        }

        int ret = command(cmd_argc.c_str());
        return ret;
    }

/***************************************************************************************************************************************************
*   @descripe: insert record to database indicator(table or key)
*   @param     condition_fv_map: condition filed-value map of which need to delete
*   @param     pindicator:  record indicator, for key value database, pindicator is a record key, for RDB(relational Database), pindicator is a table name of which this record indicate to.
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int del(std::map<std::string, std::string>& condition_fv_map, const char* pindicator)
    {
        if(NULL == pindicator)
        {
            lbwarn("Invalid parameter pindicator:%s\n", pindicator);
            return DATABASE_CODE_INVALID_PARAMETEER;
        }

        std::string cmd_argc;
        if(condition_fv_map.size() <= 0)
        {
            cmd_argc = "DEL " + std::string(pindicator);
        }
        else
        {
            cmd_argc = "DEL " + std::string(pindicator);
            std::map<std::string, std::string>::iterator it = condition_fv_map.begin();
            for(; it != condition_fv_map.end(); it++)
            {
                cmd_argc += " " + it->first + " ";
                cmd_argc += " " + it->second;
            }
        }

        int ret = command(cmd_argc.c_str());
        return ret;
    }

/***************************************************************************************************************************************************
*   @descripe: exec command immediate
*   @param     pcmd: database command to exec
*   @return    0:success, else failed
****************************************************************************************************************************************************/
virtual int command(const char* pcmd)
{
    if(NULL == pcmd)
    {
        lbwarn("Invalid redis command %s\n", pcmd);
        return DATABASE_CODE_INVALID_PARAMETEER;
    }

    if(NULL == m_predis_ctx)
    {
        lbwarn("redis context has not init\n");
        return DATABASE_CODE_DB_NOT_CONNECTED;
    }

    m_predis_reply = (redisReply*)redisCommand(m_predis_ctx, pcmd);
    lbdebug("m_predis_reply:%p = (redisReply*)redisCommand(m_predis_ctx:%p, pcmd:%s)\n", m_predis_reply, m_predis_ctx, pcmd);
    if(NULL == m_predis_reply)
    {
        lbwarn("exec redis command %s failed, m_predis_reply:%p\n", pcmd, m_predis_reply);
        return DATABASE_CODE_EXE_COMMAND_ERROR;
    }
    LB_ADD_MEM(m_predis_reply, sizeof(long));
    return handleReply();
}

virtual int vcommand(const char* pfmt, ...)
{
    va_list ap;
    va_start(ap, pfmt);
    m_predis_reply = (redisReply*)redisvCommand(m_predis_ctx, pfmt, ap);
    //va_arg(ap, int);
    va_end(ap);
    if(NULL == m_predis_reply)
    {
        lbwarn("exec redis vcommand %s failed, m_predis_reply:%p\n", pfmt, m_predis_reply);
        return DATABASE_CODE_EXE_COMMAND_ERROR;
    }
    LB_ADD_MEM(m_predis_reply, sizeof(long));
    return handleReply();
}
/***************************************************************************************************************************************************
*   @descripe: start a stansaction
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int start_transaction()
    {
        int ret = command("MULTI");
		SRS_CHECK_RESULT(ret);
        //lbdebug("ret:%d = start_transaction\n", ret);
        if(DATABASE_CODE_SUCCESS == ret)
        {
            m_btranscation = true;
        }

        return ret;
    }

/***************************************************************************************************************************************************
*   @descripe: rollback a stansaction
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int rollback_transaction()
    {
        int ret = command("DISCARD");
		SRS_CHECK_RESULT(ret);
        //lbdebug("ret:%d = rollback_transaction\n", ret);
        if(DATABASE_CODE_SUCCESS == ret)
        {
            m_btranscation = false;
        }

        return ret;
    }

/***************************************************************************************************************************************************
*   @descripe: commit a stansaction
*   @return    0:success, else failed
****************************************************************************************************************************************************/
    virtual int commit_transaction()
    {
        int ret = command("EXEC");
		SRS_CHECK_RESULT(ret);
        //lbdebug("ret:%d = commit_transaction\n", ret);
        if(DATABASE_CODE_SUCCESS == ret)
        {
            m_btranscation = false;
        }

        return ret;
    }

/***************************************************************************************************************************************************
*   @descripe: close database connection
*   @return    none
****************************************************************************************************************************************************/
    virtual void close()
    {
        //lbtrace("cloase begin\n");
        if(m_predis_reply)
        {
            LB_RM_MEM(m_predis_reply);
            freeReplyObject(m_predis_reply);
            m_predis_reply = NULL;
        }
        //lbtrace("cloase before redisFree(m_predis_ctx:%p)\n", m_predis_ctx);
        if(m_predis_ctx)
        {
            LB_RM_MEM(m_predis_ctx);
            redisFree(m_predis_ctx);
            m_predis_ctx = NULL;
        }
        //lbtrace("cloase end\n");
    }

/***************************************************************************************************************************************************
*   @descripe: get last error code
*   @return    last error code
****************************************************************************************************************************************************/
    virtual int error_code()
    {
        return m_nlast_error_code;
    }
/***************************************************************************************************************************************************
*   @descripe: get last error message
*   @return    last error message string
****************************************************************************************************************************************************/
    virtual std::string error_message()
    {
        return m_slast_error;
    }

/***************************************************************************************************************************************************
*   @descripe: trace last error
*   @return    none
****************************************************************************************************************************************************/
    virtual void trace_error()
    {
        lbtrace("error code:%d, error msg:%s\n", error_code(), error_message().c_str());
    }

protected:
    int handleReply(void* value = NULL, redisReply*** array = NULL)
    {
        //srs_trace("m_predis_ctx->err:%d", m_predis_ctx->err);
        if(NULL == m_predis_ctx)
        {
            lbwarn("redis has not connect!");
            return DATABASE_CODE_DB_NOT_CONNECTED;
        }
        int ret = 0;
        if (m_predis_ctx->err)
        {
            m_slast_error = m_predis_ctx->errstr;
            m_nlast_error_code = m_predis_ctx->err;
            lbwarn("m_predis_ctx->err:%d, m_predis_ctx->errstr:%s", m_predis_ctx->err, m_predis_ctx->errstr);
            if(m_predis_reply)
            {
                LB_RM_MEM(m_predis_reply);
                freeReplyObject(m_predis_reply);
                m_predis_reply = NULL;
            }
            return  DATABASE_CODE_CONTEXT_ERROR;
        }

        if (m_predis_reply == NULL)
        {
            m_slast_error = "auth redisReply is NULL";
            if(m_predis_reply)
            {
                LB_RM_MEM(m_predis_reply);
                freeReplyObject(m_predis_reply);
                m_predis_reply = NULL;
            }
            m_nlast_error_code = DATABASE_CODE_REPLY_ERROR;
            return DATABASE_CODE_REPLY_ERROR;
        }
        //lbtrace("m_predis_reply->type:%d， m_predis_reply->str:%s\n", m_predis_reply->type, m_predis_reply->str);
        switch (m_predis_reply->type)
        {
            case REDIS_REPLY_ERROR:
            {
                m_slast_error = m_predis_reply->str;
                ret = DATABASE_CODE_EXE_COMMAND_ERROR;
                break;
            }
            case REDIS_REPLY_STATUS:
            {
                if (!strcmp(m_predis_reply->str, "OK"))
                {
                    ret = DATABASE_CODE_SUCCESS;
                }
                else if(m_btranscation && !strcmp(m_predis_reply->str, "QUEUED"))
                {
                    ret = DATABASE_CODE_SUCCESS;
                }
                else
                {
                    m_slast_error = m_predis_reply->str;
                    ret = DATABASE_CODE_EXE_COMMAND_ERROR;
                }
                break;
            }
            case REDIS_REPLY_INTEGER:
            {
                if(value)
                {
                    *(int*)value = m_predis_reply->integer;
                }
                ret = DATABASE_CODE_SUCCESS;
                break;
            }
            case REDIS_REPLY_STRING:
            {
                if(value)
                {
                    *(std::string*)value = m_predis_reply->str;
                }
                ret = DATABASE_CODE_SUCCESS;
                break; 
            }
            case REDIS_REPLY_NIL:
            {
                if(value)
                {
                    *(std::string*)value = "";
                }
                ret = DATABASE_CODE_SUCCESS;
                break;
            } 
            case REDIS_REPLY_ARRAY:
            {
                if(value)
                {
                    *(int*)value = m_predis_reply->elements;
                }
                if(array)
                {
                    *array = m_predis_reply->element;
                }
                ret = DATABASE_CODE_SUCCESS;
                break;
            }  
            default:
            {
                m_slast_error = "unknow reply type";
                ret = DATABASE_CODE_EXE_COMMAND_ERROR;
                break;
            }
        }

        if(m_predis_reply)
        {
            m_nlast_error_code = ret;
            LB_RM_MEM(m_predis_reply);
            freeReplyObject(m_predis_reply);
            m_predis_reply = NULL;
        }

        return ret;
    }

    redisReply* begin_enum_namespace(const char* pnamespace)
    {
        char cmd[1024] = {0};
        sprintf(cmd, "keys %s*", pnamespace);
        redisReply* predis_reply = (redisReply*)redisCommand(m_predis_ctx, cmd);
        srs_trace("predis_reply:%p = (redisReply*)redisvCommand(m_predis_ctx:%p, keys %s*, pnamespace:%s)\n", predis_reply, m_predis_ctx, pnamespace);
        return predis_reply;
    }

    void end_enum_namespace(redisReply* predis_reply)
    {
        if(predis_reply)
        {
            LB_RM_MEM(predis_reply);
            freeReplyObject(predis_reply);
            predis_reply = NULL;
        }
    }

    int get_field_map(std::string key, std::map<std::string, std::string>& field_map)
    {
        return -1;
    }

    void flush_namespace(const char* pnamespace)
    {
        int ret = 0;
        redisReply* preply = begin_enum_namespace(pnamespace);
        if(NULL == preply)
        {
            return ;
        }
        if(REDIS_REPLY_ARRAY != preply->type)
        {
            srs_trace("Invaid preply->type:%d\n", preply->type);
            return ;
        }
        for(unsigned int i = 0; i < preply->elements; i++)
        {
            redisReply* childReply = preply->element[i];
            if(childReply)
            {
                if(REDIS_REPLY_STRING == childReply->type)
                {
                    lbtrace("del %s\n", childReply->str);
                    ret = vcommand("del %s", childReply->str);
                    if(DATABASE_CODE_SUCCESS != ret)
                    {
                        srs_trace("ret:%d = vcommand(del %s, childReply->str:%s) failed", ret, childReply->str);
                    }
                }
            }
        }
        end_enum_namespace(preply);
    }

    void* begin_command(const char* pcmd)
    {
        redisReply* predis_reply = (redisReply*)redisCommand(m_predis_ctx, pcmd);
        if(NULL == predis_reply)
        {
            lberror("predis_reply:%p = (redisReply*)redisCommand(m_predis_ctx:%p, pcmd:%s) failed\n", predis_reply, m_predis_ctx, pcmd);
            return NULL;
        }
        if(REDIS_REPLY_ERROR == predis_reply->type)
        {
            return NULL;
        }
        //LB_ADD_MEM(predis_reply);
        lbtrace("predis_reply->type:%d\n", predis_reply->type);
        return predis_reply;
    }

    virtual int get_result_count(void* powner)
    {
        redisReply* predis_reply = (redisReply*)powner;
        if(NULL == predis_reply)
        {
            return 0;
        }

        if(REDIS_REPLY_ARRAY == predis_reply->type)
        {
            return predis_reply->elements;
        }
        else if(REDIS_REPLY_NIL == predis_reply->type || REDIS_REPLY_STATUS == predis_reply->type)
        {
            return 0;
        }
        else
        {
            return 1;
        }
        
    }

    virtual int get_string_value(void* powner, std::string& val, int index = 0)
    {
        redisReply* predis_reply = (redisReply*)powner;
        redisReply* preply = predis_reply;
        if(NULL == predis_reply)
        {
            lberror("Invalid parameter, predis_reply:%p\n", predis_reply);
            return -1;
        }

        if(index <= 0 || (unsigned int)index > predis_reply->elements)
        {
            lberror("index:%d <= 0 || index > predis_reply->elements:%d, get string failed\n", index, predis_reply->elements);
            return -1;
        }
        
        if(REDIS_REPLY_ARRAY == predis_reply->type)
        {
            preply = predis_reply->element[index];
        }

        if(REDIS_REPLY_STRING == preply->type)
        {
            val = preply->str;
        }
        
        return 0;
    }

    virtual int get_int_value(void* powner, int& val, int index = 0)
    {
        redisReply* predis_reply = (redisReply*)powner;
        redisReply* preply = predis_reply;
        if(NULL == predis_reply)
        {
            lberror("Invalid parameter, predis_reply:%p\n", predis_reply);
            return -1;
        }

        if(index <= 0 || (unsigned int)index > predis_reply->elements)
        {
            lberror("index:%d <= 0 || index > predis_reply->elements:%d, get string failed\n", index, predis_reply->elements);
            return -1;
        }
        
        if(REDIS_REPLY_ARRAY == predis_reply->type)
        {
            preply = predis_reply->element[index];
        }

        if(REDIS_REPLY_INTEGER == preply->type)
        {
            val = preply->integer;
        }
        else
        {
            lberror("result value is not integer, preply->type:%d\n", preply->type);
            return -1;
        }
        
        return 0;
    }

    virtual void end_command(void* powner)
    {
        redisReply* predis_reply = (redisReply*)powner;
        if(NULL == predis_reply)
        {
            return;
        }
        LB_RM_MEM(predis_reply);
        freeReplyObject(predis_reply);
    }

    virtual int query_string_value(const char* pcmd, std::string& value)
    {
        int ret = -1;
        redisReply* predis_reply = (redisReply*)redisCommand(m_predis_ctx, pcmd);
        redisReply* preply = predis_reply;
        if(NULL == predis_reply)
        {
            lberror("predis_reply:%p = (redisReply*)redisCommand(m_predis_ctx:%p, pcmd:%s) failed\n", predis_reply, m_predis_ctx, pcmd);
            return -1;
        }

        if(REDIS_REPLY_ARRAY == predis_reply->type && predis_reply->elements > 0)
        {
            preply = predis_reply->element[0];
        }

        if(REDIS_REPLY_STRING == preply->type)
        {
            value = preply->str;
            ret = 0;
        }
        else
        {
            lberror("query string value failed, Invalid preply->type:%d\n", preply->type);
        }
        freeReplyObject(predis_reply);
        return ret;
    }

    virtual int query_int_value(const char* pcmd, int& value)
    {
        int ret = -1;
        redisReply* predis_reply = (redisReply*)redisCommand(m_predis_ctx, pcmd);
        redisReply* preply = predis_reply;
        if(NULL == predis_reply)
        {
            lberror("predis_reply:%p = (redisReply*)redisCommand(m_predis_ctx:%p, pcmd:%s) failed\n", predis_reply, m_predis_ctx, pcmd);
            return -1;
        }

        if(REDIS_REPLY_ARRAY == predis_reply->type && predis_reply->elements > 0)
        {
            preply = predis_reply->element[0];
        }

        if(REDIS_REPLY_INTEGER == preply->type)
        {
            value = preply->integer;
            ret = 0;
        }
        else
        {
            lberror("query int value failed, Invalid preply->type:%d\n", preply->type);
        }
        freeReplyObject(predis_reply);
        return ret;
    }
};