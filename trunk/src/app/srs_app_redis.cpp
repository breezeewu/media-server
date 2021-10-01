#include "srs_app_redis.hpp"
#include <srs_core.hpp>
#include <srs_kernel_log.hpp>
#include <srs_kernel_error.hpp>
#include <srs_app_config.hpp>
#include <string>
#include <cstring>
#include <iostream>
using namespace std;
CSrsRedisHandler* CSrsRedisHandler::m_pRedisHandle(NULL);
CSrsRedisHandler::CSrsRedisHandler()
{
    m_nport = 0;
    m_ndbidx = 0;
    pm_rct = NULL;
    pm_rr = NULL;
}

CSrsRedisHandler::~CSrsRedisHandler()
{
    disConnect();
    pm_rct = NULL;
    pm_rr = NULL;
}

CSrsRedisHandler* CSrsRedisHandler::get_inst()
{
    
    if(NULL == m_pRedisHandle)
    {
        std::string vhost = "hls";
        std::string ip = _srs_config->get_vhost_hls_redis_ip(vhost);
        //srs_trace("ip:%s", ip.c_str());
        if(!ip.empty())
        {
            int port = _srs_config->get_vhost_hls_redis_port(vhost);
            std::string pwd = _srs_config->get_vhost_hls_redis_pwd(vhost);
            int index = _srs_config->get_vhost_hls_redis_db_index(vhost);
            m_pRedisHandle = new CSrsRedisHandler();
            LB_ADD_MEM(m_pRedisHandle, sizeof(CSrsRedisHandler));
            int ret = m_pRedisHandle->connect(ip, port, pwd, index);
            if(ret < 0)
            {
                srs_freep(m_pRedisHandle);
                //delete m_pRedisHandle;
                //m_pRedisHandle = NULL;
                srs_trace("ret:%d < 0, get inst failed!", ret);
            }
        }
        else
        {
            srs_trace("redis db disable, return NULL");
        }
        
    }
    //srs_trace("m_pRedisHandle:%p", m_pRedisHandle);
    return m_pRedisHandle;
}
/*
连接redis数据库
addr: 地址，port：端口号，pwd：密码
成功返回ERROR_SUCCESS，失败返回ERROR_REDIS_CONNECT_FAIL
*/
int CSrsRedisHandler::connect(const string &addr, int port, const string &pwd, int index)
{
    srs_info("(addr:%s, port:%d, pwd:%s, index:%d) begin", addr.c_str(), port, pwd.c_str(), index);
    int ret = 0;
    m_saddr = addr;
    m_nport = port;
    m_spwd = pwd;
    m_ndbidx = index;
    pm_rct = redisConnect(m_saddr.c_str(), m_nport);
    
    if (pm_rct->err)
    {
        error_msg = pm_rct->errstr;
		srs_error("pm_rct = redisConnect(m_addr:%s, m_port:%d), err:%d, error_msg:%s, failed", m_saddr.c_str(), (int)m_nport, pm_rct->err, error_msg.c_str());
        return ERROR_REDIS_CONNECT_FAIL;
    }
    srs_info("pm_rct = redisConnect(m_saddr.c_str(), m_nport) success");
    if (!m_spwd.empty())
    {
        ret = connectAuth(m_spwd);
        if(ret)
        {
            srs_error("ret:%d = redisConnect(m_addr:%s, m_port:%d), failed", ret, m_saddr.c_str(), (int)m_nport);
            return ERROR_REDIS_AUTH_FAIL;
        }
        srs_trace("ret:%d = connectAuth(m_spwd:%s)", ret,m_spwd.c_str());
    }

    char cmd[256] = {0};
    sprintf(cmd, "select  %d", m_ndbidx);

    pm_rr = (redisReply*)redisCommand(pm_rct, cmd);
    ret = handleReply();
    srs_info(" pm_rr:%p = (redisReply*)redisCommand(pm_rct:%p, cmd:%s), ret:%d = handleReply()",  pm_rr, pm_rct, cmd, ret);
    return ret;
}

/*
断开redis连接
*/
int CSrsRedisHandler::disConnect()
{
    srs_trace("redis disConnect");
    if(pm_rr)
    {
        freeReplyObject(pm_rr);
        pm_rr = NULL;
    }

    if(pm_rct)
    {
        srs_trace("redis before redisFree\n");
        redisFree(pm_rct);
        srs_trace("redis after redisFree\n");
    }
    return 0;
}

int CSrsRedisHandler::reconnect()
{
    srs_trace("reconnect redis\n");
    std::string vhost = "hls";
    std::string ip = _srs_config->get_vhost_hls_redis_ip(vhost);
    //srs_trace("ip:%s", ip.c_str());
    if(!ip.empty() && m_pRedisHandle)
    {
         disConnect();
        int port = _srs_config->get_vhost_hls_redis_port(vhost);
        std::string pwd = _srs_config->get_vhost_hls_redis_pwd(vhost);
        int index = _srs_config->get_vhost_hls_redis_db_index(vhost);
        LB_ADD_MEM(m_pRedisHandle, sizeof(CSrsRedisHandler));
        int ret = m_pRedisHandle->connect(ip, port, pwd, index);
        if(ret < 0)
        {
            srs_freep(m_pRedisHandle);
            //delete m_pRedisHandle;
            //m_pRedisHandle = NULL;
            srs_error("reconnect to redis ret:%d = connect(%s:%d, pwd:%s, index:%d) failed, ret:%d", ret, ip.c_str(), port, pwd.c_str(), index);
        }
        return ret;
    }
    return -1;
}
/*
添加或插入键值对
key：键，value：值
成功返回ERROR_SUCCESS，失败返回<0
*/
int CSrsRedisHandler::setValue(const string &key, const string &value)
{
    string cmd = "set " + key + " " + value;
    srs_trace("key:%s\n value:%s\n cmd:%s", key.c_str(), value.c_str(), cmd.c_str());
    pm_rr = (redisReply*)redisCommand(pm_rct, cmd.c_str());

    return handleReply();
}

/*
获取键对应的值
key：键，value：值引用
成功返回ERROR_SUCCESS，失败返回<0
*/
int CSrsRedisHandler::getValue(const string &key, string &value)
{
    string cmd = "get " + key;

    pm_rr = (redisReply*)redisCommand(pm_rct, cmd.c_str());

    int ret = handleReply(&value);

    return ret;
}

/*
删除键
key：键
成功返回影响的行数（可能为0），失败返回<0
*/
int CSrsRedisHandler::delKey(const string &key)
{
    string cmd = "del " + key;

    pm_rr = (redisReply*)redisCommand(pm_rct, cmd.c_str());

    int rows = 0;
    int ret = handleReply(&rows);
    if (ret == ERROR_SUCCESS)
        return rows;
    else
        return ret;
}

int CSrsRedisHandler::setHashValue(const string &key, const string& field, const string &value)
{
    string cmd = "hset " + key + " " + field + " " + value;
    pm_rr = (redisReply*)redisCommand(pm_rct, cmd.c_str());
    srs_info("pm_rr:%p = (redisReply*)redisCommand(pm_rct:%p, cmd.c_str():%s)", pm_rr, pm_rct, cmd.c_str());

    return handleReply();
}

/*int CSrsRedisHandler::delHashKey(const string &key)
{
    string cmd = "hdel " + key + " " + field + " " + value;
    pm_rr = (redisReply*)redisCommand(pm_rct, cmd.c_str());
    srs_trace("pm_rr:%p = (redisReply*)redisCommand(pm_rct:%p, cmd.c_str():%s)", pm_rr, pm_rct, cmd.c_str());

    return handleReply();
}*/

int CSrsRedisHandler::setMultiHashValue(const string &key, const map<string, string>& fieldmap)
{
    if(fieldmap.size() <= 0)
    {
        srs_trace("key:%s, fieldmap.size():%d <= 0", key.c_str(), fieldmap.size());
        return 0;
    }

    string cmd = "hmset " + key;
    for(map<string, string>::const_iterator it = fieldmap.begin(); it != fieldmap.end(); it++)
    {
        cmd += " " + it->first + " " + it->second;
        //srs_trace("cmd:%s", cmd.c_str());
    }

    pm_rr = (redisReply*)redisCommand(pm_rct, cmd.c_str());
    srs_info("pm_rr:%p = (redisReply*)redisCommand(pm_rct:%p, cmd.c_str():%s)", pm_rr, pm_rct, cmd.c_str());

    return handleReply();
}

int CSrsRedisHandler::delHashKey(const string &key, const vector<string>& fieldvec)
{
     if(fieldvec.size() <= 0)
    {
        srs_trace("key:%s, fieldvec.size():%d <= 0", key.c_str(), fieldvec.size());
        return 0;
    }

    string cmd = "hdel " + key;
    for(vector<string>::const_iterator it = fieldvec.begin(); it != fieldvec.end(); it++)
    {
        cmd += " " + *it;
        srs_trace("cmd:%s", cmd.c_str());
    }

    pm_rr = (redisReply*)redisCommand(pm_rct, cmd.c_str());
    srs_trace("pm_rr:%p = (redisReply*)redisCommand(pm_rct:%p, cmd.c_str():%s)", pm_rr, pm_rct, cmd.c_str());

    return handleReply();
}

int CSrsRedisHandler::GetMultiHashValue(const string &key, map<string, string>& fieldmap)
{
    if(fieldmap.size() <= 0)
    {
        srs_trace("key:%s, fieldmap.size():%d <= 0", key.c_str(), fieldmap.size());
        return ERROR_SUCCESS;
    }

    string cmd = "hmget " + key;
    for(map<string, string>::iterator it = fieldmap.begin(); it != fieldmap.end(); it++)
    {
        cmd += " " + it->first;
    }

    pm_rr = (redisReply*)redisCommand(pm_rct, cmd.c_str());
    srs_trace("pm_rr:%p = (redisReply*)redisCommand(pm_rct:%p, cmd.c_str():%s)", pm_rr, pm_rct, cmd.c_str());
    if(REDIS_REPLY_ARRAY == pm_rr->type)
    {
        //map<string, string>::iterator it;
        map<string, string>::iterator it = fieldmap.begin();
        for(size_t i = 0; i < pm_rr->elements; i++)
        {
            it->second = pm_rr->element[i]->str;
            it++;
        }
    }

    return pm_rct->err ? -1 : ERROR_SUCCESS;
}
int CSrsRedisHandler::getHashValue(const string &key,  const string& field, string& value)
{
    string cmd = "hget " + key + " " + field;

    pm_rr = (redisReply*)redisCommand(pm_rct, cmd.c_str());

    return handleReply(&value);
}

/*
打印所有键值对到屏幕上
*/
int CSrsRedisHandler::printAll()
{
    string cmd = "keys *";

    pm_rr = (redisReply*)redisCommand(pm_rct, cmd.c_str());

    int len ;
    redisReply **array;
    int ret = handleReply(&len, &array);
    if (ret == ERROR_SUCCESS)
    {
        for (int i = 0; i < len; i++)
            cout << string(array[i]->str) << endl;
    }
    return 0;
}

/*
返回错误信息
*/
string CSrsRedisHandler::getErrorMsg()
{
    return error_msg;
}

/*
使用密码登录
psw：登录密码
成功返回ERROR_SUCCESS，失败返回<0
*/
int CSrsRedisHandler::connectAuth(const string &psw)
{
    string cmd = "auth " + psw;

    pm_rr = (redisReply*)redisCommand(pm_rct, cmd.c_str());

    return handleReply();
}

/*
处理redis返回的信息
value：数据指针，用于保存redis返回的基本类型（value指针指向该数据）
array：数组指针，用于保存redis返回的数组
成功返回ERROR_SUCCESS，失败返回<0
*/
int CSrsRedisHandler::handleReply(void* value, redisReply*** array)
{
    //srs_trace("pm_rct->err:%d", pm_rct->err);
    int ret = 0;
    if (pm_rct->err)
    {
        error_msg = pm_rct->errstr;
        srs_error("pm_rct->err:%d, pm_rct->errstr:%s", pm_rct->err, pm_rct->errstr);
        if(pm_rr)
        {
            freeReplyObject(pm_rr);
            pm_rr = NULL;
        }
        return  ERROR_REDIS_CONTEXT_ERROR;
    }

    if (pm_rr == NULL)
    {
        error_msg = "auth redisReply is NULL";
        if(pm_rr)
        {
            freeReplyObject(pm_rr);
            pm_rr = NULL;
        }
        return ERROR_REDIS_REPLY_ERROR;
    }
    //srs_trace("pm_rr->type:%d", pm_rr->type);
    switch (pm_rr->type)
    {
        case REDIS_REPLY_ERROR:
        {
            error_msg = pm_rr->str;
            ret = ERROR_REDIS_EXE_COMMAND_ERROR;
            srs_error("redis REDIS_REPLY_ERROR, msg:%s", error_msg.c_str());
            break;
        }
        case REDIS_REPLY_STATUS:
        {
            if (!strcmp(pm_rr->str, "OK"))
            {
                ret = ERROR_SUCCESS;
            }
            else
            {
                error_msg = pm_rr->str;
                srs_error("redis REDIS_REPLY_STATUS, msg:%s", pm_rct->err, pm_rct->errstr);
                ret = ERROR_REDIS_EXE_COMMAND_ERROR;
            }
            break;
        }
        case REDIS_REPLY_INTEGER:
        {
            if(value)
            {
                *(int*)value = pm_rr->integer;
            }
            ret = ERROR_SUCCESS;
            break;
        }
        case REDIS_REPLY_STRING:
        {
            if(value)
            {
                *(string*)value = pm_rr->str;
            }
            ret = ERROR_SUCCESS;
            break; 
        }
        case REDIS_REPLY_NIL:
        {
            if(value)
            {
                *(string*)value = "";
            }
            ret = ERROR_SUCCESS;
            break;
        } 
        case REDIS_REPLY_ARRAY:
        {
            if(value)
            {
                *(int*)value = pm_rr->elements;
            }
            if(array)
            {
                *array = pm_rr->element;
            }
            ret = ERROR_SUCCESS;
            break;
        }  
        default:
        {
            error_msg = "unknow reply type";
            ret = ERROR_REDIS_EXE_COMMAND_ERROR;
            srs_error("unknow reply type, msg:%s", pm_rct->err, error_msg.c_str());
            break;
        }
    }

    if(pm_rr)
    {
        freeReplyObject(pm_rr);
        pm_rr = NULL;
    }

    return ret;
}