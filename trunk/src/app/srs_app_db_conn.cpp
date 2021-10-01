#include <srs_app_db_conn.hpp>
#include <lbsp_database_mysql.hpp>
#include <lbsp_database_redis.hpp>
#include <srs_app_config.hpp>
#include <srs_app_log.hpp>
#include <lbsp_utility_string.hpp>
#include <cstdlib>

using namespace lbsp_util;

//std::string g_local_ip;
database_connection::database_connection()
{
    m_ppdbapi = NULL;
    m_pst_thread = NULL;

    m_benable       =  false;
    m_ndb_type      =  -1;
    m_ndb_port      = 0;
    m_ndb_index     = -1;
    m_nexpire_time  = 1800;
    m_bconnected    = false;
    m_btransaction  = true;

    m_pkey          = NULL;
    m_pvhost        = NULL;
    m_psub_host     = NULL;

    m_nmax_sql_cmd_size = 20000;
}

database_connection::~database_connection()
{
    close();

    srs_freepa(m_pkey);
    srs_freepa(m_pvhost);
    srs_freepa(m_psub_host);
}

int database_connection::init(idatabase_api* pdbapi)
{
    m_ppdbapi = pdbapi;

    return m_ppdbapi ? 0 : -1;
}

int database_connection::connect_database_from_config(const char* pkey, const char*  pvhost, const char*  psub_host)
{
    int ret = 0;
    if(pkey != m_pkey)
    {
        srs_freepa(m_pkey);
        //delete[] m_pkey;
        //m_pkey = NULL;
        if(pkey)
        {
            m_pkey = new char[strlen(pkey)+1];
            LB_ADD_MEM(m_pkey, strlen(pkey)+1);
            strcpy(m_pkey, pkey);
        }

    }

    if(m_pvhost != pvhost)
    {
        srs_freepa(m_pvhost);
        //delete[] m_pvhost;
        //m_pvhost = NULL;
        if(pvhost)
        {
            m_pvhost = new char[strlen(pvhost)+1];
            LB_ADD_MEM(m_pvhost, strlen(pvhost)+1);
            strcpy(m_pvhost, pvhost);
        }

    }

    if(m_psub_host != psub_host)
    {
        srs_freepa(m_psub_host);
        //delete[] m_psub_host;
        //m_psub_host = NULL;
        if(psub_host)
        {
            m_psub_host = new char[strlen(psub_host)+1];
            LB_ADD_MEM(m_psub_host, strlen(psub_host)+1);
            strcpy(m_psub_host, psub_host);
        }

    }

    SrsConfDirective* pconf = _srs_config->get_vhost_config(m_pkey, m_pvhost, m_psub_host);
    //srs_rtsp_debug("pconf:%p = _srs_config->get_vhost_config\n", pconf);
    if(NULL == pconf)
    {
        srs_error("pconf:%p = get_vhost_config(pkey:%s, pvhost:%s, psub_host:%s) failed\n", pconf, pkey, pvhost, psub_host);
        return 1;
    }

    m_benable = _srs_config->get_bool_frome_conf(pconf, "enabled", false);
    if(!m_benable)
    {
        srs_error("database %s is disable, open failed\n", pkey);
        return 1;
    }
    m_nmax_sql_cmd_size = _srs_config->get_int_frome_conf(pconf, "max_sql_cmd_size", m_nmax_sql_cmd_size);
    if(m_nmax_sql_cmd_size < MIN_SQL_CMD_SIZE)
    {
        m_nmax_sql_cmd_size = MIN_SQL_CMD_SIZE;
    }
    else if(m_nmax_sql_cmd_size > MAX_SQL_CMD_SIZE)
    {
        m_nmax_sql_cmd_size = MAX_SQL_CMD_SIZE;
    }
    
    m_ndb_type = _srs_config->get_int_frome_conf(pconf, "database_type", m_ndb_type);
    m_sdb_ip = _srs_config->get_string_frome_conf(pconf, "database_ip", "127.0.0.1");
    m_suser_name = _srs_config->get_string_frome_conf(pconf, "database_user_name", NULL);
    m_sdb_pwd = _srs_config->get_string_frome_conf(pconf, "database_pwd", NULL);
    m_nexpire_time = _srs_config->get_int_frome_conf(pconf, "expire_time", -1);
    m_btransaction = _srs_config->get_bool_frome_conf(pconf, "transaction", m_btransaction);
    
    if(DATABASE_TYPE_REDIS == m_ndb_type)
    {
        m_ndb_port = DATABASE_REDIS_DEFAULT_PORT;
        m_ndb_index = _srs_config->get_int_frome_conf(pconf, "database_name", m_ndb_index);
    }
    else if(DATABASE_TYPE_MYSQL == m_ndb_type)
    {
        m_ndb_port = DATABASE_MYSQL_DEFAULT_PORT;
        m_sdb_name = _srs_config->get_string_frome_conf(pconf, "database_name", NULL);
    }
    else
    {
        srs_error("Invalid m_ndb_type %d\n", m_ndb_type);
        return -1;
    }
    
    m_ndb_port = _srs_config->get_int_frome_conf(pconf, "database_port", m_ndb_port);
    srs_rtsp_debug("m_ndb_type:%d, m_sdb_ip:%s, m_suser_name:%s, m_sdb_pwd:%s, m_nexpire_time:%d, m_btransaction:%d, m_ndb_index:%d, m_sdb_name:%s, m_ndb_port:%d, m_nmax_sql_cmd_size:%d\n", 
    m_ndb_type, m_sdb_ip.c_str(), m_suser_name.c_str(), m_sdb_pwd.c_str(), m_nexpire_time, (int)m_btransaction, m_ndb_index, m_sdb_name.c_str(), m_ndb_port, m_nmax_sql_cmd_size);
    return ret;
}

int database_connection::send_command(string cmd_str)
{
    if(m_qcmd_list.size() > m_nmax_sql_cmd_size)
    {
        lberror("database command string is full %d\n", m_qcmd_list.size());
        return -1;
    }

    m_qcmd_list.push(cmd_str);

    return 0;
}

int database_connection::exe_command(string cmd_str)
{
    int ret = -1;
    bool breconn = false;
    //srs_debug("exe_command(cmd:%s), m_ppdbapi:%p\n", cmd_str.c_str(), m_ppdbapi);
    while(m_ppdbapi)
    {
        ret = m_ppdbapi->command(cmd_str.c_str());
        //srs_debug("ret:%d = m_ppdbapi->command(cmd_str:%s)\n", ret, cmd_str.c_str());
        if(0 != ret && !breconn)
        {
            srs_error("ret:%d = m_ppdbapi->command(cmd_str:%s)\n",ret, cmd_str.c_str());
            breconn = true;
            ret = reconnect();
        }
        else
        {
            break;
        }
        
    };

    return ret;
}

int database_connection::start()
{
    if(NULL == m_pst_thread)
    {
        m_pst_thread = new internal::SrsThread("database", this, 100000, true);
        LB_ADD_MEM(m_pst_thread, sizeof(internal::SrsThread));
    }
    int ret = connect();
    //srs_trace("ret:%d = connect()\n", ret);
    SRS_CHECK_RESULT(ret);

    ret = m_pst_thread->start();

    return ret;
}

void database_connection::stop()
{
    if(m_pst_thread)
    {
        m_pst_thread->stop();
    }
    srs_freep(m_pst_thread);
    //close();
}

void database_connection::on_thread_start()
{

}

int database_connection::cycle()
{
    int ret = 0;
    int num = 0;
    if(!m_bconnected)
    {
        srs_error("database %d not connect, failed\n", m_ndb_type);
        sleep(1);
        ret = reconnect();
        return ret;
    }
    
    while(m_qcmd_list.size() > 0)
    {
        bool transaction = m_qcmd_list.size() >  1 ? m_btransaction : false;
        if(transaction)
        {
            ret = m_ppdbapi->start_transaction();
            if(0 != ret)
            {
                srs_error("ret:%d = m_ppdbapi->start_transaction() failed\n", ret);
                break;
            }
        }
        
        while(m_ppdbapi && m_qcmd_list.size() > 0)
        {
            string cmd_str = m_qcmd_list.front();
            ret = m_ppdbapi->command(cmd_str.c_str());
            srs_debug("ret:%d = m_ppdbapi->command(%s)\n", ret, cmd_str.c_str());
            if(0 != ret)
            {
                if(0 == num++ % 10)
                {
                    srs_error("ret:%d = m_ppdbapi->command(cmd_Str:%s)\n", ret, cmd_str.c_str());
                    break;
                }
                else
                {
                    st_usleep(100000);
                    break;
                }
            }
            m_qcmd_list.pop();
            num = 0;
        }

        if(num >= 10 && 0 != ret)
        {
            //srs_error("ret:%d = try command %s failed for %d times\n", ret, cmd_str.c_str(), num);
            break;
        }

        if(transaction)
        {
            ret = m_ppdbapi->commit_transaction();
            if(0 != ret)
            {
                srs_error("ret:%d = m_ppdbapi->commit_transaction() failed\n", ret);
                break;
            }
        }
        
    };
    
    if(ret != 0)
    {
        ret = reconnect();
        //srs_warn("ret:%d = reconnect()\n", ret);
    }
    return ret;
}

void database_connection::on_thread_stop()
{
    
}

int database_connection::reconnect()
{
    int ret = 0;
    if(m_ppdbapi)
    {
        m_ppdbapi->close();
        srs_freep(m_ppdbapi);

    }
    ret = connect_database_from_config(m_pkey, m_pvhost, m_psub_host);
    SRS_CHECK_RESULT(ret);

    ret = connect();
    SRS_CHECK_RESULT(ret);
    return ret;
}

void database_connection::flush_namesapce(const char* pnamespace)
{
    if(0 == m_ndb_type && m_ppdbapi)
    {
        IRedisDatabaseAPI* predisdb = dynamic_cast<IRedisDatabaseAPI*>(m_ppdbapi);
        //srs_trace("predisdb:%p = dynamic_cast<IRedisDatabaseAPI*>(m_ppdbapi:%p)\n", predisdb, m_ppdbapi);
        if(predisdb)
        {
            predisdb->flush_namespace(pnamespace);
        }
    }
    else
    {
        srs_error("Invalid db type %d or db not connect, m_ppdbapi:%p\n", m_ndb_type, m_ppdbapi);
    }
}

int database_connection::connect()
{
    int ret = -1;
    if(DATABASE_TYPE_REDIS == m_ndb_type)
    {
        m_ppdbapi = new redis_database(m_ndb_index, m_nexpire_time);
        LB_ADD_MEM(m_ppdbapi, sizeof(redis_database));
        //srs_rtsp_debug("m_ppdbapi:%p = new redis_database(m_ndb_index:%d, m_nexpire_time:%d)\n", m_ppdbapi, m_ndb_index, m_nexpire_time);
    }
    else if(DATABASE_TYPE_MYSQL == m_ndb_type)
    {
        m_ppdbapi = new mysql_database(m_suser_name.c_str(), m_sdb_name.c_str());
        LB_ADD_MEM(m_ppdbapi, sizeof(mysql_database));
        //srs_rtsp_debug("m_ppdbapi:%p = new mysql_database(m_suser_name.c_str():%s, m_sdb_name.c_str():%s)\n", m_ppdbapi, m_suser_name.c_str(), m_sdb_name.c_str());
    }
    else
    {
        lberror("Not support database type %d\n", m_ndb_type);
        return -1;
    }
    
    
    ret = m_ppdbapi->connect(m_sdb_ip.c_str(), m_ndb_port, m_sdb_pwd.c_str());
    if(ret == 0)
    {
        m_bconnected = true;
    }
    else
    {
        srs_error("ret:%d = m_ppdbapi->connect(m_sdb_ip.c_str():%s, m_ndb_port:%d, m_sdb_pwd.c_str():%s) failed\n", ret, m_sdb_ip.c_str(), m_ndb_port, m_sdb_pwd.c_str());
    }
    
    return ret;
}

void database_connection::close()
{
    stop();
    if(m_ppdbapi)
    {
        m_ppdbapi->close();
        srs_trace("database_connection::close() m_ppdbapi:%p\n", m_ppdbapi);
        srs_freep(m_ppdbapi);
        //m_ppdbapi = NULL;
    }
}

int database_connection::get_host_by_devicesn(const string& devicesn, string& host, int& port)
{
    if(0 == m_ndb_type && m_ppdbapi)
    {
        int ret = -1;
        string query_cmd = "keys *:" + devicesn;
        string value;
        IRedisDatabaseAPI* predisdb = dynamic_cast<IRedisDatabaseAPI*>(m_ppdbapi);
        //srs_trace("predisdb:%p = dynamic_cast<IRedisDatabaseAPI*>(m_ppdbapi:%p)\n", predisdb, m_ppdbapi);
        if(predisdb)
        {
            ret = predisdb->query_string_value(query_cmd.c_str(), value);
            //ret = predisdb->query_string_value(query_cmd.c_str(), value);
            if(0 == ret && !value.empty())
            {
                vector<string> keylist = string_splits(value, ";");
                if(keylist.size() == 3)
                {
                    host = keylist[0];
                    port = atoi(keylist[1].c_str());
                    lbtrace("host:%s, port:%d, devicesn:%s\n", host.c_str(), port, keylist[2].c_str());
                    return 0;
                }
            }
        }
        lberror("get_host_by_devicesn failed, predisdb:%p,  ret:%d, ", predisdb, ret, value.c_str());
        return -1;
    }
    else
    {
        srs_error("Invalid db type %d or db not connect, m_ppdbapi:%p\n", m_ndb_type, m_ppdbapi);
    }
    return -1;
}

database_connection_manager* database_connection_manager::m_pdb_conn_mgr(NULL);

database_connection_manager::database_connection_manager()
{

}

database_connection_manager* database_connection_manager::get_inst(const char* plocal_host)
{
    if(NULL == m_pdb_conn_mgr)
    {
        //asser(plocal_host);
        m_pdb_conn_mgr = new database_connection_manager();
        srs_trace("create database_connection_manager, plocal_host:%p, m_pdb_conn_mgr:%p\n", plocal_host, m_pdb_conn_mgr);
        if(plocal_host)
        {
            m_pdb_conn_mgr->m_slocal_ip = plocal_host;
        }

        LB_ADD_MEM(m_pdb_conn_mgr, sizeof(database_connection_manager));
    }

    return m_pdb_conn_mgr;
}

void database_connection_manager::destroy_inst()
{
    if(m_pdb_conn_mgr)
    {
        srs_debug("srs_freep(m_pdb_conn_mgr:%p)\n", m_pdb_conn_mgr);
        srs_freep(m_pdb_conn_mgr);
        //m_pdb_conn_mgr = NULL;
    }
   
}

database_connection_manager::~database_connection_manager()
{
    for(map<string, database_connection*>::iterator it = m_mconn_list.begin(); it != m_mconn_list.end(); it++)
    {
        if(!m_slocal_ip.empty())
        {
            it->second->flush_namesapce(m_slocal_ip.c_str());
        }
        srs_freep(it->second);
    }
    m_mconn_list.clear();
}

int database_connection_manager::connect_database_from_config(const char* pkey, const char*  pvhost, const char*  psub_host)
{
    //srs_rtsp_debug("connect_database_from_config(pkey:%s, pvhost:%s, psub_host:%s), m_mconn_list.size():%ld, this:%p\n", pkey, pvhost, psub_host, m_mconn_list.size(), this);
    int ret = 0;
    std::string key = pkey;
    database_connection* pdb_conn = NULL;
    do
    {
        if(m_mconn_list.end() != m_mconn_list.find(key))
        {
            //srs_rtsp_debug("database %s connection has already exist\n", pkey);
            return 0;
        }
        pdb_conn = new database_connection();
        LB_ADD_MEM(pdb_conn, sizeof(database_connection));
        ret = pdb_conn->connect_database_from_config(pkey, pvhost, psub_host);
        srs_trace("ret:%d = pdb_conn->connect_database_from_config(pkey:%s, pvhost:%s, psub_host:%s)\n", ret, pkey, pvhost, psub_host);
        if(0 == ret)
        {
            ret = pdb_conn->start();
            srs_debug("ret:%d = pdb_conn->start()\n", ret);
            SRS_BREAK_RESULT(ret);
            m_mconn_list[key] = pdb_conn;
            srs_debug("m_mconn_list[pkey:%s] = pdb_conn:%s, m_mconn_list.size():%ld\n", key.c_str(), pdb_conn, m_mconn_list.size());
        }
        else
        {
            srs_error("ret:%d = pdb_conn->connect_database_from_config(pkey:%s, pvhost:%s, psub_host:%s)\n", ret, pkey, pvhost, psub_host);
        }
        
    } while (0);
    
    if(0 != ret)
    {
        srs_freep(pdb_conn);
        //pdb_conn = NULL;
    }
    return ret;
}

int database_connection_manager::remove_database(const std::string& key)
{
    map<string, database_connection*>::iterator it = m_mconn_list.find(key);
    if(m_mconn_list.end() != it)
    {
        it->second->stop();
        srs_freep(it->second);
        //it->second = NULL;
        m_mconn_list.erase(it);
        srs_warn("remove database %s from database connection manager\n", key.c_str());
        return 0;
    }

    return -1;
}

bool database_connection_manager::exist_database(const std::string& key)
{
    map<string, database_connection*>::iterator it = m_mconn_list.find(key);
    if(m_mconn_list.end() != it)
    {
        return true;
    }

    return false;
}

int database_connection_manager::send_command(const std::string& key, string cmd_str)
{
    map<string, database_connection*>::iterator it = m_mconn_list.find(key);
    if(m_mconn_list.end() != it)
    {
        int ret = it->second->send_command(cmd_str);
        return ret;
    }

    return -1;
}

int database_connection_manager::exe_command(const std::string& key, string cmd_str)
{
    //srs_debug("exe_command(key:%s, cmd:%s)\n", key.c_str(), cmd_str.c_str());
    map<string, database_connection*>::iterator it = m_mconn_list.find(key);
    if(m_mconn_list.end() != it)
    {
        int ret = it->second->exe_command(cmd_str);
        return ret;
    }

    return -1;
}

int database_connection_manager::get_host_by_devicesn(const std::string& key, const string& devicesn, string& host, int& port)
{
    map<string, database_connection*>::iterator it = m_mconn_list.find(key);
    if(m_mconn_list.end() != it)
    {
        int ret = it->second->get_host_by_devicesn(devicesn, host, port);
        return ret;
    }

    return -1;
}

void database_connection_manager::flush_namespace(const std::string& key, const char* pnamespace)
{
    srs_trace("flush_namespace(pkey:%s, pnamespace:%s, len:%d)\n", key.c_str(), pnamespace, strlen(pnamespace));
    map<string, database_connection*>::iterator it = m_mconn_list.find(key);
    if(m_mconn_list.end() != it && strlen(pnamespace) > 0)
    {
        it->second->flush_namesapce(pnamespace);
    }
}
