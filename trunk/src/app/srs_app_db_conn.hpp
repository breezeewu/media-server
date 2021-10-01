#ifndef __SRS_APP_DATABASE_CONNECTION_H__
#define __SRS_APP_DATABASE_CONNECTION_H__

#include <lbsi_database_api.hpp>
#include <srs_app_thread.hpp>
#include <string>
#include <queue>
#include <map>
#include <limits.h>

#define HASH_RTMP_APP_FIELD             "rtmpAppName"
#define HASH_RTMP_STREAM_FIELD          "rtmpStreamName"
#define HASH_RECORD_START_TIME_FIELD    "mediaRecordStartTime"
#define HASH_TIME_ZONE_FIELD            "timeZone"
#define HASH_RTMP_TIGGER_TYPE_FIELD     "tiggerType"
#define HASH_RTMP_SEGMENT_ALARM_TIME    "alarmTime"
#define HASH_RTMP_SEGMENT_DURATION      "duration"
#define HASH_RTMP_SEGMENT_IMG_TIMESTAMP    "imgTimestamp"
#define HASH_RTMP_SERVER_HOST_NAME      "serverHostName"
#define HASH_RTMP_SERVER_PORT           "serverPort"
#define HASH_RTMP_APP_KEY               "appKey"
#define HASH_RTMP_USER_ID               "userId"
//#define HASH_RTMP_APP_KEY               "userId"
#define HASH_RTMP_TIMESTAMP             "timestamp"
#define MIN_SQL_CMD_SIZE 1000
#define MAX_SQL_CMD_SIZE INT_MAX
using namespace std;


class database_connection:public internal::ISrsThreadHandler
{
protected:
    idatabase_api*              m_ppdbapi;
    internal::SrsThread*        m_pst_thread;

    queue<string>               m_qcmd_list;

    bool                        m_bconnected;

    bool                        m_benable;
    bool                        m_btransaction;
    int                         m_ndb_type;
    int                         m_ndb_port;
    int                         m_ndb_index;
    int                         m_nexpire_time;

    string                      m_sdb_ip;
    string                      m_suser_name;
    string                      m_sdb_pwd;
    string                      m_sdb_name;

    char*                       m_pkey;
    char*                       m_pvhost;
    char*                       m_psub_host;

    int                         m_nmax_sql_cmd_size;
    
   
public:
    database_connection();
    ~database_connection();

    virtual int init(idatabase_api* pdbapi);

    virtual int connect_database_from_config(const char* pkey, const char*  pvhost, const char*  psub_host = NULL);

    //virtual int connect_database_from_config(const char* pkey, const char*  pvhost, const char*  psub_host = NULL);

    virtual int send_command(string cmd_str);

    virtual int exe_command(string cmd_str);

     virtual int start();

    virtual void stop();

    virtual void on_thread_start();

    virtual int cycle();

    virtual void on_thread_stop();

    virtual int reconnect();

    void flush_namesapce(const char* pnamespace);

    virtual int get_host_by_devicesn(const string& devicesn, string& host, int& port);

protected:
    virtual int connect();

    virtual void close();
};

class database_connection_manager
{
protected:
    database_connection_manager();
    
    static database_connection_manager*                 m_pdb_conn_mgr;
    map<string, database_connection*>                   m_mconn_list;
    std::string                                         m_slocal_ip;

public:
    static database_connection_manager* get_inst(const char* plocal_host =  NULL);
    static void destroy_inst();

    ~database_connection_manager();

    int connect_database_from_config(const char* pkey, const char*  pvhost, const char*  psub_host);

    int remove_database(const std::string& key);

    bool exist_database(const std::string& key);

    int send_command(const std::string& key, string cmd_str);

    int exe_command(const std::string& key, string cmd_str);

    int get_host_by_devicesn(const std::string& key, const string& devicesn, string& host, int& port);

    void flush_namespace(const std::string& key, const char* pnamespace);
};
#endif