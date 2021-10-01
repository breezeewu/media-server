#pragma once
#include <string>
#include <algorithm>
#include <map>
#include <vector>
#include <stdarg.h>
#include <srs_kernel_log.hpp>
using namespace std;
#define LOG_MAX_SIZE 4096
namespace lbsp_util
{
    static string string_format(const char* fmt, ...)
    {
        char str_buf[LOG_MAX_SIZE] = {0};
        int size = 0;
        va_list ap;
        va_start(ap, fmt);
        size += vsnprintf(str_buf + size, LOG_MAX_SIZE - size, fmt, ap);
        va_end(ap);

        return string(str_buf);
    }

    static int string_split(string& path, string& attr, const char* ptag)
    {
        //srs_trace("path:%s, sttr:%s, ptag:%s\n", path.c_str(), attr.c_str(), ptag);
        if(path.empty() || NULL == ptag)
        {
            srs_error("Invalid path:%s or ptag:%p\n", path.c_str(), ptag);
            return -1;
        }
        attr.clear();
        size_t pos = path.find_first_of(ptag, 0);
        if(0 == pos)
        {
            return 0;
        }
        else if(string::npos == pos)
        {
            attr = path;
            path.clear();
            
            return 0;
        }
        attr = path.substr(0, pos);
        path = path.substr(pos + strlen(ptag));
        //lbdebug("url split path:%s split:%s, ptag:%s\n", path.c_str(), attr.c_str(), ptag);
        return 0;
    }

    static vector<string> string_splits(string str, string splt)
    {
        vector<string> strlist;
        while(!str.empty())
        {
            size_t pos = str.find(splt);
            if(pos != std::string::npos)
            {

                strlist.push_back(str.substr(0, pos));
                str = str.substr(pos + splt.length());
            }
            else
            {
                strlist.push_back(str);
                str.clear();
            }
        }

        return strlist;
    }
    static map<string, string> read_key_value_pair(string str, string splt, string tag)
    {
        map<string, string> key_val_pair;
        while(!str.empty())
        {
            string key, value;
            int ret = string_split(str, value, splt.c_str());
            if(ret < 0)
            {
                assert(0);
                return key_val_pair;
            }
            ret = string_split(value, key, tag.c_str());
            if(ret < 0)
            {
                assert(0);
                return key_val_pair;
            }
            srs_rtsp_debug("str:%s, key:%s, value:%s", str.c_str(), key.c_str(), value.c_str());
            key_val_pair[key] = value;
        };
        return key_val_pair;
    }

    static bool parser_value_from_http_param(string param, string token, string& value)
    {
        map<string, string> pair_list = read_key_value_pair(param, "&", "=");
        for(map<string, string>::iterator it = pair_list.begin(); it != pair_list.end(); it++)
        {
            if(token == it->first)
            {
                value = it->second;
                return true;
            }
        }

        return false;
    }
    static string left_trim(string str, string tag)
    {
        while(!str.empty())
        {
            if(str.length() >= tag.length() && 0 == memcmp(str.c_str(), tag.c_str(), tag.length()))
            {
                str = str.substr(tag.length());
            }
            else
            {
                break;
            }
        }
        return str;
    }
    static string right_trim(string str, string tag)
    {
        while(!str.empty())
        {
            if(str.length() >= tag.length() && 0 == memcmp(str.c_str() + str.length() - tag.length(), tag.c_str(), tag.length()))
            {
                str = str.substr(0, str.length() - tag.length());
            }
            else
            {
                break;
            }
        }
        return str;
    }

    static string string_trim(string str, string tag)
    {
        str = left_trim(str, tag);
        str = right_trim(str, tag);
        return str;
        /*size_t pos1 = str.find_first_not_of(tag);
        size_t pos2 = str.find_last_of(tag);
        pos1 = pos1 == string::npos ? 0 : pos1;
        pos2 = pos2 == string::npos ? str.length() : pos2;

        std::string trim_str =  str.substr(pos1, pos2);
        srs_trace("trim_str:%s =  str.substr(pos1:%d, pos2:%d), tag:%s\n", trim_str.c_str(), ptag.c_str());
        return trim_str;*/
    }

    static string to_string(int64_t val)
    {
        char str_buf[256] = {0};
        sprintf(str_buf, "%"PRId64"", val);

        return string(str_buf);
    }

   static string to_lower(const string& str)
   {
       string lower;
       lower.resize(str.size());
       transform(str.begin(), str.end(), lower.begin(), ::tolower);

       return lower;
   }

   static string to_upper(const string& str)
   {
       string upper;
       upper.resize(str.size());
       transform(str.begin(), str.end(), upper.begin(), ::toupper);

       return upper;
   }
}