#pragma once
#include <string>
#include <sys/time.h>
#include <openssl/md5.h>


namespace lbsp_util
{
    class CMD5Maker
    {
    public:
        static std::string gen_md5_by_string(const char* pstr, int len)
        {
            std::string str;
            str.append(pstr, len);
            return gen_md5_by_string(str);
        }

        static std::string gen_md5_by_string(const std::string& str)
        {
            char out_buf[33] = {0};
            unsigned char md5_enc[16] = {0};
            MD5_CTX     md5_ctx;
            MD5_Init(&md5_ctx);
            MD5_Update(&md5_ctx, str.c_str(), str.length());
            MD5_Final(md5_enc, &md5_ctx);
            for(int i = 0; i < 16; i++)
            {
                sprintf(out_buf + i*2, "%02x", md5_enc[i]);
            }

            return std::string(out_buf);
        }


        static std::string  gen_md5_by_time()
        {
            struct  timeval tv;
            gettimeofday(&tv, NULL);
            return gen_md5_by_string((const char*)&tv, sizeof(tv));
        }
    };
};
