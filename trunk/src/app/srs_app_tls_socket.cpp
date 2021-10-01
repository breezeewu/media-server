/*
The MIT License (MIT)

Copyright (c) 2013-2015 SRS(ossrs)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <srs_app_tls_socket.hpp>
#include <srs_app_config.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_kernel_utility.hpp>
// srs rtsp 
#define SRS_RTSP_SERVER_CERTIFY          "./ssl_crt/rtsp/server.crt"
#define SRS_RTSP_SERVER_KEY              "./ssl_crt/rtsp/server.key"
#define SRS_RTSP_SERVER_ROOT_CERTIFY     "./ssl_crt/rtsp/ca.crt"
#define SRS_RTSP_SERVER_TLS_CIPHER       "lazy"
SrsSSLSocket::SrsSSLSocket(st_netfd_t client_stfd):SrsStSocket(client_stfd)
{
#if 1
    m_ptls_skt = new CTLSSocket();
    int ret = m_ptls_skt->init_cert(TLS_SERVER_VERSION_V1_2, SRS_RTSP_SERVER_CERTIFY, SRS_RTSP_SERVER_KEY, SRS_RTSP_SERVER_TLS_CIPHER);
    srs_rtsp_debug("ret:%d = m_pssl_skt->init_cert(TLS_SERVER_VERSION_V1_2:%d, %s, %s, %s)\n", ret, TLS_SERVER_VERSION_V1_2, SRS_RTSP_SERVER_CERTIFY, SRS_RTSP_SERVER_KEY, SRS_RTSP_SERVER_TLS_CIPHER);
    assert(0 == ret);
    if(st_netfd_poll(stfd, POLLIN, recv_timeout) < 0)
    {
        srs_error("st_netfd_poll(stfd, POLLIN, recv_timeout:%"PRId64") accept failed\n", recv_timeout);
        return ;
    }
    m_ptcp_skt = m_ptls_skt->accept(st_netfd_fileno(client_stfd));
    srs_rtsp_debug(" m_ptcp_skt:%p = m_pssl_skt->accept(st_netfd_fileno(client_stfd))\n", m_ptcp_skt);
#else
    m_ptcp_skt = new CTCPSocket();
    m_ptcp_skt->init_socket(st_netfd_fileno(client_stfd));
#endif
    assert(m_ptcp_skt);
    //SRS_CHECK_RESULT(ret);
}

SrsSSLSocket::~SrsSSLSocket()
{
}

int SrsSSLSocket::read(void* buf, size_t size, ssize_t* nread)
{
    SRS_CHECK_PARAM_PTR(m_ptcp_skt, -1);
    if(nread)
    {
        *nread = 0;
    }

    /*if(st_netfd_poll(stfd, POLLIN, recv_timeout) < 0)
    {
        srs_error("st_netfd_poll(stfd, POLLIN, recv_timeout:%"PRId64") read(buf:%p, size:%ld) failed\n", recv_timeout, buf, size);
        return -1;
    }*/
    int ret = m_ptcp_skt->read((char*)buf, size);
    srs_rtsp_debug("ret:%d = m_ptcp_skt->read(buf:%p, size:%ld)\n", ret, buf, size);
    if(ret <= 0)
    {
        srs_error("ret:%d = m_ptcp_skt->read(buf:%p, size:%d) faied\n", ret, buf, size);
        return ret;
    }

    if(nread)
    {
        *nread = ret;
    }

    
    recv_bytes += ret;
    return ERROR_SUCCESS;
}

int SrsSSLSocket::read_fully(void* buf, size_t size, ssize_t* nread)
{
    size_t pos = 0;
    size_t ret = 0;
    while(pos < size)
    {
        ssize_t nbread = 0;
        ret = read((char*)buf + pos, size - pos, &nbread);
        if(ret < 0)
        {
            srs_error("ret:%d = read(buf:%p + pos:%d, size:%ld - pos:%d, &nbread:%"PRId64") failed\n", ret, buf, pos, size - pos, nbread);
            return -1;
        }
        pos += nbread;
    };
    
    return ret;
}

int SrsSSLSocket::write(void* buf, size_t size, ssize_t* nwrite)
{
    SRS_CHECK_PARAM_PTR(m_ptcp_skt, -1);
    if(nwrite)
    {
        *nwrite = 0;
    }
    size_t pos = 0;
    while(pos < size)
    {
        int nb_write = m_ptcp_skt->write((char*)buf, size);
        srs_rtsp_debug("nb_write:%d = m_ptcp_skt->write(buf:%p, size:%ld)\n", nb_write, buf, size);
        if(nb_write <= 0)
        {
            srs_error("nb_write:%d = m_ptcp_skt->write(buf:%p, size:%d) faied\n", nb_write, buf, size);
            return nb_write;
        }

       

        if(st_netfd_poll(stfd, POLLOUT, send_timeout) < 0)
        {
            srs_error("st_netfd_poll(stfd, POLLOUT, send_timeout:%"PRId64") write(buf:%p, size:%ld) failed\n", send_timeout, buf, size);
            return -1;
        }
        pos += nb_write;
        send_bytes += nb_write;
    }

    if(nwrite)
    {
        *nwrite = pos;
    }

    return ERROR_SUCCESS;
}

int SrsSSLSocket::writev(const iovec *iov, int iov_size, ssize_t* nwrite)
{
    int ret = ERROR_SUCCESS;
   for(int i = 0; i < iov_size; i++)
   {
       ssize_t nb_write = 0;
       int writed = write(iov[i].iov_base, iov[i].iov_len, &nb_write);
       if(writed < 0)
       {
           return writed;
       }
   }
    
    return ret;
}
