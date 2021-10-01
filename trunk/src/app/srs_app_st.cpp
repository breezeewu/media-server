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

#include <srs_app_st.hpp>
#include <srs_app_config.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_kernel_utility.hpp>
#define RETRY_NUM 10
SrsStSocket::SrsStSocket(st_netfd_t client_stfd)
{
    stfd = client_stfd;
    send_timeout = recv_timeout = ST_UTIME_NO_TIMEOUT;
    recv_bytes = send_bytes = 0;
#ifdef WRITE_RTMP_DATA_ENABLE
    // add by dawson, read recv data path from config file
    precvfile = NULL;
    std::string pathpartten = _srs_config->get_rtmp_recv_data_write_path();
    srs_trace("pathpartten:%s = _srs_config->get_rtmp_recv_data_write_path()", pathpartten.c_str());
    if(!pathpartten.empty())
    {
        std::string datetime = generate_datetime();
        recvpath = srs_string_replace(pathpartten, "[date]", datetime);
        srs_trace("recvpath:%s = srs_string_replace(pathpartten:%s, [date], datetime:%s)", recvpath.c_str(), pathpartten.c_str(), datetime.c_str());
        precvfile = create_write_data_file(recvpath);
        srs_trace("precvfile:%p = create_write_data_file(recvpath:%s)", precvfile, recvpath.c_str());
    }
    // add end
#endif

#ifdef WRITE_RTMP_DATA_FILE
    psktdatafile = NULL;
    if(_srs_config && !_srs_config->get_rtmp_recv_data_write_path().empty())
    {
        sktdatapath = _srs_config->get_rtmp_recv_data_write_path();
        psktdatafile = create_write_data_file(sktdatapath);
        srs_trace("psktdatafile:%p = create_write_data_file(sktdatapath:%s)", psktdatafile, sktdatapath.c_str());
    }
#endif
#ifdef WRITE_ST_SOCKET_WRITE_DATA
    m_pwrite_file = NULL;
#endif
}

SrsStSocket::~SrsStSocket()
{
#ifdef WRITE_RTMP_DATA_ENABLE
    if(precvfile)
    {
        srs_trace("fclose(precvfile:%p)", precvfile);
        close_write_data_file(precvfile, recvpath.c_str(), 1024);
        recvpath.clear();
        precvfile = NULL;
    }
#endif

#ifdef WRITE_RTMP_DATA_FILE
    if(psktdatafile)
    {
        close_write_data_file(psktdatafile, sktdatapath.c_str(), 1024);
        srs_trace("close_write_data_file(psktdatafile:%p, sktdatapath:%s)", psktdatafile, sktdatapath.c_str());
    }
#endif

#ifdef WRITE_ST_SOCKET_WRITE_DATA
    if(m_pwrite_file)
    {
        fclose(m_pwrite_file);
        m_pwrite_file = NULL;
    }
#endif
}

bool SrsStSocket::is_never_timeout(int64_t timeout_us)
{
    return timeout_us == (int64_t)ST_UTIME_NO_TIMEOUT;
}

void SrsStSocket::set_recv_timeout(int64_t timeout_us)
{
    recv_timeout = timeout_us;
}

int64_t SrsStSocket::get_recv_timeout()
{
    return recv_timeout;
}

void SrsStSocket::set_send_timeout(int64_t timeout_us)
{
    send_timeout = timeout_us;
}

int64_t SrsStSocket::get_send_timeout()
{
    return send_timeout;
}

int64_t SrsStSocket::get_recv_bytes()
{
    return recv_bytes;
}

int64_t SrsStSocket::get_send_bytes()
{
    return send_bytes;
}

int SrsStSocket::get_fd()
{
    return st_netfd_fileno(stfd);
}

bool SrsStSocket::is_readable()
{
    int ret = st_netfd_poll(stfd, POLLIN, 0);
    //srs_rtsp_debug("ret:%d = st_netfd_poll(stfd:%p, POLLIN, 0)\n", ret, stfd);
    return 0 == ret;
}

int SrsStSocket::read(void* buf, size_t size, ssize_t* nread)
{
    int ret = ERROR_SUCCESS;
    srs_verbose("%s(buf:%p, size:%"PRId64", nread:%p) begin", __FUNCTION__, buf, size, nread);
    ssize_t nb_read = st_read(stfd, buf, size, recv_timeout);
    srs_verbose("%s nb_read:%d = st_read(stfd:%p, buf:%p, size:%"PRId64", recv_timeout:%"PRId64")", __FUNCTION__, nb_read, stfd, buf, size, recv_timeout);
        // add by dawson for write recv rtmp data
#ifdef WRITE_RTMP_DATA_ENABLE
        srs_info("nb_read:%d = st_read(stfd, buf, size:%d, recv_timeout), pfile:%p", nb_read, size, pfile);
        /*if(NULL == pfile  && nb_read > 0)
        {
            timeval tv;
            if (gettimeofday(&tv, NULL) == -1) {
                //return false;
            }
            char recvdata[256] = {0};
            sprintf(recvdata, "./objs/nginx/html/rtmp/recv%d%3d.data", (int)(tv.tv_sec), (int)(tv.tv_usec / 1000));
            pfile = fopen(recvdata, "wb");
            srs_trace("pfile:%p = fopen(recvdata:%s, wb)", pfile, recvdata);
        }*/
        if(nb_read > 0 && precvfile)
        {
            int writed = fwrite(buf, 1, nb_read, precvfile);
            srs_info("writed:%d = fwrite(buf:%p, 1, nb_read:%d, precvfile:%p), curpos:%0x", writed, buf, nb_read, precvfile, ftell(precvfile));
        }
#endif
#ifdef WRITE_RTMP_DATA_FILE
    if(psktdatafile)
    {
        fwrite(buf, 1, size, psktdatafile);
        fflush(psktdatafile);
    }
#endif
        // add end
    if (nread) {
        *nread = nb_read;
    }
    
    // On success a non-negative integer indicating the number of bytes actually read is returned
    // (a value of 0 means the network connection is closed or end of file is reached).
    // Otherwise, a value of -1 is returned and errno is set to indicate the error.
    if (nb_read <= 0) {
        // @see https://github.com/ossrs/srs/issues/200
        if (nb_read < 0 && errno == ETIME) {
            srs_error("nb_read:%"PRId64" < 0 && errno:%d == ETIME reason:%s", nb_read, errno, strerror(errno));
            return ERROR_SOCKET_TIMEOUT;
        }
        
        if (nb_read == 0) {
            errno = ECONNRESET;
        }
        //srs_error("nb_read:%"PRId64" != (ssize_t)size:%"PRId64" errno:%d == ETIME reason:%s", nb_read, size, errno, strerror(errno));
        return ERROR_SOCKET_READ;
    }
    
    recv_bytes += nb_read;
    
    return ret;
}

int SrsStSocket::read_fully(void* buf, size_t size, ssize_t* nread)
{
    int ret = ERROR_SUCCESS;
    
    ssize_t nb_read = st_read_fully(stfd, buf, size, recv_timeout);
    srs_verbose("nb_read:%"PRId64" = st_read_fully(stfd:%p, buf:%p, size:%"PRId64", recv_timeout:%"PRId64, nb_read, stfd, buf, size, recv_timeout);
    if (nread) {
        *nread = nb_read;
    }
    
    // On success a non-negative integer indicating the number of bytes actually read is returned
    // (a value less than nbyte means the network connection is closed or end of file is reached)
    // Otherwise, a value of -1 is returned and errno is set to indicate the error.
    if (nb_read != (ssize_t)size) {
        // @see https://github.com/ossrs/srs/issues/200
        if (nb_read < 0 && errno == ETIME) {
            srs_trace("nb_read:%"PRId64" < 0 && errno:%d == ETIME reason:%s", nb_read, errno, strerror(errno));
            return ERROR_SOCKET_TIMEOUT;
        }
        
        if (nb_read >= 0) {
            errno = ECONNRESET;
        }
        //srs_trace("nb_read:%"PRId64" != (ssize_t)size:%"PRId64" errno:%d == ETIME reason:%s",nb_read, size, errno, strerror(errno));
        return ERROR_SOCKET_READ_FULLY;
    }
    
    recv_bytes += nb_read;
    
    return ret;
}

#if 1
int SrsStSocket::write(void* buf, size_t size, ssize_t* nwrite)
{
    int ret = ERROR_SUCCESS;
    int remain = size;
    int trynum = 0;
    int pos = 0;
    while(remain > 0)
    {
        int writed = st_write(stfd, (char*)buf + pos, remain, send_timeout);
        //int writed = write_imp(buf + pos, remain);
        if(writed <= 0)
        {
            //EINTR: this operation has been interrupt, retry again, EAGAIN: not block mode call block operation, retray again
            if(trynum++ < RETRY_NUM && (EAGAIN == errno || EINTR == errno || EWOULDBLOCK == errno))
            {
                //sv_warn("write msg timeout:%"PRId64", sendtime:%lu, reason:%s", m_llWriteTimeout, GetSysTime() - begin, strerror(errno));
                st_usleep(50000);
                continue;
                //return ERROR_SOCKET_TIMEOUT;
            }
            srs_error("writed:%d = ::send(pbuf:%p + pos:%d, remain:%d) failed! reason:%s, trynum:%d\n", writed, buf, pos, remain, strerror(errno), trynum);
            return ERROR_SOCKET_TIMEOUT;
        }
        remain = remain - writed;
        pos += writed;
        send_bytes += writed;
    };

    if(nwrite)
    {
        *nwrite = pos;
    }
    return 0;
}


int SrsStSocket::writev(const iovec *iov, int iov_size, ssize_t* nwrite)
{
    int ret = ERROR_SUCCESS;
    int send_len = 0;
    for(int i = 0; i < iov_size; i++)
    {
        ssize_t writed = 0;
        ret = write(iov[i].iov_base, iov[i].iov_len, &writed);
        if(ERROR_SUCCESS != ret)
        {
            srs_error("ret:%d = iov[i:%d].iov_base:%p, iov[i].iov_len:%d, writed:%ld\n", ret, i, iov[i].iov_base, iov[i].iov_len, writed);
            return ret;
        }

        send_len += (int)writed;
    }
    if(nwrite)
    {
        *nwrite = send_len;
    }
    return ret;
    /*ssize_t nb_write = st_writev(stfd, iov, iov_size, send_timeout);
    srs_verbose("%s nb_write:%"PRId64"= st_writev(stfd:%p, iov:%p, iov_size:%"PRId64", send_timeout:%"PRId64")", __FUNCTION__, nb_write, stfd, iov, iov_size, send_timeout);
    if (nwrite) {
        *nwrite = nb_write;
    }
    
    // On success a non-negative integer equal to nbyte is returned.
    // Otherwise, a value of -1 is returned and errno is set to indicate the error.
    if (nb_write <= 0) {
        // @see https://github.com/ossrs/srs/issues/200
        if (nb_write < 0 && errno == ETIME) {
            srs_error("nb_write:%"PRId64" < 0 && errno:%d == ETIME reason:%s", nb_write, errno, strerror(errno));
            return ERROR_SOCKET_TIMEOUT;
        }
        srs_error("nb_write:%"PRId64" <= 0  errno:%d == ETIME reason:%s", nb_write, errno, strerror(errno));
        return ERROR_SOCKET_WRITE;
    }
    
    send_bytes += nb_write;
    
    return ret;*/
}
#else
int SrsStSocket::write(void* buf, size_t size, ssize_t* nwrite)
{
    int ret = ERROR_SUCCESS;
    ssize_t nb_write = st_write(stfd, buf, size, send_timeout);
    srs_verbose("%s nb_write:%"PRId64" = st_write(stfd:%p, buf:%p, size:%"PRId64", send_timeout:%"PRId64")", __FUNCTION__, nb_write, stfd, buf, size, send_timeout);
    if (nwrite) {
        *nwrite = nb_write;
    }
    
    // On success a non-negative integer equal to nbyte is returned.
    // Otherwise, a value of -1 is returned and errno is set to indicate the error.
    if (nb_write <= 0) {
        // @see https://github.com/ossrs/srs/issues/200
        if (nb_write < 0 && errno == ETIME) {
             srs_error("nb_write:%"PRId64" < 0 && errno:%d == ETIME reason:%s", nb_write, errno, strerror(errno));
            return ERROR_SOCKET_TIMEOUT;
        }
        srs_error("nb_write:%"PRId64" != (ssize_t)size:%"PRId64" errno:%d == ETIME reason:%s", nb_write, size, errno, strerror(errno));
        return ERROR_SOCKET_WRITE;
    }
#ifdef WRITE_ST_SOCKET_WRITE_DATA
    else
    {
        if(NULL == m_pwrite_file)
        {
            m_pwrite_file = fopen("stwrite.data", "wb");
        }

        if(m_pwrite_file)
        {
            fwrite(buf, 1, nb_write, m_pwrite_file);
        }
    }
#endif
    send_bytes += nb_write;
    
    return ret;
}

int SrsStSocket::writev(const iovec *iov, int iov_size, ssize_t* nwrite)
{
    int ret = ERROR_SUCCESS;
    
    ssize_t nb_write = st_writev(stfd, iov, iov_size, send_timeout);
    srs_verbose("%s nb_write:%"PRId64"= st_writev(stfd:%p, iov:%p, iov_size:%"PRId64", send_timeout:%"PRId64")", __FUNCTION__, nb_write, stfd, iov, iov_size, send_timeout);
    if (nwrite) {
        *nwrite = nb_write;
    }
    
    // On success a non-negative integer equal to nbyte is returned.
    // Otherwise, a value of -1 is returned and errno is set to indicate the error.
    if (nb_write <= 0) {
        // @see https://github.com/ossrs/srs/issues/200
        if (nb_write < 0 && errno == ETIME) {
            srs_error("nb_write:%"PRId64" < 0 && errno:%d == ETIME reason:%s", nb_write, errno, strerror(errno));
            return ERROR_SOCKET_TIMEOUT;
        }
        srs_error("nb_write:%"PRId64" <= 0  errno:%d == ETIME reason:%s", nb_write, errno, strerror(errno));
        return ERROR_SOCKET_WRITE;
    }
    
    send_bytes += nb_write;
    
    return ret;
}
#endif
#ifdef __linux__
#include <sys/epoll.h>

bool srs_st_epoll_is_supported(void)
{
    struct epoll_event ev;

    ev.events = EPOLLIN;
    ev.data.ptr = NULL;
    /* Guaranteed to fail */
    epoll_ctl(-1, EPOLL_CTL_ADD, -1, &ev);

    return (errno != ENOSYS);
}
#endif

int srs_st_init()
{
    int ret = ERROR_SUCCESS;
    
#ifdef __linux__
    // check epoll, some old linux donot support epoll.
    // @see https://github.com/ossrs/srs/issues/162
    if (!srs_st_epoll_is_supported()) {
        ret = ERROR_ST_SET_EPOLL;
        srs_error("epoll required on Linux. ret=%d", ret);
        return ret;
    }
#endif
    
    // Select the best event system available on the OS. In Linux this is
    // epoll(). On BSD it will be kqueue.
    if (st_set_eventsys(ST_EVENTSYS_ALT) == -1) {
        ret = ERROR_ST_SET_EPOLL;
        srs_error("st_set_eventsys use %s failed. ret=%d", st_get_eventsys_name(), ret);
        return ret;
    }
    srs_trace("st_set_eventsys to %s", st_get_eventsys_name());

    if(st_init() != 0){
        ret = ERROR_ST_INITIALIZE;
        srs_error("st_init failed. ret=%d", ret);
        return ret;
    }
    srs_trace("st_init success, use %s", st_get_eventsys_name());
    
    return ret;
}

void srs_close_stfd(st_netfd_t& stfd)
{
    if (stfd) {
        // we must ensure the close is ok.
        int err = st_netfd_close(stfd);
        if(err == -1)
        {
            srs_error("err:%d = st_netfd_close(stfd:%p) failed, st_netfd_poll(stfd, POLLIN, 0):%d, st_netfd_poll(stfd, POLLOUT, 0):%d\n", err, stfd, st_netfd_poll(stfd, POLLIN, 0), st_netfd_poll(stfd, POLLOUT, 0));
            //close(stfd->osfd);
        }
        //srs_assert(err != -1);
        stfd = NULL;
    }

}

