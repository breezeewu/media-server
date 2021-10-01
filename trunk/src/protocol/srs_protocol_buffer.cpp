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

#include <srs_protocol_buffer.hpp>

#include <stdlib.h>

#include <srs_kernel_error.hpp>
#include <srs_kernel_log.hpp>
#include <srs_kernel_utility.hpp>
#include <srs_core_performance.hpp>

// the default recv buffer size, 128KB.
#define SRS_DEFAULT_RECV_BUFFER_SIZE 131072

// limit user-space buffer to 256KB, for 3Mbps stream delivery.
//      800*2000/8=200000B(about 195KB).
// @remark it's ok for higher stream, the buffer is ok for one chunk is 256KB.
#define SRS_MAX_SOCKET_BUFFER 262144

// the max header size,
// @see SrsProtocol::read_message_header().
#define SRS_RTMP_MAX_MESSAGE_HEADER 11

#ifdef SRS_PERF_MERGED_READ
IMergeReadHandler::IMergeReadHandler()
{
}

IMergeReadHandler::~IMergeReadHandler()
{
}
#endif

SrsFastBuffer::SrsFastBuffer()
{
#ifdef SRS_PERF_MERGED_READ
    merged_read = false;
    _handler = NULL;
#endif
    
    nb_buffer = SRS_DEFAULT_RECV_BUFFER_SIZE;
    buffer = (char*)malloc(nb_buffer);
    p = end = buffer;

#ifdef WRITE_RTMP_DATA_ENABLE
    // add by dawson for write rtmp buffer data
    pfile   = NULL;
    lwrite_pos = 0;
    llast_read_size = 0;
    // add end
#endif
}

SrsFastBuffer::~SrsFastBuffer()
{
    free(buffer);
    buffer = NULL;
#ifdef WRITE_RTMP_DATA_ENABLE
    if(pfile)
    {
        fclose(pfile);
        pfile = NULL;
        srs_trace("fclose(pfile:%p) end", pfile);
    }
    lwrite_pos = 0;
#endif
}

int SrsFastBuffer::size()
{
    return (int)(end - p);
}

char* SrsFastBuffer::bytes()
{
    return p;
}

void SrsFastBuffer::set_buffer(int buffer_size)
{
    // never exceed the max size.
    if (buffer_size > SRS_MAX_SOCKET_BUFFER) {
        srs_warn("limit the user-space buffer from %d to %d", 
            buffer_size, SRS_MAX_SOCKET_BUFFER);
    }
    
    // the user-space buffer size limit to a max value.
    int nb_resize_buf = srs_min(buffer_size, SRS_MAX_SOCKET_BUFFER);

    // only realloc when buffer changed bigger
    if (nb_resize_buf <= nb_buffer) {
        return;
    }
    
    // realloc for buffer change bigger.
    int start = (int)(p - buffer);
    int nb_bytes = (int)(end - p);
    
    buffer = (char*)realloc(buffer, nb_resize_buf);
    nb_buffer = nb_resize_buf;
    p = buffer + start;
    end = p + nb_bytes;
}

char SrsFastBuffer::read_1byte()
{
    srs_assert(end - p >= 1);
    return *p++;
}

char* SrsFastBuffer::read_slice(int size)
{
    srs_assert(size >= 0);
    srs_assert(end - p >= size);
    srs_assert(p + size >= buffer);
    
    char* ptr = p;
    p += size;

    return ptr;
}

void SrsFastBuffer::skip(int size)
{
    srs_assert(end - p >= size);
    srs_assert(p + size >= buffer);
    p += size;
}
#ifdef WRITE_RTMP_DATA_ENABLE
void SrsFastBuffer::print_cur_buff(int pos, int size)
{
    //srs_trace_memory(p + pos, size);
    /*char buf[1024] = {0};
    sprintf(buf, "curpos:%0x, memory:", (unsigned int)(get_cur_write_pos() + pos));
    for(int i = 0; strlen(buf) < 256 && i < size; i+=4)
    {
        unsigned int chval = (int)(char)*(p + pos + i);
        sprintf(buf + strlen(buf), "%0x", (unsigned int)chval);
    }
    srs_trace(buf);*/
}

long SrsFastBuffer::get_cur_write_pos()
{
    long left = end - p;
    return lwrite_pos - left;
}

void SrsFastBuffer::closefile()
{
    if(pfile)
    {
        srs_trace("close file pfile:%p, filelen:%0x, llast_read_size:%d", pfile, ftell(pfile), llast_read_size);
        fflush(pfile);
        fclose(pfile);
        pfile = NULL;
        if(llast_read_size > 0)
        {
             timeval tv;
            if (gettimeofday(&tv, NULL) == -1) {
                //return false;
            }
            char lastreadname[256] = {0};
            sprintf(lastreadname, "./objs/nginx/html/rtmp/lastread%d%3d.data", (int)(tv.tv_sec), (int)(tv.tv_usec / 1000));
            pfile = fopen(lastreadname, "wb");
            srs_trace("pfile:%p = fopen(rtmpname:%s, wb)", pfile, lastreadname);
            if(pfile)
            {
                int writed = fwrite(end - llast_read_size - 32, 1, llast_read_size + 32, pfile);
                srs_trace("writed:%d = fwrite(end - llast_read_size:%ld - 32, 1, llast_read_size + 32, pfile:%p)", writed, llast_read_size, pfile);
                fclose(pfile);
                pfile = NULL;
            }
        }
    }
}
#endif
int SrsFastBuffer::grow(ISrsBufferReader* reader, int required_size)
{
    int ret = ERROR_SUCCESS;
    srs_verbose("SrsFastBuffer::grow(reader:%p, required_size:%d) begin", reader, required_size);
    // already got required size of bytes.
    if (end - p >= required_size) {
        return ret;
    }

    // must be positive.
    srs_assert(required_size > 0);

    // the free space of buffer, 
    //      buffer = consumed_bytes + exists_bytes + free_space.
    int nb_free_space = (int)(buffer + nb_buffer - end);
    
    // the bytes already in buffer
    int nb_exists_bytes = (int)(end - p);
    srs_assert(nb_exists_bytes >= 0);
    
    // resize the space when no left space.
    if (nb_free_space < required_size - nb_exists_bytes) {
        srs_verbose("move fast buffer %d bytes", nb_exists_bytes);

        // reset or move to get more space.
        if (!nb_exists_bytes) {
            // reset when buffer is empty.
            p = end = buffer;
            srs_verbose("all consumed, reset fast buffer");
        } else if (nb_exists_bytes < nb_buffer && p > buffer) {
            // move the left bytes to start of buffer.
            // @remark Only move memory when space is enough, or failed at next check.
            // @see https://github.com/ossrs/srs/issues/848
            buffer = (char*)memmove(buffer, p, nb_exists_bytes);
            p = buffer;
            end = p + nb_exists_bytes;
        }
        
        // check whether enough free space in buffer.
        nb_free_space = (int)(buffer + nb_buffer - end);
        if (nb_free_space < required_size - nb_exists_bytes) {
            ret = ERROR_READER_BUFFER_OVERFLOW;
            srs_error("buffer overflow, required=%d, max=%d, left=%d, ret=%d", 
                required_size, nb_buffer, nb_free_space, ret);
            return ret;
        }
    }

    // buffer is ok, read required size of bytes.
    while (end - p < required_size) {
        ssize_t nread;
        srs_verbose("SrsFastBuffer::grow before ret = reader->read(end, nb_free_space, &nread)");
#ifdef READ_RTMP_DATA_FROM_FILE
        if(NULL == pfile)
        {
            pfile = fopen("rtmp1554168613757.data", "rb");
            srs_trace("pfile:%p = fopen(rtmp1554168613757.data, rb)", pfile);
        }
        if(pfile)
        {
            nread = fread(end, 1, nb_free_space, pfile);
            //srs_trace("nread:%d = fread(end:%p, 1, nb_free_space:%d, pfile:%p)", nread, end, nb_free_space, pfile);
            lwrite_pos += nread;
        }
        if(nread > 0)
        {
            ret = ERROR_SUCCESS;
        }
        else
        {
            srs_error("read rtmp data file end********************");
            ret = -1;
        }
#else
        ret = reader->read(end, nb_free_space, &nread);

#endif
        srs_verbose("%s ret:%d = reader:%p->read(end:%p, nb_free_space:%d, &nread:%"PRId64")", __FUNCTION__, ret, reader, end, nb_free_space, nread);
        if (ret != ERROR_SUCCESS) {
            return ret;
        }
        
#ifdef SRS_PERF_MERGED_READ
        /**
        * to improve read performance, merge some packets then read,
        * when it on and read small bytes, we sleep to wait more data.,
        * that is, we merge some data to read together.
        * @see https://github.com/ossrs/srs/issues/241
        */
        if (merged_read && _handler) {
            _handler->on_read(nread);
        }
#endif
        
        // we just move the ptr to next.
        srs_assert((int)nread > 0);
        end += nread;
        nb_free_space -= nread;
    }
    
    return ret;
}

#ifdef SRS_PERF_MERGED_READ
void SrsFastBuffer::set_merge_read(bool v, IMergeReadHandler* handler)
{
    merged_read = v;
    _handler = handler;
}
#endif

