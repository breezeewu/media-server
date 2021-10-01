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

#ifndef SRS_KERNEL_LOG_HPP
#define SRS_KERNEL_LOG_HPP
//#include <lbmemcheck.hpp>
/*
#include <srs_kernel_log.hpp>
*/

#include <srs_core.hpp>

#include <stdio.h>

#include <errno.h>
#include <string.h>

#include <srs_kernel_consts.hpp>

/**
* the log level, for example:
* if specified Debug level, all level messages will be logged.
* if specified Warn level, only Warn/Error/Fatal level messages will be logged.
*/
class SrsLogLevel
{
public:
    // only used for very verbose debug, generally, 
    // we compile without this level for high performance.
    static const int Verbose = 0x01;
    static const int Info = 0x02;
    static const int Trace = 0x03;
    static const int Warn = 0x04;
    static const int Error = 0x05;
    // specified the disabled level, no log, for utest.
    static const int Disabled = 0x06;
};

/**
* the log interface provides method to write log.
* but we provides some macro, which enable us to disable the log when compile.
* @see also SmtDebug/SmtTrace/SmtWarn/SmtError which is corresponding to Debug/Trace/Warn/Fatal.
*/ 
class ISrsLog
{
public:
    ISrsLog();
    virtual ~ISrsLog();
public:
    /**
    * initialize log utilities.
    */
    virtual int initialize();
public:
    /**
    * log for verbose, very verbose information.
    */
    virtual void verbose(const char* tag, int context_id, const char* fmt, ...);
    /**
    * log for debug, detail information.
    */
    virtual void info(const char* tag, int context_id, const char* fmt, ...);
    /**
    * log for trace, important information.
    */
    virtual void trace(const char* tag, int context_id, const char* fmt, ...);
    /**
    * log for trace, important information.
    */
    virtual void trace(const char* tag, const char* pfile, int line, const char* pfun, int context_id, const char* fmt, ...);
    /**
    * log for warn, warn is something should take attention, but not a error.
    */
    virtual void warn(const char* tag,  const char* file, int line, const char* function, int context_id, const char* fmt, ...);
    /**
    * log for error, something error occur, do something about the error, ie. close the connection,
    * but we will donot abort the program.
    */
    virtual void error(const char* tag, const char* pfile, int line, const char* pfun, int context_id, const char* fmt, ...);
    /**
     * dawson
    * log for memory, show the momory when it is necessary
    * @param level, output log level must be hight then config output log level
    * @param pmemory, memory ptr to print,
    * @param size, memory to output
    */
    virtual void print_memory(int level, const char* pmemory, int size, int max_print_size = 64);
};

/**
 * the context id manager to identify context, for instance, the green-thread.
 * usage:
 *      _srs_context->generate_id(); // when thread start.
 *      _srs_context->get_id(); // get current generated id.
 *      int old_id = _srs_context->set_id(1000); // set context id if need to merge thread context.
 */
// the context for multiple clients.
class ISrsThreadContext
{
public:
    ISrsThreadContext();
    virtual ~ISrsThreadContext();
public:
    /**
     * generate the id for current context.
     */
    virtual int generate_id();
    /**
     * get the generated id of current context.
     */
    virtual int get_id();
    /**
     * set the id of current context.
     * @return the previous id value; 0 if no context.
     */
    virtual int set_id(int v);
};

// user must provides a log object
extern ISrsLog* _srs_log;

// user must implements the LogContext and define a global instance.
extern ISrsThreadContext* _srs_context;

// donot print method
#if 1
    #define srs_verbose(msg, ...) _srs_log->verbose(NULL, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_info(msg, ...)    _srs_log->info(NULL, _srs_context->get_id(), msg, ##__VA_ARGS__)
    //#define srs_trace(msg, ...)   _srs_log->trace(NULL, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_trace(msg, ...)       _srs_log->trace(NULL, __FILE__, __LINE__, __FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_warn(msg, ...)    _srs_log->warn(NULL, __FILE__, __LINE__, __FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_error(msg, ...)   _srs_log->error(NULL, __FILE__, __LINE__, __FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define tag_error(tag, msg, ...)    _srs_log->error(tag, __FILE__, __LINE__, __FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_dump_memory              _srs_log->print_memory
    #define srs_trace_memory(msg, size)  _srs_log->print_memory(SrsLogLevel::Trace, msg, size)
    #define srs_err_memory(msg, size)  _srs_log->print_memory(SrsLogLevel::Error, msg, size)
    #define srs_debug(msg, ...)                      //_srs_log->trace(NULL, __FILE__, __LINE__, __FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_rtsp_debug(msg, ...)                 //_srs_log->trace(NULL, __FILE__, __LINE__, __FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_rtsp_debug_memory(msg, size)          //srs_trace_memory(msg, size)
    #define UNREFERENCED_PARAMETER(P) (P)
// use __FUNCTION__ to print c method
#elif 0
    #define srs_verbose(msg, ...) _srs_log->verbose(__FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_info(msg, ...)    _srs_log->info(__FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_trace(msg, ...)   _srs_log->trace(__FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_warn(msg, ...)    _srs_log->warn(__FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_error(msg, ...)   _srs_log->error(__FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
// use __PRETTY_FUNCTION__ to print c++ class:method
#else
    #define srs_verbose(msg, ...) _srs_log->verbose(__PRETTY_FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_info(msg, ...)    _srs_log->info(__PRETTY_FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_trace(msg, ...)   _srs_log->trace(__PRETTY_FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_warn(msg, ...)    _srs_log->warn(__PRETTY_FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
    #define srs_error(msg, ...)   _srs_log->error(__PRETTY_FUNCTION__, _srs_context->get_id(), msg, ##__VA_ARGS__)
#endif

// add by dawson for micro control
#define TS_SLICE_WRITE_REDIS
//#define ENABLE_WRITE_VIDEO_STREAM
//#define ENABLE_WRITE_AUDIO_STREAM
//#define WRITE_RTMP_DATA_ENABLE
//#define READ_RTMP_DATA_FROM_FILE
#ifdef WRITE_RTMP_DATA_ENABLE
#include <stdio.h>
#include <sys/time.h>
#endif

// TODO: FIXME: add more verbose and info logs.
/*#ifndef SRS_AUTO_VERBOSE
    #undef srs_verbose
    #define srs_verbose(msg, ...) (void)0
#endif*/
#ifndef SRS_AUTO_INFO
    #undef srs_info
    #define srs_info(msg, ...) (void)0
#endif
#ifndef SRS_AUTO_TRACE
    #undef srs_trace
    #define srs_trace(msg, ...) (void)0
#endif
#define SRS_CHECK_RESULT(ret) if(0 > ret) {srs_error("%s:%d, %s check result failed, ret:%d\n", __FILE__, __LINE__, __FUNCTION__, ret); return ret;}
#define SRS_BREAK_RESULT(ret) if(0 > ret) {srs_error("%s:%d, %s check result failed, ret:%d, break!\n", __FILE__, __LINE__, __FUNCTION__, ret); break;}
#define SRS_CHECK_VALUE(val, ret) if(!(val)) {srs_error("%s:%d, %s check value failed, ret:%d\n", __FILE__, __LINE__, __FUNCTION__, ret); return ret;}
#define SRS_CHECK_PARAM_PTR(ptr, ret) if(NULL == ptr) { srs_error("%s:%d, %s, Invalid ptr:%p\n", __FILE__, __LINE__, __FUNCTION__, ptr); return ret;}
#endif

