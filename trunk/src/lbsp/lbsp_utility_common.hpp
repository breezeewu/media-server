#pragma once
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
using namespace std;
#define INET6_ADDRSTRLEN 50
static uint32_t lazy_get_random_int()
{
#if defined(__WIN32__) || defined(_WIN32)
  return rand();
#else
  return random();
#endif
    /*static int seed_num = 0;
    srand((unsigned)time(NULL) + seed_num++);

    return rand();*/
}

static u_int32_t lazy_get_random32() {
  /* Return a 32-bit random number.
     Because "lazy_get_random_int()" returns a 31-bit random number, we call it a second
     time, to generate the high bit.
     (Actually, to increase the likelhood of randomness, we take the middle 16 bits of two successive calls to "our_random()")
  */
  long random_1 = lazy_get_random_int();
  u_int32_t random16_1 = (u_int32_t)(random_1&0x00FFFF00);

  long random_2 = lazy_get_random_int();
  u_int32_t random16_2 = (u_int32_t)(random_2&0x00FFFF00);

  return (random16_1<<8) | (random16_2>>8);
}

static int lazy_get_local_port(int fd)
{
    // discovery client information
    sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    if (getsockname(fd, (sockaddr*)&addr, &addrlen) == -1) {
        return 0;
    }
    srs_verbose("get local ip success.");
    
    int port = ntohs(addr.sin_port);

    srs_verbose("get local ip of client port=%s, fd=%d", port, fd);

    return port;
}

static string lazy_get_peer_ip(int fd)
{
    std::string ip;
    
    // discovery client information
    sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    if (getpeername(fd, (sockaddr*)&addr, &addrlen) == -1) {
        srs_error("getpeername(fd:%d, (sockaddr*)&addr, &addrlen) failed, reason:%s", fd, strerror(errno));
        return ip;
    }
    srs_verbose("get peer name success.");

    // ip v4 or v6
    char buf[INET6_ADDRSTRLEN];
    memset(buf, 0, sizeof(buf));
    
    if ((inet_ntop(addr.sin_family, &addr.sin_addr, buf, sizeof(buf))) == NULL) {
        srs_error("inet_ntop(addr.sin_family, &addr.sin_addr, buf, sizeof(buf))) == NULL failed, reason:%s", strerror(errno));
        return ip;
    }
    srs_verbose("get peer ip of client ip=%s, fd=%d", buf, fd);
    
    ip = buf;
    
    srs_verbose("get peer ip success. ip=%s, fd=%d", ip.c_str(), fd);
    
    return ip;
}

static string lazy_get_local_ip(int fd)
{
    std::string ip;

    // discovery client information
    sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    if (getsockname(fd, (sockaddr*)&addr, &addrlen) == -1) {
        return ip;
    }
    srs_verbose("get local ip success.");

    // ip v4 or v6
    char buf[INET6_ADDRSTRLEN];
    memset(buf, 0, sizeof(buf));

    if ((inet_ntop(addr.sin_family, &addr.sin_addr, buf, sizeof(buf))) == NULL) {
        return ip;
    }

    ip = buf;

    srs_verbose("get local ip of client ip=%s, fd=%d", buf, fd);

    return ip;
}

static string get_datetime(bool utc)
{
    char time_buf[128] = {0};
    timeval tv;
    if (gettimeofday(&tv, NULL) == -1) {
        return string();
    }

    // to calendar time
    struct tm* tm;
    if (utc) {
        if ((tm = gmtime(&tv.tv_sec)) == NULL) {
            return string();
        }
    } else {
        if ((tm = localtime(&tv.tv_sec)) == NULL) {
            return string();
        }
    }

    // write log header
    //int log_header_size = -1;
    snprintf(time_buf, 128, "%d-%02d-%02d %02d:%02d:%02d", 1900 + tm->tm_year, 1 + tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

    return string(time_buf);
}

// in million second
static long get_timestamp()
{
    timeval tv;
    if (gettimeofday(&tv, NULL) == -1) {
        return -1;
    }

    // to calendar time
    /*struct tm* tm;
    if (utc) {
        if ((tm = gmtime(&tv.tv_sec)) == NULL) {
            return string();
        }
    } else {
        if ((tm = localtime(&tv.tv_sec)) == NULL) {
            return string();
        }
    }*/

    return tv.tv_sec * 1000 + tv.tv_usec/1000;
}