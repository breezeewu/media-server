#pragma once
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <srs_app_log.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_utility.hpp>
#ifdef WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#pragma warning( disable : 4996)
#else
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
#ifndef lbusleep
#define lbusleep st_usleep
#endif
#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS 0
#endif
#ifndef lbtrace
#define lbtrace srs_trace
#endif
#ifndef lbdebug
#define lbdebug(...)
#endif
#ifndef lberror
#define lberror srs_error
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET  ~0
#endif
#define LB_CHECK_RES(ret) if(ret < 0) { lberror("%s %s %d check result failed, ret:%d, reason:%s\n", __FILE__, FUNCTION__, __LINE__, ret, strerror(errno)); return ret;}
#define RETRY_NUM 10
#define MIN_TIMEOUT_IN_MS			5000
#define MAX_TIMEOUT_IN_MS			120000
class ITCPSocket
{
public:
	virtual ~ITCPSocket() {}

	virtual int init_socket(int fd = INVALID_SOCKET) = 0;

	virtual int get_socket() = 0;

	virtual int bind(const char* ip, int port) = 0;

	virtual int listen(int maxnum) = 0;

	virtual ITCPSocket* accept() = 0;

	virtual int connect(const char* ip, int port) = 0;

	virtual int set_socket_opt(int level, int optname, const char* optval, int optlen) = 0;

	virtual int read(char* pbuff, int len) = 0;

	virtual int write(const char* pbuff, const int len) = 0;

	virtual void close() = 0;
};

class CTCPSocket:public ITCPSocket
{
protected:
	int				m_nfd;
	int64_t			m_lread_bytes;
	int64_t			m_lwrite_bytes;
	int				m_nread_timeout_ms;
	int				m_nwrite_timeout_ms;			
public:
	CTCPSocket()
	{
		m_nfd = INVALID_SOCKET;
		m_lread_bytes		= 0;
		m_lwrite_bytes		= 0;
	}

	~CTCPSocket()
	{
		close();
	}

	virtual int init_socket(int fd = INVALID_SOCKET)
	{
		if (INVALID_SOCKET == fd)
		{
#ifdef WIN32
			WSADATA wsaData;
			//��ʼ��windows Socket����
			if (WSAStartup(MAKEWORD(2, 0), &wsaData))
			{
				lberror("WSAStartup(MAKEWORD(2, 0), &wsaData) failed, reason:%s\n", strerror(errno));
				assert(0);
			}
#endif
			fd = socket(AF_INET, SOCK_STREAM, 0);
		}
		else
		{
			close();
		}
		m_nfd = fd;

		return INVALID_SOCKET == m_nfd ? -1 : ERROR_SUCCESS ;
	}

	virtual int get_socket()
	{
		return m_nfd;
	}

	virtual int bind(const char* ip, int port)
	{
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return -1;
		}
		struct sockaddr_in sa; //sockaddr_in �ṹ��
		memset(&sa, 0, sizeof(sa));

		sa.sin_family = AF_INET;
		if (ip)
		{
			sa.sin_addr.s_addr = inet_addr(ip); //����˵�ַ
		}
		else
		{
			sa.sin_addr.s_addr = INADDR_ANY;
		}

		sa.sin_port = htons(port); //����˿�
		return ::bind(m_nfd, (struct sockaddr*)&sa, sizeof(sa));
	}

	virtual int listen(int maxnum)
	{
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return -1;
		}
		return ::listen(m_nfd, maxnum);
	}

	virtual ITCPSocket* accept()
	{
		if (INVALID_SOCKET == m_nfd)
		{
			int ret = init_socket();
			//
			if(ret != ERROR_SUCCESS)
			{
				lberror("init tcp sokcet failed, m_nfd:%d\n", m_nfd);
				return NULL;
			}
			//
		}
		struct sockaddr_in sa;
		socklen_t sa_len = (socklen_t)sizeof(sa);
		int fd = ::accept(m_nfd, (struct sockaddr*)&sa, &sa_len);
		if (INVALID_SOCKET == fd)
		{
			lberror("fd:%d = ::accept(m_nfd:%d, (struct sockaddr*)&sa, &sa_len) failed!\n", fd, m_nfd);
			return NULL;
		}
		CTCPSocket* ptcpskt = new CTCPSocket();
		ptcpskt->init_socket(fd);
		return (ITCPSocket*)ptcpskt;
	}

	virtual int connect(const char* ip, int port)
	{
		if(INVALID_SOCKET == m_nfd)
		{
			int ret = init_socket();
			if(ERROR_SUCCESS != ret)
			{
				lberror("ret:%d = init_socket() failed\n", ret);
				return -1;
			}
		}
		if (NULL == ip)
		{

			lberror("Invalid ip addr:%s\n", ip);
			return -1;
		}
		lbdebug("tcp connect(ip:%s, port:%d) begin\n", ip, port);
		hostent* phe = gethostbyname(ip);
		if (NULL == phe)
		{
			lberror("phe:%p = gethostbyname(ip:%s) failed\n", phe, ip);
			return -1;
		}
		struct sockaddr_in	sa_in;
		//struct in_addr ip;
		memcpy(&sa_in.sin_addr, phe->h_addr, phe->h_length);
		sa_in.sin_family = AF_INET;
		sa_in.sin_port = htons(port);
		lbdebug("hostname:%s has ip address %s\n", ip, inet_ntoa(sa_in.sin_addr));
		/*struct sockaddr_in sa; //sockaddr_in �ṹ��
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = inet_addr(ip); //����˵�ַ
		sa.sin_port = htons(port); //����˿�*/

		return ::connect(m_nfd, (struct sockaddr*)&sa_in, sizeof(sa_in));
	}

	virtual int set_socket_opt(int level, int optname, const char* optval, int optlen)
	{
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return -1;
		}
		
		return setsockopt(m_nfd, level, optname, optval, optlen);
	}

	virtual int set_read_timeout(int timeout_ms)
	{
		if(timeout_ms < MIN_TIMEOUT_IN_MS || timeout_ms > MAX_TIMEOUT_IN_MS)
		{
			lberror("Invalid parameter timeout_ms:%d, out of range(%d, %d)\n", timeout_ms, MIN_TIMEOUT_IN_MS, MAX_TIMEOUT_IN_MS);
			return -1;
		}

		struct timeval tv = { timeout_ms / 1000 , timeout_ms % 1000};
		int ret = setsockopt(m_nfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		if ( -1 == ret)
		{
			lberror("ret:%d = setsocketopt(m_nfd:%d, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))", ret, m_nfd);
			return -1;
		}

		m_nread_timeout_ms = timeout_ms;

		return ret;
	}

	virtual int set_write_timeout(int timeout_ms)
	{
		if(timeout_ms < MIN_TIMEOUT_IN_MS || timeout_ms > MAX_TIMEOUT_IN_MS)
		{
			lberror("Invalid parameter timeout_ms:%d, out of range(%d, %d)\n", timeout_ms, MIN_TIMEOUT_IN_MS, MAX_TIMEOUT_IN_MS);
			return -1;
		}

		struct timeval tv = { timeout_ms / 1000 , timeout_ms % 1000};
		int ret = setsockopt(m_nfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		if(-1 == ret)
		{
			lberror("ret:%d = setsocketopt(m_nfd:%d, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv))", ret, m_nfd);
			return -1;
		}
		m_nwrite_timeout_ms = timeout_ms;
		return ret;
	}

	virtual int read(char* pbuf, int len)
	{
		int ret = 0;
		int nbread = 0;
		int trynum = 0;
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return -1;
		}
		unsigned long begin_time = get_sys_time();
		do
		{
			nbread = read_imp(pbuf, len);
			//lbdebug("nbread:%d = ::recv(m_nfd:%d, pbuf:%p, size:%d), m_lread_bytes:%0x", nbread, m_nfd, pbuf, len, (uint32_t)m_lread_bytes);
			if(nbread <= 0)
			{
				//EINTR:指操作被中断唤醒，需要重新读/写, EAGAIN:非阻塞模式下调用了阻塞操作，操作没有完成，重试一次
				if(trynum++ < RETRY_NUM && (EAGAIN == errno || EINTR == errno || EWOULDBLOCK == errno))
				{
					//sv_warn("recv failed nbread:%d, errno:%d, reason:%s, trynum:%d\n", nbread, errno, strerror(errno), trynum);
					lbusleep(50000);
					continue;
				}
				if(get_sys_time() - begin_time < (unsigned long)m_nread_timeout_ms)
				{
					lbusleep(50000);
					continue;
				}
				if(0 == errno)
				{
					ret = -ERROR_SOCKET_TIMEOUT;
					lberror("nbread:%d = ::recv(m_nfd:%d, pbuf:%p, len:%d) failed, ret:%d, trynum:%d, timeout:%lu", nbread, m_nfd, pbuf, len, ret, trynum, get_sys_time() - begin_time);
				}
				else
				{
					ret = errno > 0 ? (-errno) : errno;
					lberror("nbread:%d = ::recv(m_nfd:%d, pbuf:%p, len:%d) failed, ret:%d, reason:%s, trynum:%d, timeout:%lu", nbread, m_nfd, pbuf, len, ret, strerror(errno), trynum, get_sys_time() - begin_time);
				}
				
				return ret;
			}
			m_lread_bytes += nbread;
		}while(nbread <= 0);
		return nbread;
		//return recv(m_nfd, pbuff, len, 0);
	}

	virtual int write(const char* pbuf, const int len)
	{
		int ret = -1;
		int remain = len;
		int trynum = 0;
		int pos = 0;
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return -1;
		}

		while(remain > 0)
		{
			int writed = write_imp(pbuf + pos, remain);
			if(writed <= 0)
			{
				//EINTR:指操作被中断唤醒，需要重新读/写, EAGAIN:非阻塞模式下调用了阻塞操作，操作没有完成，重试一次
				if(trynum++ < RETRY_NUM && (EAGAIN == errno || EINTR == errno || EWOULDBLOCK == errno))
				{
					//sv_warn("write msg timeout:%"PRId64", sendtime:%lu, reason:%s", m_llWriteTimeout, GetSysTime() - begin, strerror(errno));
					lbusleep(50000);
					continue;
					//return ERROR_SOCKET_TIMEOUT;
				}
				lberror("writed:%d = ::send(pbuf:%p + pos:%d, remain:%d) failed! reason:%s, trynum:%d\n", writed, pbuf, pos, remain, strerror(errno), trynum);
				return -1;
			}
			remain = remain - writed;
			pos += writed;
			m_lwrite_bytes += writed;
		}

		return pos > 0 ? pos : ret;
	}

	virtual int write_imp(const char* pbuf, const int len)
	{
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return -1;
		}

		int ret = send(m_nfd, pbuf, len, 0);
		//lbdebug("ret:%d = send(m_nfd:%d, pbuf:%s, len:%d, 0)\n", ret, m_nfd, pbuf, len);
		return ret;
	}

	virtual int read_imp(char* pbuf, int len)
	{
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return -1;
		}

		int ret = recv(m_nfd, pbuf, len, 0);
		//lbdebug("ret:%d = recv(m_nfd:%d, pbuf:%s, len:%d, 0)\n", ret, m_nfd, pbuf, len);
		return ret;
	}

	virtual void close()
	{
		if (INVALID_SOCKET == m_nfd)
		{
			return ;
		}
#ifdef WIN32
		closesocket(m_nfd);
#else
		::close(m_nfd);
#endif
	}
};
