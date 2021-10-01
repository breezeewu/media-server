#pragma once
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <srs_app_log.hpp>
#ifdef WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#pragma warning( disable : 4996)
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
#ifndef lbtrace
#define lbtrace srs_trace
#endif
#ifndef lberror
#define lberror srs_error
#endif
#define INVALID_SOCKET  ~0
#define LB_CHECK_RES(ret) if(ret < 0) { lberror("%s %s %d check result failed, ret:%d, reason:%s\n", __FILE__, FUNCTION__, __LINE__, ret, strerror(errno)); return ret;}

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

	virtual int write(char* pbuff, int len) = 0;

	virtual void close() = 0;
};

class CTCPSocket:public ITCPSocket
{
protected:
	int		m_nfd;

public:
	CTCPSocket()
	{
		m_nfd = INVALID_SOCKET;
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

		return 0;
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
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return NULL;
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
		if (INVALID_SOCKET == m_nfd || NULL == ip)
		{
			lberror("tcp sokcet have not init, m_nfd:%d, ip:%p\n", m_nfd, ip);
			return -1;
		}
		lbtrace("tcp connect(ip:%s, port:%d) begin\n", ip, port);
		struct sockaddr_in sa; //sockaddr_in �ṹ��
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = inet_addr(ip); //����˵�ַ
		sa.sin_port = htons(port); //����˿�

		return ::connect(m_nfd, (struct sockaddr*)&sa, sizeof(sa));
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

	virtual int read(char* pbuff, int len)
	{
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return -1;
		}

		return recv(m_nfd, pbuff, len, 0);
	}

	virtual int write(char* pbuff, int len)
	{
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return -1;
		}

		return send(m_nfd, pbuff, len, 0);
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
