#pragma once
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tcp_socket.hpp"
#include <assert.h>
#include <map>
//#include <mutex>
#ifdef WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#pragma warning( disable : 4996)
#else
#include <netdb.h>
#include <sys/socket.h>
#endif
#ifndef lbtrace
#define lbtrace printf
#endif
#ifndef lberror
#define lberror printf
#endif
enum tls_version
{
	TLS_VERSION_UNKNOWN = -1,
	TLS_SERVER_VERSION_V1 = 0,
	TLS_SERVER_VERSION_V1_1 = 1,
	TLS_SERVER_VERSION_V1_2 = 2,
	TLS_SERVER_VERSION_TOP_MOST = 0x10,
	DTSL_SERVER_VERSION_V1 = 0x11,
	DTSL_SERVER_VERSION_V1_2 = 0x012,
	DTLS_SERVER_VERSION_TOP_MOST = 0x20,

	TLS_CLIENT_VERSION_V1 = 0x100,
	TLS_CLIENT_VERSION_V1_1 = 0x101,
	TLS_CLIENT_VERSION_V1_2 = 0x102,
	TLS_CLIENT_VERSION_TOP_MOST = 0x110,
	DTSL_CLIENT_VERSION_V1 = 0x111,
	DTSL_CLIENT_VERSION_V1_2 = 0x0112,
	DTLS_CLIENT_VERSION_TOP_MOST = 0x120,
};
class CSSLSocket :public CTCPSocket
{
protected:
	SSL*			m_pssl;

public:
	CSSLSocket()
	{
		m_pssl = NULL;
	}

	int init_accept_socket(SSL_CTX* psslctx, int fd)
	{
		X509* cli_cert = NULL;
		//ʹ�����е�TCP���ӿ���SSLЭ��
		m_pssl = SSL_new(psslctx);
		LB_ADD_MEM(m_pssl, sizeof(SSL));
		if (NULL == m_pssl)
		{
			lberror("m_pssl:%p = SSL_new(psslctx:%p) failed!\n", m_pssl, psslctx);
			return -1;
		}

		SSL_set_fd(m_pssl, fd);

		//����SSL����
		int ret = SSL_accept(m_pssl);
		if (ret < 0)
		{
			ERR_print_errors_fp(stderr);
			lberror("ret:%d = SSL_accept(ssl) failed\n", ret);
			LB_RM_MEM(m_pssl);
			SSL_free(m_pssl);
			m_pssl = NULL;
			return ret;
		}

		//���SSL�����õ����㷨
		printf("SSL connection using %s\n", SSL_get_cipher(m_pssl));

		//��ÿͻ���֤��
		cli_cert = SSL_get_peer_certificate(m_pssl);
		LB_ADD_MEM(cli_cert, sizeof(X509));
		if (cli_cert != NULL) {
			printf("Client certificate :\n");
			char* str = X509_NAME_oneline(X509_get_subject_name(cli_cert), 0, 0);
			LB_ADD_MEM(str, strlen(str)+1);
			if (NULL == str)
			{
				lberror("str:%p = X509_NAME_oneline(X509_get_subject_name(client_cert:%p), 0, 0) failed!", str, cli_cert);
				LB_RM_MEM(m_pssl);
				SSL_free(m_pssl);
				m_pssl = NULL;
				return -1;
			}
			printf("\t subject : %s\n", str);
			LB_RM_MEM(str);
			OPENSSL_free(str);

			str = X509_NAME_oneline(X509_get_issuer_name(cli_cert), 0, 0);
			if (NULL == str)
			{
				lberror("str:%p = X509_NAME_oneline(X509_get_issuer_name(client_cert:%p) failed!", str, cli_cert);
				LB_RM_MEM(m_pssl);
				SSL_free(m_pssl);
				m_pssl = NULL;
				return -1;
			}
			LB_ADD_MEM(str, strlen(str)+1);
			printf("\t issuer : %s\n", str);
			LB_RM_MEM(str);
			OPENSSL_free(str);
			LB_RM_MEM(cli_cert);
			X509_free(cli_cert);
			cli_cert = NULL;
		}
		m_nfd = fd;

		return 0;
	}

	int init_connect_socket(SSL_CTX* psslctx, int fd)
	{
		//ʹ�����е�TCP���ӿ���SSLЭ��
		m_pssl = SSL_new(psslctx);
		LB_ADD_MEM(m_pssl, sizeof(SSL));
		if (NULL == m_pssl)
		{
			lberror("m_pssl:%p = SSL_new(psslctx:%p) failed!\n", m_pssl, psslctx);
			return -1;
		}

		SSL_set_fd(m_pssl, fd);

		//����SSL����
		int err = SSL_connect(m_pssl);
		if (err < 0)
		{
			lberror("err:%d = SSL_connect(m_pssl:%p)", err, m_pssl);
			LB_RM_MEM(m_pssl);
			SSL_free(m_pssl);
			m_pssl = NULL;
		}
		m_nfd = fd;

		return 0;
	}

	virtual int read(char* pbuff, int len)
	{
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return -1;
		}

		return SSL_read(m_pssl, pbuff, len);
	}

	virtual int write(char* pbuff, int len)
	{
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return -1;
		}

		return SSL_write(m_pssl, pbuff, len);
	}
	/*virtual int read(void* pbuf, int len)
	{
		if (NULL == m_pssl || INVALID_SOCKET == m_nfd)
		{
			lberror("ssl socket not init, m_pssl:%p, m_nfd:%d\n", m_pssl, m_nfd);
			return -1;
		}

		return SSL_read(m_pssl, pbuf, len);
	}

	virtual int write(void* pbuf, int len)
	{
		if (NULL == m_pssl || INVALID_SOCKET == m_nfd)
		{
			lberror("ssl socket not init, m_pssl:%p, m_nfd:%d\n", m_pssl, m_nfd);
			return -1;
		}

		return SSL_write(m_pssl, pbuf, len);
	}*/

	virtual void close()
	{
		if (m_pssl)
		{
			LB_RM_MEM(m_pssl);
			SSL_free(m_pssl);
			m_pssl = NULL;
		}
		if (INVALID_SOCKET != m_nfd)
		{
#ifdef WIN32
			closesocket(m_nfd);
#else
			::close(m_nfd);
#endif
			m_nfd = INVALID_SOCKET;
		}
	}
};

class CTLSSocket:public CTCPSocket
{
private:
	tls_version		m_eTLSVer;
	char*			m_pcert_path;
	char*			m_pkey_path;
	char*			m_pkey_pwd;
	SSL_CTX*		m_pssl_ctx;
	SSL*			m_pssl;
public:
	CTLSSocket(tls_version tls_ver, const char* cert_path = NULL, const char* key_path = NULL, const char* key_pwd = NULL)
	{
		m_nfd			= INVALID_SOCKET;
		m_eTLSVer		= tls_ver;
		m_pcert_path	= NULL;
		m_pkey_path		= NULL;
		m_pkey_pwd		= NULL;
		m_pssl_ctx		= NULL;
		m_pssl			= NULL;
		int len			= 0;
		if (cert_path && ((len = strlen(cert_path)) > 0))
		{
			m_pcert_path = new char[len+1];
			LB_ADD_MEM(m_pcert_path, len+1);
			memcpy(m_pcert_path, cert_path, len + 1 );
		}

		if (key_path && ((len = strlen(key_path)) > 0))
		{
			m_pkey_path = new char[len + 1];
			LB_ADD_MEM(m_pkey_path, len+1);
			memcpy(m_pkey_path, key_path, len + 1);
		}

		if (key_pwd && ((len = strlen(key_pwd)) > 0))
		{
			m_pkey_pwd = new char[len + 1];
			LB_ADD_MEM(m_pkey_pwd, len+1);
			memcpy(m_pkey_pwd, key_pwd, len + 1);
		}
	}

	~CTLSSocket()
	{
		close();
	}

	int init_cert(tls_version tls_ver, const char* cert_path = NULL, const char* key_path = NULL, const char* key_pwd = NULL)
	{
		int ret = -1;
		do
		{

			//��ʼ��OpenSSL����
			/*SSL_load_error_strings();

			SSLeay_add_ssl_algorithms();*/
			SSL_library_init();
			  ERR_load_crypto_strings();
			  SSL_load_error_strings();
			  OpenSSL_add_all_algorithms();

			//����SSLЭ��汾ΪV2V3����Ӧ

			const SSL_METHOD *meth = SSLv23_client_method();//get_ssl_method_by_tls_version(tls_ver); //

			SSL_CTX* sslctx = SSL_CTX_new(meth);
			LB_ADD_MEM(sslctx,sizeof(SSL_CTX));
			//ptlsctx->tls_ver = tls_ver;
			if (!sslctx)
			{
				ERR_print_errors_fp(stderr);
				lberror("SSL_CTX_new failed, sslctx:%p\n", sslctx);
				break;
			}
			if (cert_path)
			{
				//���÷�����֤��
				ret = SSL_CTX_use_certificate_file(sslctx, cert_path, SSL_FILETYPE_PEM);
				if (ret <= 0)
				{
					ERR_print_errors_fp(stderr);
					lberror("SSL_CTX_use_certificate_file failed, cert_path:%s, ret:%d\n", cert_path, ret);
					break;
				}
			}

			if (key_path)
			{
				// add password for key
				if (key_pwd)
				{
					SSL_CTX_set_default_passwd_cb(sslctx, pem_password_callback);
					SSL_CTX_set_default_passwd_cb_userdata(sslctx, this);
					if (key_pwd != m_pkey_pwd)
					{
						/*if (m_pkey_pwd)
						{
							delete[] m_pkey_pwd;
							LB_RM_MEM(m_pkey_pwd);
							m_pkey_pwd = NULL;
						}*/
						LB_DEL_ARR(m_pkey_pwd);
						m_pkey_pwd = copy_string(key_pwd);
					}
				}

				//���÷�����˽Կ
				ret = SSL_CTX_use_PrivateKey_file(sslctx, key_path, SSL_FILETYPE_PEM);
				if (ret <= 0)
				{
					ERR_print_errors_fp(stderr);
					lberror("SSL_CTX_use_PrivateKey_file failed, key_path:%s, ret:%d\n", key_path, ret);
					break;
				}
			}

			if (cert_path && key_path)
			{
				//���˽Կ��֤���Ƿ�ƥ��
				ret = SSL_CTX_check_private_key(sslctx);
				if (!ret) {

					fprintf(stderr, "Private key does not match the certificate public key.\n");
					lberror("SSL_CTX_check_private_key failed, ret:%d, cert_path:%s, key_path:%s\n", ret, cert_path, key_path);
					break;

				}
			}
			m_pssl_ctx = sslctx;
			/*if (m_pcert_path)
			{
				delete[] m_pcert_path;

				m_pcert_path = NULL;
			}*/
			LB_DEL_ARR(m_pcert_path);
			m_pcert_path = copy_string(cert_path);

			/*if (m_pkey_path)
			{
				delete[] m_pkey_path;
				m_pkey_path = NULL;
			}*/
			LB_DEL_ARR(m_pkey_path);
			m_pkey_path = copy_string(key_path);
			return 0;
		} while (0);

		return -1;
	}

	virtual int init_socket(int fd = INVALID_SOCKET)
	{
		int ret = CTCPSocket::init_socket(fd);
		if (ret < 0)
		{
			lberror("ret:%d = CTCPSocket::init_socket(fd:%d) failed!\n", ret, fd);
			return ret;
		}

		ret = init_cert(m_eTLSVer, m_pcert_path, m_pkey_path, m_pkey_pwd);
		if (ret < 0)
		{
			lberror("ret:%d = init_cert(m_eTLSVer:%d, m_pcert_path:%s, m_pkey_path:%s, m_pkey_pwd:%s) failed!", ret, m_eTLSVer, m_pcert_path, m_pkey_path, m_pkey_pwd);
		}
		return ret;
	}

	virtual ITCPSocket* accept()
	{
		//X509* cli_cert = NULL;
		int ret = -1;
		if (INVALID_SOCKET == m_nfd)
		{
			lberror("tcp sokcet have not init, m_nfd:%d\n", m_nfd);
			return NULL;
		}

		do
		{
			struct sockaddr_in sa_cli;
			socklen_t client_len = sizeof(sa_cli);
			//ptls_accept = (tls_accept_ctx*)malloc(sizeof(tls_accept_ctx));
			int fd = ::accept(m_nfd, (struct sockaddr*)&sa_cli, &client_len);
			if (fd < 0)
			{
				ERR_print_errors_fp(stderr);
				lberror("fd:%d = accept(ptlsctx->fd:%d, (struct sockaddr*)&sa_cli, (int*)&client_len:%d) failed\n", fd, m_nfd, client_len);
				break;
			}
			CSSLSocket* psslskt = new CSSLSocket();
			LB_ADD_MEM(psslskt, sizeof(CSSLSocket));
			ret = psslskt->init_accept_socket(m_pssl_ctx, fd);
			if (ret < 0)
			{
				lberror("ret:%d = psslskt->init_socket(fd:%d)\n", ret, fd);
				//LB_RM_MEM(psslskt);
				//delete psslskt;
				//psslskt = NULL;
				LB_DEL(psslskt);
			}
			return psslskt;
		} while (0);

		return NULL;
	}

	virtual int connect(const char* ip, int port)
	{
		lbtrace("tls connect(ip:%s, port:%d)\n", ip, port);
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
		lbtrace("hostname:%s has ip address %s\n", ip, inet_ntoa(sa_in.sin_addr));
		int ret = ::connect(m_nfd, (struct sockaddr*) &sa_in, sizeof(sa_in));
		if (ret < 0)
		{
			lberror("ret:%d = connect(m_nfd:%d, (struct sockaddr*) &sa, sizeof(sa)) failed!\n", ret, m_nfd);
			return ret;
		}
		lbtrace("ret:%d = ::connect(m_nfd, (struct sockaddr*) &sa_in, sizeof(sa_in))\n", ret);
		//ʹ�����е�TCP���ӿ���SSLЭ��
		m_pssl = SSL_new(m_pssl_ctx);
		LB_ADD_MEM(m_pssl, sizeof(SSL));
		if (NULL == m_pssl)
		{
			lberror("m_pssl:%p = SSL_new(m_pssl_ctx:%p) failed!\n", m_pssl, m_pssl_ctx);
			return -1;
		}

		SSL_set_fd(m_pssl, m_nfd);

		//����SSL����
		ret = SSL_connect(m_pssl);
		lbtrace("ret:%d = SSL_connect(m_pssl:%p)\n", ret, m_pssl);
		if (ret < 0)
		{
			lberror("ret:%d = SSL_connect(ssl:%p)", ret, m_pssl);
			LB_RM_MEM(m_pssl);
			SSL_free(m_pssl);
			return ret;
		}

		return ret;
	}
	virtual int read(char* pbuff, int len)
	//virtual int read(char* pbuff, int len)
	{
		if (NULL == m_pssl || INVALID_SOCKET == m_nfd)
		{
			lberror("ssl socket not init, m_pssl:%p, m_nfd:%d\n", m_pssl, m_nfd);
			return -1;
		}

		int ret = SSL_read(m_pssl, pbuff, len);
		//lbtrace("ret:%d = SSL_read(m_pssl, pbuff:%s, len:%d)\n", ret, pbuff, len);
		return ret;
	}

	virtual int write(char* pbuff, int len)
	{
		if (NULL == m_pssl || INVALID_SOCKET == m_nfd)
		{
			lberror("ssl socket not init, m_pssl:%p, m_nfd:%d\n", m_pssl, m_nfd);
			return -1;
		}

		int ret = SSL_write(m_pssl, pbuff, len);
		//lbtrace("ret:%d = SSL_write(m_pssl:%p, pbuff:%s, len:%d)\n", ret, m_pssl, pbuff, len);
		return ret;
	}

	virtual void close()
	{
		if (m_pssl)
		{
			LB_RM_MEM(m_pssl);
			SSL_free(m_pssl);
			m_pssl = NULL;
		}
		if (INVALID_SOCKET != m_nfd)
		{
#ifdef WIN32
			closesocket(m_nfd);
#else
			::close(m_nfd);
#endif
			m_nfd = INVALID_SOCKET;
		}

		if (m_pssl_ctx)
		{
			LB_RM_MEM(m_pssl_ctx);
			SSL_CTX_free(m_pssl_ctx);
			m_pssl_ctx = NULL;
		}

		LB_DEL(m_pkey_pwd);
		LB_DEL(m_pkey_path);
		LB_DEL(m_pcert_path);
	}

protected:
	static int pem_password_callback(char *buf, int size, int rwflag, void *userdata)
	{
		CTLSSocket* pthis = (CTLSSocket*)userdata;
		if (pthis && pthis->m_pkey_pwd && size > (int)strlen(pthis->m_pkey_pwd))
		{
			memcpy(buf, pthis->m_pkey_pwd, strlen(pthis->m_pkey_pwd));
			return strlen(pthis->m_pkey_pwd);
		}

		return 0;
	}

	char* copy_string(const char* pstr)
	{
		if (NULL == pstr)
		{
			return NULL;
		}

		int len = strlen(pstr) + 1;
		char*  pnew = new char[len];
		LB_ADD_MEM(pnew, len);
		strcpy(pnew, pstr);
		return pnew;
	}

	const SSL_METHOD* get_ssl_method_by_tls_version(tls_version tls_ver)
	{
		switch (tls_ver)
		{
		case TLS_SERVER_VERSION_V1:
			return TLSv1_server_method();
		case TLS_SERVER_VERSION_V1_1:
			return TLSv1_1_server_method();
		case TLS_SERVER_VERSION_V1_2:
			return TLSv1_2_server_method();
		/*case TLS_SERVER_VERSION_V2_3:
			return SSLv23_server_method();*/
		case TLS_SERVER_VERSION_TOP_MOST:
			return SSLv23_server_method();
		/*case DTSL_SERVER_VERSION_V1:
			return DTLSv1_server_method();
		case DTSL_SERVER_VERSION_V1_2:
			return DTLSv1_2_server_method();
		case DTLS_SERVER_VERSION_TOP_MOST:
			return DTLS_server_method();*/
		case TLS_CLIENT_VERSION_V1:
			return TLSv1_client_method();
		case TLS_CLIENT_VERSION_V1_1:
			return TLSv1_1_client_method();
		case TLS_CLIENT_VERSION_V1_2:
			return TLSv1_2_client_method();
		case TLS_CLIENT_VERSION_TOP_MOST:
			return SSLv23_client_method();
		/*case DTSL_CLIENT_VERSION_V1:
			return DTLSv1_client_method();
		case DTSL_CLIENT_VERSION_V1_2:
			return DTLSv1_2_client_method();
		case DTLS_CLIENT_VERSION_TOP_MOST:
			return DTLS_client_method();*/
		default:
			assert(0);
			return NULL;
		}
	}

};

class CTLSSocketManager
{
protected:
	CTLSSocketManager()
	{

	}

public:
	~CTLSSocketManager()
	{

	}

	const CTLSSocketManager& getInst()
	{
		return m_sslsktmgr;
	}
	int add_tls_socket(int skt, CSSLSocket* psslskt)
	{
		//std::lock_guard<std::recursive_mutex>	lock(m_mutex);
		if (INVALID_SOCKET == skt)
		{
			printf("Invalid socket, skt:%d\n", skt);
			return -1;
		}
		int skt_type = -1;
		socklen_t len = sizeof(skt_type);
		getsockopt(skt, SOL_SOCKET, SO_TYPE, (char*)&skt_type, &len);
		if (skt_type != SOCK_STREAM)
		{
			lbtrace("skt:%d type:%d is not SOCK_STREAM\n", skt, skt_type);
			return -1;
		}
		std::map<int, CSSLSocket*>::iterator it = m_msslsktlist.find(skt);
		if (it != m_msslsktlist.end())
		{
			m_msslsktlist[skt] = psslskt;
			return 0;
		}
		assert(0);
		return -1;
	}

	int write(int skt, char* pbuf, int len, int flag)
	{
		//std::lock_guard<std::recursive_mutex>	lock(m_mutex);
		CSSLSocket* psslskt = get_ssl_by_socket(skt);
		int ret = 0;
		if (psslskt)
		{
			ret = psslskt->write(pbuf, len);
		}
		else
		{
			ret = send(skt, pbuf, len, flag);
		}

		return ret;
	}

	int read(int skt, char* pbuf, int len, int flag)
	{
		//std::lock_guard<std::recursive_mutex>	lock(m_mutex);
		CSSLSocket* psslskt = get_ssl_by_socket(skt);
		int ret = 0;
		if (psslskt)
		{
			ret = psslskt->read(pbuf, len);
		}
		else
		{
			ret = recv(skt, pbuf, len, flag);
		}

		return ret;
	}

	/*int write(int skt, char* pbuf, int len, int flag)
	{
		std::lock_guard<std::recursive_mutex>	lock(m_mutex);
		CSSLSocket* psslskt = get_ssl_by_socket(skt);
		int ret = 0;
		if (psslskt)
		{
			ret = psslskt->write(pbuf, len);
		}
		else
		{
			ret = send(skt, pbuf, len, flag);
		}

		return ret;
	}

	int read(int skt, char* pbuf, int len, int flag)
	{
		std::lock_guard<std::recursive_mutex>	lock(m_mutex);
		CSSLSocket* psslskt = get_ssl_by_socket(skt);
		int ret = 0;
		if (psslskt)
		{
			ret = psslskt->read(pbuf, len);
		}
		else
		{
			ret = recv(skt, pbuf, len, flag);
		}

		return ret;
	}*/

	int write(int skt, struct in_addr address, int16_t portNum, char* pbuf, int len, int flag)
	{
		//std::lock_guard<std::recursive_mutex>	lock(m_mutex);
		CSSLSocket* psslskt = get_ssl_by_socket(skt);
		int ret = 0;
		if (psslskt)
		{
			ret = psslskt->write(pbuf, len);
		}
		else
		{
			struct sockaddr_in dest;
			dest.sin_family = AF_INET;
			dest.sin_addr.s_addr = address.s_addr;
			dest.sin_port = (portNum);
			int addrlen = sizeof(dest);
			//SET_SOCKADDR_SIN_LEN(var);
			ret = sendto(skt, pbuf, len, flag, (struct sockaddr*)&dest, addrlen);
		}

		return ret;
	}

	int read(int skt, struct in_addr address, int16_t portNum, char* pbuf, int len, int flag)
	{
		//std::lock_guard<std::recursive_mutex>	lock(m_mutex);
		CSSLSocket* psslskt = get_ssl_by_socket(skt);
		//CSSLSocket* psslskt = get_ssl_by_socket(skt);
		int ret = 0;
		if (psslskt)
		{
			ret = psslskt->read(pbuf, len);
		}
		else
		{
			struct sockaddr_in dest;
			dest.sin_family = AF_INET;
			dest.sin_addr.s_addr = address.s_addr;
			dest.sin_port = (portNum);
			socklen_t addrlen = sizeof(dest);
			//SET_SOCKADDR_SIN_LEN(var);
			ret = recvfrom(skt, pbuf, len, flag, (struct sockaddr*)&dest, &addrlen);
		}

		return ret;
	}
protected:
	CSSLSocket* get_ssl_by_socket(int skt)
	{
		std::map<int, CSSLSocket*>::iterator it = m_msslsktlist.find(skt);
		if (it != m_msslsktlist.end())
		{
			return it->second;
		}

		return NULL;
	}
protected:
	std::map<int, CSSLSocket*>		m_msslsktlist;
	//std::recursive_mutex			m_mutex;
	static CTLSSocketManager		m_sslsktmgr;
};
