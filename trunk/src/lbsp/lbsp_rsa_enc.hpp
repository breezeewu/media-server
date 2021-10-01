/**************************************************************************************
Copyright (C), 2018-2025, LeBo Technology Co.,Ltd.
File name:     mediasendermanager.h
Author:        zwu
Version:       1.0.0
Date:          2018-5-30
Description:   This class implement aes encrypt and decrypt
Platform:      windows,linux, ardroid
***************************************************************************************/
#ifndef LBSP_RSA_ENCRYPT_H_
#define LBSP_RSA_ENCRYPT_H_
#include <openssl/rsa.h>
#include <openssl/pem.h>
# include <openssl/bio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <srs_kernel_log.hpp>
#define lberror(...)  srs_error(__VA_ARGS__)
extern char pubkey[];
extern char prikey[];
using namespace std;
#define CheckPointer(ptr, ret) if(NULL == ptr) {return ret;}
//struct RSA;
class rsaenc
{
public:
rsaenc()
{
    m_pRSAPublic    = NULL;
    m_pRSAPrivate   = NULL;
    m_pRsaBuffer    = NULL;
    //m_pBio          = NULL;
    m_iRsaBufLen    = 0;
    m_iPaddMode     = 0;
}

~rsaenc()
{
    deinit();
}

int init_public_key(string pub_key, int paddmode)
{
    //RSA* prsa = RSA_new();
    //LB_ADD_MEM(prsa, sizeof(int));
    BIO* pbio = BIO_new_mem_buf(const_cast<char*>(pub_key.data()), static_cast<int>(pub_key.size()));
    LB_ADD_MEM(pbio, sizeof(BIO*));
    //if (!bio) throw Poco::IOException("Cannot create BIO for reading public key");
    m_pRSAPublic = PEM_read_bio_RSA_PUBKEY(pbio, NULL, 0, 0);
    LB_ADD_MEM(m_pRSAPublic, sizeof(RSA*));
    /*m_pRSAPublic = PEM_read_bio_RSAPublicKey(bio, &prsa, 0, 0);
    if (!m_pRSAPublic)
    {
        int rc = BIO_reset(bio);
        // BIO_reset() normally returns 1 for success and 0 or -1 for failure. 
        // File BIOs are an exception, they return 0 for success and -1 for failure.
        //if (rc != 1) throw Poco::FileException("Failed to load public key");
        m_pRSAPublic = PEM_read_bio_RSA_PUBKEY(bio, &prsa, 0, 0);
    }*/
    BIO_free(pbio);

    if (!m_pRSAPublic)
    {
        //RSA_free(prsa);
        return -1;
        //throw Poco::FileException("Failed to load public key");
    }

    m_iRsaSize = RSA_size(m_pRSAPublic);

    if (NULL == m_pRsaBuffer || m_iRsaBufLen < m_iRsaSize)
    {
        LB_DEL_ARR(m_pRsaBuffer);
        /*if (m_pRsaBuffer)
        {

            delete[] m_pRsaBuffer;
            LB_RM_MEM(m_pRsaBuffer);
            m_pRsaBuffer = NULL;
        }*/
        m_pRsaBuffer = new uint8_t[m_iRsaSize];
        LB_ADD_MEM(m_pRsaBuffer, m_iRsaSize);
        memset(m_pRsaBuffer, 0, m_iRsaSize);
        m_iRsaBufLen = m_iRsaSize;
    }
    m_iPos = 0;
    m_iPaddMode = paddmode;
    return 0;
}

int init_private_key(string priv_key, int paddmode)
{
    if (NULL == m_pRSAPrivate)
    {
        m_pRSAPrivate = RSA_new();
    }

    BIO* bio = BIO_new_mem_buf(const_cast<char*>(priv_key.c_str()), static_cast<int>(priv_key.length()));
    //if (!bio) throw Poco::IOException("Cannot create BIO for reading public key");
    RSA* pRSAPrivate = PEM_read_bio_RSAPrivateKey(bio, &m_pRSAPrivate, 0, 0);
    
    BIO_free(bio);
    if (!pRSAPrivate)
    {
        RSA_free(m_pRSAPrivate);
        return -1;
        //throw Poco::FileException("Failed to load public key");
    }

    m_iRsaSize = RSA_size(m_pRSAPrivate);

    if (NULL == m_pRsaBuffer || m_iRsaBufLen < m_iRsaSize)
    {
        LB_DEL_ARR(m_pRsaBuffer);
        /*if (m_pRsaBuffer)
        {
            delete[] m_pRsaBuffer;
            LB_RM_MEM(m_pRsaBuffer);
            m_pRsaBuffer = NULL;
        }*/
        m_pRsaBuffer = new uint8_t[m_iRsaSize];
        LB_ADD_MEM(m_pRsaBuffer, m_iRsaSize);
        memset(m_pRsaBuffer, 0, m_iRsaSize);
        m_iRsaBufLen = m_iRsaSize;
    }
    m_iPos = 0;
    m_iPaddMode = paddmode;
    return 0;
}

int public_encrypt(const uint8_t* pdata, int len, uint8_t* poutdata, int* poutlen)
{
	CheckPointer(pdata, -1);
	CheckPointer(poutdata, -1);
	CheckPointer(poutlen, -1);
	unsigned char* pin = (unsigned char*)pdata;
	unsigned char* pout = poutdata;
	int maxenclen = m_iRsaSize;
	if (RSA_PKCS1_PADDING == m_iPaddMode)
	{
		//RSA_PKCS1_PADDINGģʽ�£�ÿ�μ��ܵ����ݳ��ȱ��� ��RSAԿģ��(modulus)������11���ֽ�, Ҳ����RSA_size(rsa)�C11
		maxenclen = m_iRsaSize - 11;
	}
	
	while (len > 0)
	{
		int enclen = len > maxenclen ? maxenclen : len;
		int ret = RSA_public_encrypt(enclen, pin, pout, const_cast<RSA*>(m_pRSAPublic), m_iPaddMode);
		if (ret < 0)
		{
			assert(0);
			return ret;
		}
		pin += enclen;
		pout += ret;
		len -= enclen;
	}
	if (poutlen)
	{
		*poutlen = pout - poutdata;
	}
	return 0;
	
	const uint8_t* input = (const uint8_t*)pdata;
	int inputLength = len;
	int outputLength = *poutlen;
	uint8_t* poutput = poutdata;
	int rc = 0;
	std::streamsize missing = 0;
	while (inputLength > 0 || missing > 0)
	{
		// check how many data bytes we are missing to get the buffer full
		//poco_assert_dbg(m_iRsaSize >= _pos);
		missing = m_iRsaSize - m_iPos;
		if (missing == 0)
		{
			int tmp = RSA_public_encrypt(static_cast<int>(m_iRsaSize), m_pRsaBuffer, poutput, const_cast<RSA*>(m_pRSAPublic), m_iPaddMode);
			if (tmp == -1)
				assert(0);
			rc += tmp;
			poutput += tmp;
			outputLength -= tmp;
			m_iPos = 0;
			pdata += static_cast<int>(m_iRsaSize);

		}
		else
		{
			if (missing > inputLength)
				missing = inputLength;

			memcpy(m_pRsaBuffer + m_iPos, pdata, missing);
			input += missing;
			m_iPos += missing;
			inputLength -= missing;
		}
	}

	if (poutlen)
	{
		*poutlen = rc;
	}
	return rc > 0 ? 0 : -1;
}

int public_decrypt(const uint8_t* pdata, int len, uint8_t* poutdata, int* poutlen)
{
    CheckPointer(pdata, -1);
    CheckPointer(poutdata, -1);
    CheckPointer(poutlen, -1);

    const uint8_t* input = (const uint8_t*)pdata;
    int inputLength = len;
    int outputLength = *poutlen;
    uint8_t* poutput = poutdata;
    int rc = 0;
    std::streamsize missing = 0;
    while (inputLength > 0 || missing > 0)
    {
        // check how many data bytes we are missing to get the buffer full
        //poco_assert_dbg(m_iRsaSize >= _pos);
        missing = m_iRsaSize - m_iPos;
        if (missing == 0)
        {
            int tmp = RSA_public_decrypt(static_cast<int>(m_iRsaSize), m_pRsaBuffer, poutput, const_cast<RSA*>(m_pRSAPublic), m_iPaddMode);
            if (tmp == -1)
                assert(0);
            rc += tmp;
            poutput += tmp;
            outputLength -= tmp;
            m_iPos = 0;
            pdata += static_cast<int>(m_iRsaSize);

        }
        else
        {
            if (missing > inputLength)
                missing = inputLength;

            memcpy(m_pRsaBuffer + m_iPos, pdata, missing);
            input += missing;
            m_iPos += missing;
            inputLength -= missing;
        }
    }

    if (poutlen)
    {
        *poutlen = rc;
    }
    return rc > 0 ? 0 : -1;
}
int private_encrypt(const uint8_t* pdata, int len, uint8_t* poutdata, int* poutlen)
{
    CheckPointer(pdata, -1);
    CheckPointer(poutdata, -1);
    CheckPointer(poutlen, -1);
    CheckPointer(m_pRSAPrivate, -1);
    const uint8_t* pin = pdata;
    uint8_t* pout = poutdata;
    int outlen = *poutlen;
    int enclen = 0;
    while (len > 0 && outlen > 0)
    {
        int copylen = len > m_iRsaSize ? m_iRsaSize : len;
        int flen = copylen;
        memset(m_pRsaBuffer, 0, m_iRsaSize);
        memcpy(m_pRsaBuffer, pin, copylen);
        if (RSA_PKCS1_PADDING == m_iPaddMode)
        {
            //RSA_PKCS1_PADDINGģʽ�£�ÿ�μ��ܵ����ݳ��ȱ��� ��RSAԿģ��(modulus)������11���ֽ�, Ҳ����RSA_size(rsa)�C11
            flen = copylen > (m_iRsaSize - 11) ? (m_iRsaSize - 11) : copylen;
        }
        else if (RSA_NO_PADDING == m_iPaddMode)
        {
            flen = m_iRsaSize;
        }
        int ret = RSA_private_encrypt(flen, m_pRsaBuffer, pout, m_pRSAPrivate, m_iPaddMode);
        len -= flen;
        outlen -= ret;
        pin += flen;
        pout += ret;
        enclen += ret;
    }
    if (poutlen)
    {
        *poutlen = enclen;
    }
    return enclen >  0 ? 0 : -1;
}

int private_decrypt(const uint8_t* pdata, int len, uint8_t* poutdata, int* poutlen)
{
	CheckPointer(pdata, -1);
	CheckPointer(poutdata, -1);
	CheckPointer(poutlen, -1);

	const uint8_t* input = (const uint8_t*)pdata;
	int inputLength = len;
	int outputLength = *poutlen;
	uint8_t* poutput = poutdata;
	int rc = 0;
	std::streamsize missing = 0;
	while (inputLength > 0 || missing > 0)
	{
		// check how many data bytes we are missing to get the buffer full
		//poco_assert_dbg(m_iRsaSize >= _pos);
		missing = m_iRsaSize - m_iPos;
		if (missing == 0)
		{
			int tmp = RSA_private_decrypt(static_cast<int>(m_iRsaSize), m_pRsaBuffer, poutput, const_cast<RSA*>(m_pRSAPrivate), m_iPaddMode);
			if (tmp == -1)
            {
                assert(0);
            }
				
			rc += tmp;
			poutput += tmp;
			outputLength -= tmp;
			m_iPos = 0;
			pdata += static_cast<int>(m_iRsaSize);

		}
		else
		{
			if (missing > inputLength)
				missing = inputLength;

			memcpy(m_pRsaBuffer + m_iPos, pdata, missing);
			input += missing;
			m_iPos += missing;
			inputLength -= missing;
		}
	}

	if (poutlen)
	{
		*poutlen = rc;
	}
	return rc > 0 ? 0 : -1;
}

void deinit()
{
    if (m_pRSAPublic)
    {
        RSA_free(m_pRSAPublic);
        m_pRSAPublic = NULL;
    }

    if (m_pRSAPrivate)
    {
        RSA_free(m_pRSAPrivate);
        m_pRSAPrivate = NULL;
    }

    if (m_pRsaBuffer)
    {
        delete[] m_pRsaBuffer;
        LB_RM_MEM(m_pRsaBuffer);
        m_pRsaBuffer = NULL;
    }

    m_iRsaBufLen = 0;
    m_iPos = 0;
}

int private_key_decrypt(const char* ppriv_key, const char* penc_buf, int len, char* pdec_buf, int dec_buf_len, int padding_mode = RSA_PKCS1_PADDING)
{
    if(!ppriv_key || !penc_buf || !pdec_buf || dec_buf_len <= 0)
    {
        lberror("Invalid parameter, ppriv_key:%p || !penc_buf%p || !pdec_buf:%p, dec_buf_len:%d", ppriv_key, penc_buf, pdec_buf, dec_buf_len);
        return -1;
    }
    deinit();
    int ret = init_private_key(ppriv_key, padding_mode);
    //sv_trace("ret:%d = init_private_key(ppriv_key:%s, padding_mode:%d)", ret, ppriv_key, padding_mode);
    if(ret < 0)
    {
        lberror("ret:%d = rsa_enc.init_private_key(ppriv_key) failed", ret);
        return ret;
    }
    ret = private_decrypt((const uint8_t*)penc_buf, len, (uint8_t*)pdec_buf, &dec_buf_len);
    if(ret < 0)
    {
        lberror("ret:%d = rsa_enc.private_decrypt(penc_buf:%p, len:%d, decbuf:%p, &outlen:%d)", ret, penc_buf, len, pdec_buf, dec_buf_len);
        return ret;
    }

    return dec_buf_len;
}

int private_key_encrypt(const char* ppriv_key, const char* porg_buf, int org_len, char* penc_buf, int enc_len, int padding_mode = RSA_PKCS1_PADDING)
{
    if(!ppriv_key || !porg_buf || !penc_buf)
    {
        lberror("Invalid parameter, ppriv_key:%p || !porg_buf:%p || !penc_buf%p", ppriv_key, porg_buf, penc_buf);
        return -1;
    }
    deinit();
    int ret = init_private_key(ppriv_key, padding_mode);
    if(ret < 0)
    {
        lberror("ret:%d = rsa_enc.init_private_key(ppriv_key) failed", ret);
        return ret;
    }
    ret = private_encrypt((const uint8_t*)porg_buf, org_len, (uint8_t*)penc_buf, &enc_len);
    //sv_trace("ret:%d = rsa_enc.private_decrypt((const uint8_t*)penc_buf, len:%d, (uint8_t*)decbuf:%s, &outlen:%d)", ret, len, decbuf, outlen);
    if(ret < 0)
    {
        lberror("ret:%d = rsa_enc.private_decrypt(porg_buf:%p, org_len:%d, penc_buf:%p, &enc_len:%d)", ret, porg_buf, org_len, penc_buf, enc_len);
        return ret;
    }
    
    return enc_len;
}

int public_key_decrypt(const char* ppub_key, const char* penc_buf, int len, char* pdec_buf, int dec_buf_len, int padding_mode = RSA_PKCS1_PADDING)
{
    if(!ppub_key || !penc_buf || len%128 != 0 || !pdec_buf)
    {
        lberror("Invalid parameter, ppub_key:%p || !penc_buf:%p || len:%d/128 != 0 || !pdec_buf:%p", ppub_key, penc_buf, len, pdec_buf);
        return -1;
    }
    deinit();
    int ret = init_public_key(ppub_key, padding_mode);
    if(ret < 0)
    {
        lberror("ret:%d = rsa_enc.init_private_key(ppriv_key) failed", ret);
        return ret;
    }
    ret = public_decrypt((const uint8_t*)penc_buf, len, (uint8_t*)pdec_buf, &dec_buf_len);
    //sv_trace("ret:%d = rsa_enc.private_decrypt((const uint8_t*)penc_buf, len:%d, (uint8_t*)decbuf:%s, &outlen:%d)", ret, len, decbuf, outlen);
    if(ret < 0)
    {
        lberror("ret:%d = rsa_enc.private_decrypt(penc_buf:%p, len:%d, decbuf:%p, &outlen:%d)", ret, penc_buf, len, pdec_buf, dec_buf_len);
        return ret;
    }

    return dec_buf_len;
}

int public_key_encrypt(const char* ppub_key, const char* porg_buf, int org_len, char* penc_buf, int enc_buf_len, int padding_mode = RSA_PKCS1_PADDING)
{
    if(!ppub_key || !porg_buf || !penc_buf)
    {
        lberror("Invalid parameter, ppriv_key:%p || !porg_buf:%p || !penc_buf%p", ppub_key, porg_buf, penc_buf);
        return -1;
    }
    deinit();
    int ret = init_public_key(ppub_key, padding_mode);
    //sv_trace("ret:%d = init_private_key(ppub_key:%s, padding_mode:%d)", ret, ppub_key, padding_mode);
    if(ret < 0)
    {
        lberror("ret:%d = rsa_enc.init_private_key(ppriv_key) failed", ret);
        return ret;
    }
    ret = public_encrypt((const uint8_t*)porg_buf, org_len, (uint8_t*)penc_buf, &enc_buf_len);
    //sv_trace("ret:%d = rsa_enc.private_decrypt((const uint8_t*)penc_buf, len:%d, (uint8_t*)decbuf:%s, &outlen:%d)", ret, len, decbuf, outlen);
    if(ret < 0)
    {
        lberror("ret:%d = rsa_enc.private_decrypt(porg_buf:%p, org_len:%d, penc_buf:%p, &enc_buf_len:%d)", ret, porg_buf, org_len, penc_buf, enc_buf_len);
        return ret;
    }
    
    return enc_buf_len;
}
protected:
    //RSA*             m_pRSA;
    RSA*             m_pRSAPublic;
    RSA*             m_pRSAPrivate;
    int             m_iRsaSize;
    int             m_iPaddMode;
    uint8_t*        m_pRsaBuffer;
    int             m_iRsaBufLen;
    int             m_iPos;
};

#endif