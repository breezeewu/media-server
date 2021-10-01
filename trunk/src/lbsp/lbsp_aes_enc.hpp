/****************************************************************************************************************
//  lbsp_aes_enc.hpp
//
//  Created by dawson on 2019/3/23.
//  Copyright © 2019 Sunvalley. All rights reserved.
****************************************************************************************************************/

#ifndef __AES_CBC_H_
#define __AES_CBC_H_
#include <stdint.h>
#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/modes.h>
#include <srs_kernel_log.hpp>
#ifndef lbtrace
#define lbtrace srs_trace
#endif
#ifndef lberror
#define lberror srs_error
#endif
#define ENCRYPT_AES_BY_KEY_DIRECTORY
class IAesEnc
{
public:
    virtual ~IAesEnc(){}

/***************************************************************************************************************
 * @describe init aes encoder
 * @param pkey : cipher key for encryption or decryption
 * @param len : cipher key len
 * @param mode : encrypt mode, AES_ENCRYPT, AES_DECRYPT
 * @return Success return 0 , else return -1
***************************************************************************************************************/
    virtual int init(uint8_t* pkey, int len, int mode) = 0;

/***************************************************************************************************************
 * @describe encrypt/decrypt data
 * @param pindata : input data buffer
 * @param poutdata : output data buffer
 * @param len : input/output data buffer length
 * @return Success return 0 , else return -1
***************************************************************************************************************/
    virtual int encrypt(uint8_t* pindata, uint8_t* poutdata, int len) = 0;

/***************************************************************************************************************
 * @describe destroy encoder
 * @return none
***************************************************************************************************************/
    virtual void deinit() = 0;
};

class CAesEnc:public IAesEnc
{
public:
    CAesEnc()
	{
	}
	
    ~CAesEnc()
	{
		deinit();
	}

    virtual int init(uint8_t* pkey, int len, int mode)
	{
		//lbtrace("(pkey:%s, len:%d, mode:%d)", pkey, len, mode);
		int ret = -1;
#ifdef ENCRYPT_AES_BY_KEY_DIRECTORY
		int keylen = len > AES_BLOCK_SIZE ? AES_BLOCK_SIZE : len;
		memset(m_key, 0, 16);
		memcpy(m_key, pkey, keylen);
		//lbtrace("init key:%s, keylen:%d, mode:%d", m_key, keylen, mode);
		m_nenc_mode = mode;
	#else
		uint8_t md5[50] = {0};
		// generate 32 bytes md5 string
		int md5len = genmd5(pkey, len, md5, 50);
		if(md5len <= 0)
		{
			lberror("%s gen md5 failed", pkey);
			return -1;
		}
		// copy 32 bytes md5 to key and kiv
		memcpy(m_key, md5, AES_BLOCK_SIZE);
		memcpy(m_kiv, md5 + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		m_nenc_mode = mode;

#endif
		// init aes encrypt/decrypt key
		if(AES_ENCRYPT == m_nenc_mode)
		{
			ret = AES_set_encrypt_key(m_key, 128, &m_aes_key);
			//lbtrace("ret:%d = AES_set_encrypt_key(m_key, 128, &m_aes_key)", ret);
		}
		else
		{
			ret = AES_set_decrypt_key(m_key, 128, &m_aes_key);
			//lbtrace("ret:%d = AES_set_decrypt_key(m_key, 128, &m_aes_key)", ret);
		}

		if(ret < 0)
		{
			lberror("aes init cbc key failed, pkey:%s, len:%d, mode:%d", pkey, len, mode);
			return ret;
		}
		

		return 0;
	}
#if 1
    virtual int encrypt(uint8_t* pindata, uint8_t* poutdata, int len)
	{
		int enclen = 0;
		int remain_size = len % AES_BLOCK_SIZE;
		len -= remain_size;
		uint8_t* pin = pindata;
		uint8_t* pout = poutdata;
		
		while(enclen < len)
		{
			if(AES_ENCRYPT == m_nenc_mode)
			{
				AES_encrypt(pin, pout, &m_aes_key);
			}
			else
			{
				AES_decrypt(pin, pout, &m_aes_key);
			}
			pin += AES_BLOCK_SIZE;
			pout += AES_BLOCK_SIZE;
			enclen += AES_BLOCK_SIZE;
		}
		//srs_trace("pindata:%p, poutdata:%p, len:%d, enclen:%d, m_nenc_mode:%d", pindata, poutdata, len, enclen, m_nenc_mode);
		if(remain_size > 0 && pindata != poutdata)
		{
			memcpy(pout, pin, remain_size);
		}
		enclen += remain_size;

		return enclen;
	}
#else
    virtual int encrypt(uint8_t* pindata, uint8_t* poutdata, int len)
	{
		int enclen = 0;
		int remain_size = len % AES_BLOCK_SIZE;
		len -= remain_size;
		uint8_t* pin = pindata;
		uint8_t* pout = poutdata;
		uint8_t* pdst = poutdata;
		if(pindata == poutdata)
		{
			pout = m_copybuf;
		}
		while(enclen < len)
		{
			if(AES_ENCRYPT == m_nenc_mode)
			{
				AES_encrypt(pin, pout, &m_aes_key);
			}
			else
			{
				AES_decrypt(pin, pout, &m_aes_key);
			}
			pin += AES_BLOCK_SIZE;
			if(pindata == poutdata)
			{
				memcpy(pdst, m_copybuf, AES_BLOCK_SIZE);
				pdst += AES_BLOCK_SIZE;
			}
			else
			{
				pout += AES_BLOCK_SIZE;
			}
			enclen += AES_BLOCK_SIZE;
		}
		if(remain_size > 0 && pindata != poutdata)
		{
			memcpy(pout, pin, remain_size);
		}
		return enclen + remain_size;
	}
#endif
    virtual void deinit()
	{
		memset(&m_aes_key, 0, sizeof(m_aes_key));
		memset(m_key, 0, sizeof(m_key));
		memset(m_kiv, 0, sizeof(m_kiv));
		memset(m_copybuf, 0, AES_BLOCK_SIZE);
		m_nenc_mode = -1;
	}

	int genmd5(uint8_t* pkey, int len, uint8_t* pmd5, int md5len)
	{
		//lbtrace("(pkey:%s, len:%d, pmd5:%p, md5len:%d)", pkey, len, pmd5, md5len);
		uint8_t tmp[16] = {0};
		int i = 0;
		if(NULL == pkey || NULL == pmd5 || md5len < 16)
		{
			lberror("Invalid pameter, pkey:%p, len:%d, pmd5:%p, md5len:%d", pkey, len, pmd5, md5len);
			return -1;
		}

		memset(pmd5, 0, md5len);
		MD5_CTX md5ctx;
		MD5_Init(&md5ctx);
		MD5_Update(&md5ctx, pkey, len);
		MD5_Final(tmp, &md5ctx);

		for(; i < 16 && i < md5len; i++)
		{
			sprintf((char*)pmd5 + i*2, "%02X", tmp[i]);
		}
		//lbtrace("md5len:%d, pmd5:%s", i*2, pmd5);
		return i*2;
	}

protected:
    AES_KEY     m_aes_key;
    uint8_t     m_key[AES_BLOCK_SIZE];
	uint8_t		m_kiv[AES_BLOCK_SIZE];
    uint8_t     m_copybuf[AES_BLOCK_SIZE];
    int         m_nenc_mode;
};

#endif
