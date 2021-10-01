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

#include <srs_kernel_stream.hpp>

using namespace std;

#include <srs_kernel_log.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_utility.hpp>

SrsStream::SrsStream()
{
    p = bytes = NULL;
    nb_bytes = 0;
    
    // TODO: support both little and big endian.
    srs_assert(srs_is_little_endian());
}

SrsStream::~SrsStream()
{
}

int SrsStream::initialize(char* b, int nb)
{
    int ret = ERROR_SUCCESS;
    
    if (!b) {
        ret = ERROR_KERNEL_STREAM_INIT;
        srs_error("stream param bytes must not be NULL. ret=%d", ret);
        return ret;
    }
    
    if (nb <= 0) {
        ret = ERROR_KERNEL_STREAM_INIT;
        srs_error("stream param size must be positive. ret=%d", ret);
        return ret;
    }

    nb_bytes = nb;
    p = bytes = b;
    srs_info("init stream ok, size=%d", size());

    return ret;
}

char* SrsStream::data()
{
    return bytes;
}

int SrsStream::size()
{
    return nb_bytes;
}

int SrsStream::pos()
{
    return (int)(p - bytes);
}

bool SrsStream::empty()
{
    return !bytes || (p >= bytes + nb_bytes);
}

bool SrsStream::require(int required_size)
{
    srs_assert(required_size >= 0);
    
    return required_size <= nb_bytes - (p - bytes);
}

int SrsStream::remain()
{
    return nb_bytes - pos();
}

void SrsStream::skip(int size)
{
    srs_assert(p);
    
    p += size;
}

int8_t SrsStream::read_1bytes()
{
    srs_assert(require(1));
    
    return (int8_t)*p++;
}

int16_t SrsStream::read_2bytes()
{
    srs_assert(require(2));
    
    int16_t value;
    char* pp = (char*)&value;
    pp[1] = *p++;
    pp[0] = *p++;
    
    return value;
}

int32_t SrsStream::read_3bytes()
{
    srs_assert(require(3));
    
    int32_t value = 0x00;
    char* pp = (char*)&value;
    pp[2] = *p++;
    pp[1] = *p++;
    pp[0] = *p++;
    
    return value;
}

int32_t SrsStream::read_4bytes()
{
    srs_assert(require(4));
    
    int32_t value;
    char* pp = (char*)&value;
    pp[3] = *p++;
    pp[2] = *p++;
    pp[1] = *p++;
    pp[0] = *p++;
    
    return value;
}

int64_t SrsStream::read_8bytes()
{
    srs_assert(require(8));
    
    int64_t value;
    char* pp = (char*)&value;
    pp[7] = *p++;
    pp[6] = *p++;
    pp[5] = *p++;
    pp[4] = *p++;
    pp[3] = *p++;
    pp[2] = *p++;
    pp[1] = *p++;
    pp[0] = *p++;
    
    return value;
}

string SrsStream::read_string(int len)
{
    srs_assert(require(len));
    
    std::string value;
    value.append(p, len);
    
    p += len;
    
    return value;
}

int SrsStream::read_bytes(char* data, int size)
{
    if(!require(size))
    {
        srs_assert(require(size));
        return -1;
    }
    
    memcpy(data, p, size);
    
    p += size;

    return ERROR_SUCCESS;;
}

int SrsStream::write_1bytes(int8_t value)
{
    if(!require(1))
    {
        srs_assert(require(1));
        return -1;
    }
    //srs_assert(require(1));
    
    *p++ = value;
    return ERROR_SUCCESS;
}

int SrsStream::write_2bytes(int16_t value)
{
    if(!require(2))
    {
        srs_assert(require(2));
        return -1;
    }
    
    char* pp = (char*)&value;
    *p++ = pp[1];
    *p++ = pp[0];

    return ERROR_SUCCESS;
}

int SrsStream::write_4bytes(int32_t value)
{
    if(!require(4))
    {
        srs_assert(require(4));
        return -1;
    }
    
    char* pp = (char*)&value;
    *p++ = pp[3];
    *p++ = pp[2];
    *p++ = pp[1];
    *p++ = pp[0];

    return ERROR_SUCCESS;
}

int SrsStream::write_3bytes(int32_t value)
{
    if(!require(3))
    {
        srs_assert(require(3));
        return -1;
    }
    
    char* pp = (char*)&value;
    *p++ = pp[2];
    *p++ = pp[1];
    *p++ = pp[0];

    return ERROR_SUCCESS;
}

int SrsStream::write_8bytes(int64_t value)
{
    if(!require(8))
    {
        srs_assert(require(8));
        return -1;
    }
    
    char* pp = (char*)&value;
    *p++ = pp[7];
    *p++ = pp[6];
    *p++ = pp[5];
    *p++ = pp[4];
    *p++ = pp[3];
    *p++ = pp[2];
    *p++ = pp[1];
    *p++ = pp[0];

    return ERROR_SUCCESS;
}

int SrsStream::write_string(string value)
{
    if(!require(value.length()))
    {
        srs_assert(require(value.length()));
        return -1;
    }
    srs_assert(require((int)value.length()));
    
    memcpy(p, value.data(), value.length());
    p += value.length();

    return ERROR_SUCCESS;
}

int SrsStream::write_bytes(char* data, int size)
{
     if(!require(size))
    {
        srs_assert(require(size));
        return -1;
    }
    //srs_assert(require(size));
    
    memcpy(p, data, size);
    p += size;

    return ERROR_SUCCESS;
}

SrsBitStream::SrsBitStream()
{
    cb = 0;
    cb_left = 0;
    stream = NULL;
}

SrsBitStream::~SrsBitStream()
{
}

int SrsBitStream::initialize(SrsStream* s) {
    stream = s;
    return ERROR_SUCCESS;
}

bool SrsBitStream::empty() {
    if (cb_left) {
        return false;
    }
    return stream->empty();
}

int8_t SrsBitStream::read_bit() {
    if (!cb_left) {
        srs_assert(!stream->empty());
        cb = stream->read_1bytes();
        cb_left = 8;
    }
    
    int8_t v = (cb >> (cb_left - 1)) & 0x01;
    cb_left--;
    return v;
}

CBitStream::CBitStream()
{
    cn_bits_offset = 0;
}

CBitStream::~CBitStream()
{

}

int64_t CBitStream::read_bits(int bits)
{
    int64_t val = 0;
    int bytesoff = 0;
    while(bits > 0)
    {
        val <<= 1;
        val += (p[bytesoff] >> (7 - cn_bits_offset)) & 0x1;
        bytesoff += (cn_bits_offset + 1)/8;
        cn_bits_offset = (cn_bits_offset + 1)%8;
        bits--;
    }
    p += bytesoff;
    return val;
}

int CBitStream::write_bits(int bits, int64_t val)
{
	int bytesoff = 0;
    int writebits = bits;
    //srs_assert(require((bits + cn_bits_offset)/8));
	while(writebits > 0)
	{
		char cval = (char)(val >> (writebits -1));
		cval = (cval & 0x1) << (7 - cn_bits_offset);
		cval = (char)cval & 0xff;
		p[bytesoff] = cval | p[bytesoff];
		bytesoff += (cn_bits_offset + 1)/8;
		cn_bits_offset = (cn_bits_offset + 1)%8;
		writebits--;
	}

	return bits - writebits;
}
int CBitStream::read_uev()
{
    SrsBitStream sbs;
    sbs.initialize(this);
    int val;
    int ret = srs_avc_nalu_read_uev(&sbs, val);
    if(ret != ERROR_SUCCESS)
    {
        assert(0);
    }
    return val;
}

    SrsDeviceSN::SrsDeviceSN()
    {

    }
    SrsDeviceSN::~SrsDeviceSN()
    {

    }

    void SrsDeviceSN::set_device_sn(const std::string& device_sn)
    {
        sdevice_sn = device_sn;
    }

    const char* SrsDeviceSN::get_device_sn(int nbytes)
    {
        int pos = 0;
        int snlen = sdevice_sn.length();
        if(snlen <= 0)
        {
            return NULL;
        }

        if(nbytes <= snlen && nbytes > 0)
        {
            pos = snlen - nbytes;
        }
        
        return sdevice_sn.c_str() + pos;
    }