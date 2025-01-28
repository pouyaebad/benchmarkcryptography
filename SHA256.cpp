
#include "pch.h"
#include "sha256.h"


/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                                                                                                */
/*	This implementation of SHA-256 hashing algorithm was created by Brad Conte (brad AT bradconte.com)							  */
/*		Disclaimer: This code is presented "as is" without any guarantees.                                                        */
/*                                                                                                                                */
/*		SHA-256 is one of the three algorithms in the SHA2 specification.														  */
/*		The others, SHA-384 and SHA-512, are not offered in this implementation.												  */
/*		This implementation uses little endian byte order.																		  */
/*                                                                                                                                */
/*		Algorithm specification can be found here :																				  */
/*                                                                                                                                */
/*		See:    http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf									  */
/*                                                                                                                                */
/*                                                                                                                                */
/* These are basic implementations of standard cryptography algorithms, written by Brad Conte(brad@bradconte.com) from scratch    */
/* and without any cross - licensing.They exist to provide publically accessible, restriction - free implementations of popular   */
/* cryptographic algorithms, like AES and SHA - 1. These are primarily intended for educational and pragmatic purposes(such as    */
/* comparing a specification to actual implementation code, or for building an internal application that computes test vectors    */
/* for a product).The algorithms have been tested against standard test vectors.                                                  */
/*                                                                                                                                */
/* This code is released into the public domain free of any restrictions. The author requests acknowledgement if the code is used,*/
/* but does not require it.This code is provided free of any liability and without any quality claims by the author.              */
/*                                                                                                                                */
/* Note that these are *not* cryptographically secure implementations. They have no resistence to side-channel attacks and should */
/* not be used in contexts that need cryptographically secure implementations.                                                    */
/*                                                                                                                                */
/* These algorithms are not optimized for speed or space. They are primarily designed to be easy to read, although some basic     */
/* optimization techniques have been employed.                                                                                    */
/*                                                                                                                                */
/*                                                                                                                                */
/* The original implementation by Brad Conte (brad AT bradconte.com) was functional and in C,							          */
/*                                                                                                                                */
/* it is a bit changed to better fit in C++ by Pouya Ebadollahyvahed (all changes are Released to Public Domain with no warranty) */
/*                                                                                                                                */
/**********************************************************************************************************************************/



/**********************************************************************************************************************************/
/*                                                            Macroes                                                             */
/**********************************************************************************************************************************/


#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))


#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))

#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))



/**********************************************************************************************************************************/
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                          SHA256                                                                */
/*                                                                                                                                */
/*                                                   Class Member Functions                                                       */
/*                                                                                                                                */
/**********************************************************************************************************************************/

SHA256::SHA256()
{
	initilize();
}



void SHA256::initilize()
{
	m_ctx.datalen = 0LL;
	m_ctx.bitlen = 0LL;
	m_ctx.state[0] = 0x6a09e667;
	m_ctx.state[1] = 0xbb67ae85;
	m_ctx.state[2] = 0x3c6ef372;
	m_ctx.state[3] = 0xa54ff53a;
	m_ctx.state[4] = 0x510e527f;
	m_ctx.state[5] = 0x9b05688c;
	m_ctx.state[6] = 0x1f83d9ab;
	m_ctx.state[7] = 0x5be0cd19;
}



void SHA256::get_input(const uint08T data[],const size_t len)
{
	for (size_t index = 0; index < len; ++index)
	{
		m_ctx.data[m_ctx.datalen] = data[index];
		m_ctx.datalen++;

		if (64 == m_ctx.datalen)
		{
			transform();
			m_ctx.bitlen += 512;
			m_ctx.datalen = 0;
		}
	}
}




void SHA256::calculate_hash(uint08T hash[])
{
	uint32T index{ m_ctx.datalen };

	// Pad whatever data is left in the buffer.
	if (m_ctx.datalen < 56)
	{
		m_ctx.data[index++] = 0x80;
		while (index < 56)
			m_ctx.data[index++] = 0x00;
	}
	else
	{
		m_ctx.data[index++] = 0x80;
		while (index < 64)
			m_ctx.data[index++] = 0x00;

		transform();
		std::memset(m_ctx.data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	m_ctx.bitlen += m_ctx.datalen * 8;
	m_ctx.data[63] = (uint08T) m_ctx.bitlen;
	m_ctx.data[62] = (uint08T) (m_ctx.bitlen >> 8);
	m_ctx.data[61] = (uint08T) (m_ctx.bitlen >> 16);
	m_ctx.data[60] = (uint08T) (m_ctx.bitlen >> 24);
	m_ctx.data[59] = (uint08T) (m_ctx.bitlen >> 32);
	m_ctx.data[58] = (uint08T) (m_ctx.bitlen >> 40);
	m_ctx.data[57] = (uint08T) (m_ctx.bitlen >> 48);
	m_ctx.data[56] = (uint08T) (m_ctx.bitlen >> 56);
	transform();

	// Since this implementation uses little endian byte ordering and SHA uses big endian, reverse all the bytes when copying the final state to the output hash.
	for (index = 0; index < 4; ++index)
	{
		hash[index] = (m_ctx.state[0] >> (24 - index * 8)) & 0x000000ff;
		hash[index + 4] = (m_ctx.state[1] >> (24 - index * 8)) & 0x000000ff;
		hash[index + 8] = (m_ctx.state[2] >> (24 - index * 8)) & 0x000000ff;
		hash[index + 12] = (m_ctx.state[3] >> (24 - index * 8)) & 0x000000ff;
		hash[index + 16] = (m_ctx.state[4] >> (24 - index * 8)) & 0x000000ff;
		hash[index + 20] = (m_ctx.state[5] >> (24 - index * 8)) & 0x000000ff;
		hash[index + 24] = (m_ctx.state[6] >> (24 - index * 8)) & 0x000000ff;
		hash[index + 28] = (m_ctx.state[7] >> (24 - index * 8)) & 0x000000ff;
	}

	initilize();
}




void SHA256::transform()
{
	uint32T a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (m_ctx.data[j] << 24) | (m_ctx.data[j + 1] << 16) | (m_ctx.data[j + 2] << 8) | (m_ctx.data[j + 3]);

	for (; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = m_ctx.state[0];
	b = m_ctx.state[1];
	c = m_ctx.state[2];
	d = m_ctx.state[3];
	e = m_ctx.state[4];
	f = m_ctx.state[5];
	g = m_ctx.state[6];
	h = m_ctx.state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	m_ctx.state[0] += a;
	m_ctx.state[1] += b;
	m_ctx.state[2] += c;
	m_ctx.state[3] += d;
	m_ctx.state[4] += e;
	m_ctx.state[5] += f;
	m_ctx.state[6] += g;
	m_ctx.state[7] += h;
}
