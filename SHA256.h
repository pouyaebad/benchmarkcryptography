#pragma once

#include "common_defs.h"

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
/*		See:    http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf		                              */
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
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                          SHA256                                                                */
/*                                                          Class                                                                 */
/*                                                                                                                                */
/**********************************************************************************************************************************/

class SHA256
{

public: 
	
	SHA256();

	constexpr int get_hash_size_bytes() const { return 32; }; // SHA256 always outputs a 32 byte digest

	void get_input(const uint08T data[], const size_t len);
	void calculate_hash(uint08T hash[]);


protected:

	struct SHA256_CTX
	{
		uint08T data[64];
		uint32T datalen;
		uint64T bitlen;
		uint32T state[8];
	};

	const uint32T k[64]
	{
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};

	SHA256_CTX m_ctx;

	void initilize();
	void transform();
};
