
#pragma once

#include "common_defs.h"


/**********************************************************************************************************************************/
/*                                                                                                                                */
/*  Important Note:                                                                                                               */
/*            This file contains decleration & definition of one class.                                                           */
/*                                                                                                                                */
/*            This file is supposed to be a source file (*.cpp), the only reason                                                  */
/*            it is a *.cuh file (header file) is that, it is used in CUDA code (for GPU) so functions are defined as __device__  */
/*            It is also used in normal code to run on CPU                                                                        */
/*                                                                                                                                */
/*            So I (Pouya) had to define a (*.cuh) file to include in both .cu and .cpp files to run it both on GPU and CPU       */
/*                                                                                                                                */
/*                                                                                                                                */
/*                                                                                                                                */
/*				This implementation of Rijndael was created by Steven M.Gibson of GRC.com.										  */
/*                                                                                                                                */
/*				It is intended for general purpose use, but was written in support of GRC's										  */
/*				reference implementation of the SQRL(Secure Quick Reliable Login) client.										  */
/*                                                                                                                                */
/*				See:    http://csrc.nist.gov/archive/aes/rijndael/wsdindex.html													  */
/*                                                                                                                                */
/*				NO COPYRIGHT IS CLAIMED IN THIS WORK, HOWEVER, NEITHER IS ANY WARRANTY MADE										  */
/*				REGARDING ITS FITNESS FOR ANY PARTICULAR PURPOSE.USE IT AT YOUR OWN RISK.										  */
/*                                                                                                                                */
/*                                                                                                                                */
/*      The original implementation by Steven M.Gibson of GRC.com was functional and in C,									      */
/*                                                                                                                                */
/* it is a bit changed to better fit in C++ by Pouya Ebadollahyvahed (all changes are Released to Public Domain with no warranty) */
/*                                                                                                                                */
/**********************************************************************************************************************************/


enum ENCRYPTION_MODE { MODE_ENCRYPT, MODE_DECRYPT };


// cipher context, holds inter-call data
struct AES_CNTX
{
	ENCRYPTION_MODE mode;
	int				rounds;     // keysize-based rounds count
	uint32T*		roundKey;	// pointer to current round key
	uint32T			buf[68];    // key expansion buffer
};


// GCM context, holds keytables, instance data, and AES context
struct GCM_CNTX
{
	ENCRYPTION_MODE mode;
	uint64T			len;			// cipher data length processed so far
	uint64T			addLen;			// total add data length
	uint64T			HTableLo[16];	// precalculated lo-half HTable
	uint64T			HTableHi[16];	// precalculated hi-half HTable
	uint08T			baseCntr[16];	// first counter-mode cipher output for tag
	uint08T			ivCntr[16];		// the current cipher-input IV|Counter value
	uint08T			buf[16];		// buf working value
	AES_CNTX		aesCtx;			// cipher context used
};


/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       AES_GCM_IMPL                                                             */
/*                                                          Class                                                                 */
/*                                                                                                                                */
/*  A concrete class, which implements mathematical algorithms of AES-GCM                                                         */
/*                                                                                                                                */
/*                                                                                                                                */
/*  AES-GCM Operation has this order & steps: 								  													  */
/*                                                                                                                                */
/*	While()																														  */
/*  {                                                                                                                             */
/*		1- gcm_setkey(): sets AES & GCM keying materials																		  */
/*                                                                                                                                */
/*		2- gcm_start(): Sets the Encryption / Decryption mode Accepts the initialization vector and additional data				  */
/*                                                                                                                                */
/*			3- gcm_process(): Encrypts or decrypts the plaintext or ciphertext													  */
/*			3- ...................																								  */
/*			3- gcm_process(): This function can be called as many times as needed to encrypt/decrypt messages					  */
/*                                                                                                                                */
/*		4- gcm_finish(): Performs a final GHASH to generate the authentication tag												  */
/*  }                                                                                                                             */
/*                                                                                                                                */
/**********************************************************************************************************************************/

class AES_GCM_IMPL
{

public:

	// Default Constructor fills the AES key expansion tables with static data.This is not "per key" data, but static system - wide read - only table data
	__device__ AES_GCM_IMPL()
	{
		int pow[256], log[256], index, x, y, z; // x, y & z are general purpose variables

		for (index = 0, x = 1; index < 256; index++) // fill the 'pow' and 'log' tables over GF(2^8)
		{
			pow[index] = x;
			log[x] = index;
			x = (x ^ xTime(x)) & 0xFF;
		}

		for (index = 0, x = 1; index < 10; index++)
		{
			m_round_constants[index] = (uint32T)x;
			x = xTime(x) & 0xFF;
		}

		m_substit_box_forward[0x00] = 0x63;
		m_substit_box_reverse[0x63] = 0x00;

		for (index = 1; index < 256; index++)
		{
			x = y = pow[255 - log[index]];
			mix(x, y);
			mix(x, y);
			mix(x, y);
			mix(x, y);
			m_substit_box_forward[index] = (uint08T)(x ^= 0x63);
			m_substit_box_reverse[x] = (uint08T)index;
		}

		for (index = 0; index < 256; index++) // generate the forward and reverse key expansion tables
		{
			x = m_substit_box_forward[index];
			y = xTime(x) & 0xFF;
			z = (y ^ x) & 0xFF;

			m_table_forward[0][index] = ((uint32T)y) ^ ((uint32T)x << 8) ^ ((uint32T)x << 16) ^ ((uint32T)z << 24);
			m_table_forward[1][index] = rotate_left_8bits(m_table_forward[0][index]);
			m_table_forward[2][index] = rotate_left_8bits(m_table_forward[1][index]);
			m_table_forward[3][index] = rotate_left_8bits(m_table_forward[2][index]);

			x = m_substit_box_reverse[index];

			m_table_reverse[0][index] = ((uint32T)mul(0x0E, x, pow, log)) ^ ((uint32T)mul(0x09, x, pow, log) << 8) ^ ((uint32T)mul(0x0D, x, pow, log) << 16) ^ ((uint32T)mul(0x0B, x, pow, log) << 24);
			m_table_reverse[1][index] = rotate_left_8bits(m_table_reverse[0][index]);
			m_table_reverse[2][index] = rotate_left_8bits(m_table_reverse[1][index]);
			m_table_reverse[3][index] = rotate_left_8bits(m_table_reverse[2][index]);
		}
	}


	__device__ inline bool gcm_setkey(GCM_CNTX* ctx, const uint08T* key, const uint32T keysize);
	__device__ inline void gcm_start(GCM_CNTX* ctx, ENCRYPTION_MODE mode, const uint08T* iv, uint32T iv_len, const uint08T* add, uint32T add_len);
	__device__ inline void gcm_process(GCM_CNTX* ctx, uint32T length, const uint08T* input, uint08T* output);
	__device__ inline void gcm_finish(GCM_CNTX* ctx, uint08T* tag, uint32T tag_len);



protected:

	uint32T m_round_constants[10];									// AES round constants
	uint08T m_substit_box_forward[256], m_substit_box_reverse[256];	// Forward & Reverse key schedule assembly tables, Reverse used for Decryption ONLY
	uint32T m_table_forward[4][256], m_table_reverse[4][256];		// For key expansion


	__device__ inline void gcm_mult(GCM_CNTX* ctx, const uint08T x[16], uint08T output[16]);

	__device__ inline bool aes_set_encryption_key(AES_CNTX* ctx, const uint08T* key, uint32T keysize);
	__device__ inline bool aes_set_decryption_key(AES_CNTX* ctx, const uint08T* key, uint32T keysize);
	__device__ inline bool aes_setkey(AES_CNTX* ctx, ENCRYPTION_MODE mode, const uint08T* key, uint32T keysize);
	__device__ inline void aes_cipher(AES_CNTX* ctx, const uint08T input[16], uint08T output[16]);


	/**********************************************************************************************************************************/
	/*                                                Inline Helper Members Functions                                                 */
	/**********************************************************************************************************************************/

	__device__ void make_32bit_from_8bits_BE(uint64T& out_32bit, const uint08T in_8bit[])
	{
		out_32bit = ((uint32T)in_8bit[0] << 24) | ((uint32T)in_8bit[1] << 16) | ((uint32T)in_8bit[2] << 8) | ((uint32T)in_8bit[3]);
	}


	__device__ void make_32bit_from_8bits_LE(uint32T& out_32bit, const uint08T in_8bit[])
	{
		out_32bit = ((uint32T)in_8bit[0]) | ((uint32T)in_8bit[1] << 8) | ((uint32T)in_8bit[2] << 16) | ((uint32T)in_8bit[3] << 24);
	}


	__device__ void make_8bits_from_32bit_BE(const uint32T in_32bit, uint08T out_8bit[])
	{
		out_8bit[0] = (uint08T)(in_32bit >> 24);
		out_8bit[1] = (uint08T)(in_32bit >> 16);
		out_8bit[2] = (uint08T)(in_32bit >> 8);
		out_8bit[3] = (uint08T)(in_32bit);
	}


	__device__ void make_8bits_from_32bit_LE(const uint32T in_32bit, uint08T out_8bit[])
	{
		out_8bit[0] = (uint08T)(in_32bit);
		out_8bit[1] = (uint08T)(in_32bit >> 8);
		out_8bit[2] = (uint08T)(in_32bit >> 16);
		out_8bit[3] = (uint08T)(in_32bit >> 24);
	}


	__device__ uint32T rotate_left_8bits(const uint32T valInput)
	{
		return ((valInput << 8) & 0xFFFFFFFF) | (valInput >> 24);
	}


	__device__ int xTime(const int valInput)
	{
		return ((valInput << 1) ^ ((valInput & 0x80) ? 0x1B : 0x00));
	}


	__device__ void mix(int& valInput1, int& valInput2)
	{
		valInput2 = ((valInput2 << 1) | (valInput2 >> 7)) & 0xFF;
		valInput1 ^= valInput2;
	}


	__device__ int mul(int valInput1, int valInput2, int pow[], int log[])
	{
		return (valInput2 ? pow[(log[valInput1] + log[valInput2]) % 0xFF] : 0);
	}


	__device__ uint32T* aes_round_reverse(uint32T X[], uint32T Y[], uint32T* pRoundKey)
	{
		X[0] = *pRoundKey++ ^ m_table_reverse[0][Y[0] & 0xFF] ^ m_table_reverse[1][(Y[3] >> 8) & 0xFF] ^ m_table_reverse[2][(Y[2] >> 16) & 0xFF] ^ m_table_reverse[3][(Y[1] >> 24) & 0xFF];
		X[1] = *pRoundKey++ ^ m_table_reverse[0][Y[1] & 0xFF] ^ m_table_reverse[1][(Y[0] >> 8) & 0xFF] ^ m_table_reverse[2][(Y[3] >> 16) & 0xFF] ^ m_table_reverse[3][(Y[2] >> 24) & 0xFF];
		X[2] = *pRoundKey++ ^ m_table_reverse[0][Y[2] & 0xFF] ^ m_table_reverse[1][(Y[1] >> 8) & 0xFF] ^ m_table_reverse[2][(Y[0] >> 16) & 0xFF] ^ m_table_reverse[3][(Y[3] >> 24) & 0xFF];
		X[3] = *pRoundKey++ ^ m_table_reverse[0][Y[3] & 0xFF] ^ m_table_reverse[1][(Y[2] >> 8) & 0xFF] ^ m_table_reverse[2][(Y[1] >> 16) & 0xFF] ^ m_table_reverse[3][(Y[0] >> 24) & 0xFF];

		return pRoundKey;
	}


	__device__ uint32T* aes_round_forward(uint32T X[], uint32T Y[], uint32T *pRoundKey)
	{
		X[0] = *pRoundKey++ ^ m_table_forward[0][Y[0] & 0xFF] ^ m_table_forward[1][(Y[1] >> 8) & 0xFF] ^ m_table_forward[2][(Y[2] >> 16) & 0xFF] ^ m_table_forward[3][(Y[3] >> 24) & 0xFF];
		X[1] = *pRoundKey++ ^ m_table_forward[0][Y[1] & 0xFF] ^ m_table_forward[1][(Y[2] >> 8) & 0xFF] ^ m_table_forward[2][(Y[3] >> 16) & 0xFF] ^ m_table_forward[3][(Y[0] >> 24) & 0xFF];
		X[2] = *pRoundKey++ ^ m_table_forward[0][Y[2] & 0xFF] ^ m_table_forward[1][(Y[3] >> 8) & 0xFF] ^ m_table_forward[2][(Y[0] >> 16) & 0xFF] ^ m_table_forward[3][(Y[1] >> 24) & 0xFF];
		X[3] = *pRoundKey++ ^ m_table_forward[0][Y[3] & 0xFF] ^ m_table_forward[1][(Y[0] >> 8) & 0xFF] ^ m_table_forward[2][(Y[1] >> 16) & 0xFF] ^ m_table_forward[3][(Y[2] >> 24) & 0xFF];

		return pRoundKey;
	}
};



/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       AES_GCM_IMPL                                                             */
/*                                                                                                                                */
/*                                                   Class Member Functions                                                       */
/*                                                                                                                                */
/*  A concrete class, which implements mathematical algorithms of AES-GCM                                                         */
/*                                                                                                                                */
/**********************************************************************************************************************************/


/***********************************************************************************************************************************
 *  aes_set_encryption_key()
 *
 *  This is called by 'aes_setkey' when we're establishing a key for subsequent encryption.  We give it a pointer to the
 *  encryption context, a pointer to the key, and the key's length in bytes. Valid lengths are: 16, 24 or 32 bytes (128, 192, 256 bits).
 *
 ************************************************************************************************************************************/

__device__ inline bool AES_GCM_IMPL::aes_set_encryption_key(AES_CNTX* ctx, const uint08T* key, uint32T keysize)
{
	uint32T index, * pRoundKey = ctx->roundKey;

	for (index = 0; index < (keysize >> 2); index++)
		make_32bit_from_8bits_LE(pRoundKey[index], &(key[index << 2]));

	switch (ctx->rounds)
	{
	case 10:
		for (index = 0; index < 10; index++, pRoundKey += 4)
		{
			pRoundKey[4] = pRoundKey[0] ^ m_round_constants[index] ^ ((uint32T)m_substit_box_forward[(pRoundKey[3] >> 8) & 0xFF]) ^ ((uint32T)m_substit_box_forward[(pRoundKey[3] >> 16) & 0xFF] << 8) ^ ((uint32T)m_substit_box_forward[(pRoundKey[3] >> 24) & 0xFF] << 16) ^ ((uint32T)m_substit_box_forward[(pRoundKey[3]) & 0xFF] << 24);
			pRoundKey[5] = pRoundKey[1] ^ pRoundKey[4];
			pRoundKey[6] = pRoundKey[2] ^ pRoundKey[5];
			pRoundKey[7] = pRoundKey[3] ^ pRoundKey[6];
		}
		break;

	case 12:
		for (index = 0; index < 8; index++, pRoundKey += 6)
		{
			pRoundKey[6] = pRoundKey[0] ^ m_round_constants[index] ^ ((uint32T)m_substit_box_forward[(pRoundKey[5] >> 8) & 0xFF]) ^ ((uint32T)m_substit_box_forward[(pRoundKey[5] >> 16) & 0xFF] << 8) ^ ((uint32T)m_substit_box_forward[(pRoundKey[5] >> 24) & 0xFF] << 16) ^ ((uint32T)m_substit_box_forward[(pRoundKey[5]) & 0xFF] << 24);
			pRoundKey[7] = pRoundKey[1] ^ pRoundKey[6];
			pRoundKey[8] = pRoundKey[2] ^ pRoundKey[7];
			pRoundKey[9] = pRoundKey[3] ^ pRoundKey[8];
			pRoundKey[10] = pRoundKey[4] ^ pRoundKey[9];
			pRoundKey[11] = pRoundKey[5] ^ pRoundKey[10];
		}
		break;

	case 14:
		for (index = 0; index < 7; index++, pRoundKey += 8)
		{
			pRoundKey[8] = pRoundKey[0] ^ m_round_constants[index] ^ ((uint32T)m_substit_box_forward[(pRoundKey[7] >> 8) & 0xFF]) ^ ((uint32T)m_substit_box_forward[(pRoundKey[7] >> 16) & 0xFF] << 8) ^ ((uint32T)m_substit_box_forward[(pRoundKey[7] >> 24) & 0xFF] << 16) ^ ((uint32T)m_substit_box_forward[(pRoundKey[7]) & 0xFF] << 24);
			pRoundKey[9] = pRoundKey[1] ^ pRoundKey[8];
			pRoundKey[10] = pRoundKey[2] ^ pRoundKey[9];
			pRoundKey[11] = pRoundKey[3] ^ pRoundKey[10];

			pRoundKey[12] = pRoundKey[4] ^ ((uint32T)m_substit_box_forward[(pRoundKey[11]) & 0xFF]) ^ ((uint32T)m_substit_box_forward[(pRoundKey[11] >> 8) & 0xFF] << 8) ^ ((uint32T)m_substit_box_forward[(pRoundKey[11] >> 16) & 0xFF] << 16) ^ ((uint32T)m_substit_box_forward[(pRoundKey[11] >> 24) & 0xFF] << 24);
			pRoundKey[13] = pRoundKey[5] ^ pRoundKey[12];
			pRoundKey[14] = pRoundKey[6] ^ pRoundKey[13];
			pRoundKey[15] = pRoundKey[7] ^ pRoundKey[14];
		}
		break;

	default:
		return false;
	}

	return true;
}


/***********************************************************************************************************************************
 *  aes_set_decryption_key()
 *
 *  This is called by 'aes_setkey' when we're establishing a key for subsequent decryption.  We give it a pointer to
 *  the encryption context, a pointer to the key, and the key's length in bits. Valid lengths are: 128, 192, or 256 bits.
 *
 ************************************************************************************************************************************/

__device__ inline bool AES_GCM_IMPL::aes_set_decryption_key(AES_CNTX* ctx, const uint08T* key, uint32T keysize)
{
	AES_CNTX cty;            // a calling aes context for set_encryption_key
	uint32T* pSKey, * pRoundKey = ctx->roundKey;
	int index1, index2;

	cty.rounds = ctx->rounds;
	cty.roundKey = cty.buf;     // round count and key buf pointer

	if (false == aes_set_encryption_key(&cty, key, keysize))
		return (false);

	pSKey = cty.roundKey + cty.rounds * 4;

	*pRoundKey++ = *pSKey++; // copy a 128-bit block
	*pRoundKey++ = *pSKey++;
	*pRoundKey++ = *pSKey++;
	*pRoundKey++ = *pSKey++;

	for (index1 = ctx->rounds - 1, pSKey -= 8; index1 > 0; index1--, pSKey -= 8)
		for (index2 = 0; index2 < 4; index2++, pSKey++)
			*pRoundKey++ = m_table_reverse[0][m_substit_box_forward[(*pSKey) & 0xFF]] ^ m_table_reverse[1][m_substit_box_forward[(*pSKey >> 8) & 0xFF]] ^ m_table_reverse[2][m_substit_box_forward[(*pSKey >> 16) & 0xFF]] ^ m_table_reverse[3][m_substit_box_forward[(*pSKey >> 24) & 0xFF]];


	*pRoundKey++ = *pSKey++; // copy a 128-bit block
	*pRoundKey++ = *pSKey++;
	*pRoundKey++ = *pSKey++;
	*pRoundKey++ = *pSKey++;

	memset(&cty, 0, sizeof(AES_CNTX));   // clear local aes context

	return true;
}


/***********************************************************************************************************************************
 *  aes_setkey()
 *
 *  is called to expand the key for encryption or decryption, Valid lengths for key are: 16, 24, 32 for 128, 192, or 256 bit keys
 *
 ************************************************************************************************************************************/

__device__ inline bool AES_GCM_IMPL::aes_setkey(AES_CNTX* ctx, ENCRYPTION_MODE mode, const uint08T* key, uint32T keysize)
{
	ctx->mode = mode;
	ctx->roundKey = ctx->buf;

	switch (keysize)
	{
	case 16: ctx->rounds = 10; break;   // 16-byte: 128-bit key
	case 24: ctx->rounds = 12; break;   // 24-byte: 192-bit key
	case 32: ctx->rounds = 14; break;   // 32-byte: 256-bit key
	default: return(false);
	}

	if (MODE_DECRYPT == mode)   // expand our key for encryption or decryption
		return(aes_set_decryption_key(ctx, key, keysize));
	else
		return(aes_set_encryption_key(ctx, key, keysize));
}


/***********************************************************************************************************************************
*  aes_cipher()
 *
 *  being called to encrypt or decrypt ONE 128-bit block of data
 *
 ************************************************************************************************************************************/

__device__ inline void AES_GCM_IMPL::aes_cipher(AES_CNTX* ctx, const uint08T input_block_128bit[16], uint08T output_block_128bit[16])
{
	uint32T	X[4], Y[4], * pRoundKey = ctx->roundKey;
	int		index;

	make_32bit_from_8bits_LE(X[0], &(input_block_128bit[0])); X[0] ^= *pRoundKey++; // load our 128-bit input buffer in a storage memory endian-neutral way
	make_32bit_from_8bits_LE(X[1], &(input_block_128bit[4])); X[1] ^= *pRoundKey++;
	make_32bit_from_8bits_LE(X[2], &(input_block_128bit[8])); X[2] ^= *pRoundKey++;
	make_32bit_from_8bits_LE(X[3], &(input_block_128bit[12])); X[3] ^= *pRoundKey++;


	if (MODE_DECRYPT == ctx->mode)
	{
		for (index = (ctx->rounds >> 1) - 1; index > 0; index--)
		{
			pRoundKey= aes_round_reverse(Y, X, pRoundKey);
			pRoundKey= aes_round_reverse(X, Y, pRoundKey);
		}

		pRoundKey= aes_round_reverse(Y, X, pRoundKey);

		X[0] = *pRoundKey++ ^ ((uint32T)m_substit_box_reverse[(Y[0]) & 0xFF]) ^ ((uint32T)m_substit_box_reverse[(Y[3] >> 8) & 0xFF] << 8) ^ ((uint32T)m_substit_box_reverse[(Y[2] >> 16) & 0xFF] << 16) ^ ((uint32T)m_substit_box_reverse[(Y[1] >> 24) & 0xFF] << 24);
		X[1] = *pRoundKey++ ^ ((uint32T)m_substit_box_reverse[(Y[1]) & 0xFF]) ^ ((uint32T)m_substit_box_reverse[(Y[0] >> 8) & 0xFF] << 8) ^ ((uint32T)m_substit_box_reverse[(Y[3] >> 16) & 0xFF] << 16) ^ ((uint32T)m_substit_box_reverse[(Y[2] >> 24) & 0xFF] << 24);
		X[2] = *pRoundKey++ ^ ((uint32T)m_substit_box_reverse[(Y[2]) & 0xFF]) ^ ((uint32T)m_substit_box_reverse[(Y[1] >> 8) & 0xFF] << 8) ^ ((uint32T)m_substit_box_reverse[(Y[0] >> 16) & 0xFF] << 16) ^ ((uint32T)m_substit_box_reverse[(Y[3] >> 24) & 0xFF] << 24);
		X[3] = *pRoundKey++ ^ ((uint32T)m_substit_box_reverse[(Y[3]) & 0xFF]) ^ ((uint32T)m_substit_box_reverse[(Y[2] >> 8) & 0xFF] << 8) ^ ((uint32T)m_substit_box_reverse[(Y[1] >> 16) & 0xFF] << 16) ^ ((uint32T)m_substit_box_reverse[(Y[0] >> 24) & 0xFF] << 24);
	}
	else
	{
		for (index = (ctx->rounds >> 1) - 1; index > 0; index--)
		{
			pRoundKey= aes_round_forward(Y, X, pRoundKey);
			pRoundKey= aes_round_forward(X, Y, pRoundKey);
		}

		pRoundKey= aes_round_forward(Y, X, pRoundKey);

		X[0] = *pRoundKey++ ^ ((uint32T)m_substit_box_forward[(Y[0]) & 0xFF]) ^ ((uint32T)m_substit_box_forward[(Y[1] >> 8) & 0xFF] << 8) ^ ((uint32T)m_substit_box_forward[(Y[2] >> 16) & 0xFF] << 16) ^ ((uint32T)m_substit_box_forward[(Y[3] >> 24) & 0xFF] << 24);
		X[1] = *pRoundKey++ ^ ((uint32T)m_substit_box_forward[(Y[1]) & 0xFF]) ^ ((uint32T)m_substit_box_forward[(Y[2] >> 8) & 0xFF] << 8) ^ ((uint32T)m_substit_box_forward[(Y[3] >> 16) & 0xFF] << 16) ^ ((uint32T)m_substit_box_forward[(Y[0] >> 24) & 0xFF] << 24);
		X[2] = *pRoundKey++ ^ ((uint32T)m_substit_box_forward[(Y[2]) & 0xFF]) ^ ((uint32T)m_substit_box_forward[(Y[3] >> 8) & 0xFF] << 8) ^ ((uint32T)m_substit_box_forward[(Y[0] >> 16) & 0xFF] << 16) ^ ((uint32T)m_substit_box_forward[(Y[1] >> 24) & 0xFF] << 24);
		X[3] = *pRoundKey++ ^ ((uint32T)m_substit_box_forward[(Y[3]) & 0xFF]) ^ ((uint32T)m_substit_box_forward[(Y[0] >> 8) & 0xFF] << 8) ^ ((uint32T)m_substit_box_forward[(Y[1] >> 16) & 0xFF] << 16) ^ ((uint32T)m_substit_box_forward[(Y[2] >> 24) & 0xFF] << 24);
	}

	make_8bits_from_32bit_LE(X[0], output_block_128bit);
	make_8bits_from_32bit_LE(X[1], &(output_block_128bit[4]));
	make_8bits_from_32bit_LE(X[2], &(output_block_128bit[8]));
	make_8bits_from_32bit_LE(X[3], &(output_block_128bit[12]));
}


/***********************************************************************************************************************************
* gcm_mult()
*
* Performs a GHASH operation on the 128 - bit input vector 'x',
* setting the 128 - bit output vector to 'x' times H using our precomputed tables.
* 'x' and 'output' are seen as elements of GCM's GF(2^128) Galois field.
*
************************************************************************************************************************************/

__device__ inline void AES_GCM_IMPL::gcm_mult(GCM_CNTX* ctx, const uint08T inputVector[16], uint08T outputVector[16])
{
	// This 16-entry table of pre-computed constants is used to improve over a strictly table-free but significantly slower 128x128 bit multiple within GF(2^128)
	static const uint64T last4[16] = { 0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
		0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0 };

	int      index;
	uint08T lo, hi, rem;
	uint64T zh, zl;

	lo = (uint08T)(inputVector[15] & 0x0f);
	hi = (uint08T)(inputVector[15] >> 4);
	zh = ctx->HTableHi[lo];
	zl = ctx->HTableLo[lo];

	for (index = 15; index >= 0; index--)
	{
		lo = (uint08T)(inputVector[index] & 0x0f);
		hi = (uint08T)(inputVector[index] >> 4);

		if (15 != index)
		{
			rem = (uint08T)(zl & 0x0f);
			zl = (zh << 60) | (zl >> 4);
			zh = (zh >> 4);
			zh ^= (uint64T)last4[rem] << 48;
			zh ^= ctx->HTableHi[lo];
			zl ^= ctx->HTableLo[lo];
		}
		rem = (uint08T)(zl & 0x0f);
		zl = (zh << 60) | (zl >> 4);
		zh = (zh >> 4);
		zh ^= (uint64T)last4[rem] << 48;
		zh ^= ctx->HTableHi[hi];
		zl ^= ctx->HTableLo[hi];
	}

	make_8bits_from_32bit_BE((uint32T)(zh >> 32), outputVector);
	make_8bits_from_32bit_BE((uint32T)(zh), &(outputVector[4]));
	make_8bits_from_32bit_BE((uint32T)(zl >> 32), &(outputVector[8]));
	make_8bits_from_32bit_BE((uint32T)(zl), &(outputVector[12]));
}


/***********************************************************************************************************************************
* gcm_setkey()
*
* sets the GCM (and AES) keying material for use; It initializes the AES key and populates the gcm context's pre-calculated HTables.
* keysize in bytes must be 16, 24, 32 for 128, 192 or 256-bit keys respectively. 
*
************************************************************************************************************************************/

__device__ inline bool AES_GCM_IMPL::gcm_setkey(GCM_CNTX* ctx, const uint08T* key, const uint32T keysize)
{
	int     index, index2;
	uint64T block_hi, block_lo, vl, vh, * HiL, * HiH;
	uint32T T;
	uint08T block_buffer[16];

	memset(ctx, 0, sizeof(GCM_CNTX));  // zero caller-provided GCM context
	memset(block_buffer, 0, 16);                     // initialize the block to encrypt

	// encrypt the null 128-bit block to generate a key-based value which is then used to initialize our GHASH lookup tables
	if (false == aes_setkey(&ctx->aesCtx, MODE_ENCRYPT, key, keysize))
		return(false);

	aes_cipher(&ctx->aesCtx, block_buffer, block_buffer);

	make_32bit_from_8bits_BE(block_hi, block_buffer);    // pack h as two 64-bit ints, big-endian
	make_32bit_from_8bits_BE(block_lo, &(block_buffer[4]));
	vh = (uint64T)block_hi << 32 | block_lo;

	make_32bit_from_8bits_BE(block_hi, &(block_buffer[8]));
	make_32bit_from_8bits_BE(block_lo, &(block_buffer[12]));
	vl = (uint64T)block_hi << 32 | block_lo;

	ctx->HTableLo[8] = vl;           // 8 = 1000 corresponds to 1 in GF(2^128)
	ctx->HTableHi[8] = vh;
	ctx->HTableHi[0] = 0;            // 0 corresponds to 0 in GF(2^128)
	ctx->HTableLo[0] = 0;

	for (index = 4; index > 0; index >>= 1)
	{
		T = (uint32T)(vl & 1) * 0xe1000000U;
		vl = (vh << 63) | (vl >> 1);
		vh = (vh >> 1) ^ ((uint64T)T << 32);
		ctx->HTableLo[index] = vl;
		ctx->HTableHi[index] = vh;
	}

	for (index = 2; index < 16; index <<= 1)
	{
		HiL = ctx->HTableLo + index;
		HiH = ctx->HTableHi + index;
		vh = *HiH;
		vl = *HiL;
		for (index2 = 1; index2 < index; index2++)
		{
			HiH[index2] = vh ^ ctx->HTableHi[index2];
			HiL[index2] = vl ^ ctx->HTableLo[index2];
		}
	}

	return true;
}


/***********************************************************************************************************************************
 *  gcm_start()
 *
 * Given a user-provided GCM context, this initializes it, sets the encryption mode, and
 * preprocesses the initialization vector and additional AEAD data.
 *
 * ctx : is user provided GCM context
 * mode: ENCRYPT or DECRYPT
 * iv  : initialization vector, the length should be 12
 * add : is AEAD data or NULL
 *
 ************************************************************************************************************************************/

__device__ inline void AES_GCM_IMPL::gcm_start(GCM_CNTX* ctx, ENCRYPTION_MODE mode, const uint08T* iv, uint32T iv_len, const uint08T* add, uint32T add_len)
{
	const uint08T* pTemp;
	uint08T work_buf[16];	// XOR source built from provided IV if len != 16
	uint32T index, use_len;	// byte count to process, up to 16 bytes


	memset(ctx->ivCntr, 0x00, sizeof(ctx->ivCntr)); // since the context might be reused under the same key, we zero the working buffers for this next new process
	memset(ctx->buf, 0x00, sizeof(ctx->buf));

	ctx->len = 0;
	ctx->addLen = 0;
	ctx->mode = mode;
	ctx->aesCtx.mode = MODE_ENCRYPT;   // GCM *always* runs AES in ENCRYPTION mode

	if (12 == iv_len)
	{                                                               // GCM natively uses a 12-byte, 96-bit IV
		memcpy(ctx->ivCntr, iv, iv_len);							// copy the IV to the top of the 'y' buff
		ctx->ivCntr[15] = 1;                                        // start "counting" from 1 (not 0)
	}
	else    // if we don't have a 12-byte IV, we GHASH whatever we've been given
	{
		memset(work_buf, 0x00, 16);								// clear the working buffer
		make_8bits_from_32bit_BE(iv_len * 8, &(work_buf[12]));  // place the IV into buffer

		pTemp = iv;
		while (iv_len > 0)
		{
			use_len = (iv_len < 16) ? iv_len : 16;
			for (index = 0; index < use_len; index++)
				ctx->ivCntr[index] ^= pTemp[index];

			gcm_mult(ctx, ctx->ivCntr, ctx->ivCntr);
			iv_len -= use_len;
			pTemp += use_len;
		}
		for (index = 0; index < 16; index++)
			ctx->ivCntr[index] ^= work_buf[index];
		gcm_mult(ctx, ctx->ivCntr, ctx->ivCntr);
	}

	aes_cipher(&ctx->aesCtx, ctx->ivCntr, ctx->baseCntr);

	ctx->addLen = add_len;
	pTemp = add;
	while (add_len > 0)
	{
		use_len = (add_len < 16) ? add_len : 16;
		for (index = 0; index < use_len; index++)
			ctx->buf[index] ^= pTemp[index];

		gcm_mult(ctx, ctx->buf, ctx->buf);
		add_len -= use_len;
		pTemp += use_len;
	}
}


/***********************************************************************************************************************************
 *  gcm_process()
 *
 *  This is called once or more to process bulk plaintext or ciphertext data.
 *
 *  Size of output will be equal to size of input. If called multiple times (which is fine) all but the final
 *  invocation MUST be called with length mod 16 == 0. (Only the final call can have a partial block length of < 128 bits.)
 *
 ************************************************************************************************************************************/

__device__ inline void AES_GCM_IMPL::gcm_process(GCM_CNTX* ctx, uint32T data_length, const uint08T* input_data, uint08T* output_data)
{
	uint08T ecntr[16];			// counter-mode cipher output for XORing
	uint32T index, use_len;		// byte count to process, up to 16 bytes


	ctx->len += data_length;	// bump the GCM context's running length count

	while (data_length > 0)
	{
		use_len = (data_length < 16) ? data_length : 16; // clamp the length to process at 16 bytes

		for (index = 16; index > 12; index--)			// increment the context's 128-bit IV||Counter 'y' vector
			if (++ctx->ivCntr[index - 1] != 0)
				break;

		aes_cipher(&ctx->aesCtx, ctx->ivCntr, ecntr);  // encrypt the context's 'y' vector under the established key


		if (MODE_ENCRYPT == ctx->mode)					// encrypt or decrypt the input to the output
		{
			for (index = 0; index < use_len; index++)
			{
				output_data[index] = (uint08T)(ecntr[index] ^ input_data[index]); // XOR the cipher's ouptut vector (ectr) with our input

				// now we mix in our data into the authentication hash. if we're ENcrypting we XOR in the post-XOR (output) results, but if we're DEcrypting we XOR in the input data
				ctx->buf[index] ^= output_data[index];
			}
		}
		else
		{
			for (index = 0; index < use_len; index++)
			{
				// but if we're DEcrypting we XOR in the input data first, i.e. before saving to ouput data, otherwise if the input and output buffer are the same (inplace decryption) 
				// we would not get the correct auth tag

				ctx->buf[index] ^= input_data[index];

				// XOR the cipher's ouptut vector (ectr) with our input
				output_data[index] = (uint08T)(ecntr[index] ^ input_data[index]);
			}
		}
		gcm_mult(ctx, ctx->buf, ctx->buf);    // perform a GHASH operation

		data_length -= use_len;		// drop the remaining byte count to process
		input_data += use_len;		// bump our input pointer forward
		output_data += use_len;		// bump our output pointer forward
	}
}


/***********************************************************************************************************************************
 *  gcm_finish()
 *
 * This is called once after all calls to gcm_process() to finalize the GCM.
 * It performs the final GHASH to produce the resulting authentication TAG.
 *
 ************************************************************************************************************************************/

__device__ inline void AES_GCM_IMPL::gcm_finish(GCM_CNTX* ctx, uint08T* tag, uint32T tag_len)
{
	uint08T work_buf[16];
	uint32T index;
	uint64T orig_len{ ctx->len * 8 }, orig_add_len{ ctx->addLen * 8 };

	if (0 != tag_len)
		memcpy(tag, ctx->baseCntr, tag_len);

	if ((0 != orig_len) || (0 != orig_add_len))
	{
		memset(work_buf, 0x00, 16);

		make_8bits_from_32bit_BE((uint32T)(orig_add_len >> 32), work_buf);
		make_8bits_from_32bit_BE((uint32T)(orig_add_len), &(work_buf[4]));
		make_8bits_from_32bit_BE((uint32T)(orig_len >> 32), &(work_buf[8]));
		make_8bits_from_32bit_BE((uint32T)(orig_len), &(work_buf[12]));

		for (index = 0; index < 16; index++)
			ctx->buf[index] ^= work_buf[index];

		gcm_mult(ctx, ctx->buf, ctx->buf);

		for (index = 0; index < tag_len; index++)
			tag[index] ^= ctx->buf[index];
	}
}
