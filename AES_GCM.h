//
// Copyright 2024, Pouya Ebadollahyvahed
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files(the “Software”),
// to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, 
// sublicense, and /or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following 
// conditions :
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#pragma once

#include <new>
#include <string>
#include <memory>
#include <atomic>
#include <type_traits>

#include "common_defs.h"


// std::hardware_destructive_interference_size = 64 but for GPU it is not working so I defined by manually
// Contains parameters for 1 record of data to be processed (encrypted, decrypted or authenticated)
template<typename T> struct alignas(64) AES_GCM_PARAMS{
	int keyLength;
	int initVectorLength;
	int assocAuthLength;
	int plainTextLength;
	int CipherTextLength;
	int authTagLength;

	T* key;
	T* initVector;
	T* assocAuth;
	T* plainText;
	T* CipherText;
	T* authTag;

	static_assert(std::is_integral_v<T>, "Only Integral Types are Allowed for AES-GCM Key and Data Variables");
};



/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                         AES_GCM                                                                */
/*                                                          Class                                                                 */
/*                                                                                                                                */
/* Abstract polymorphic class, contains functions to write logs, loads test data file into buffer and so on                       */
/*                                                                                                                                */
/**********************************************************************************************************************************/

class AES_GCM
{
	/**********************************************************************************************************************************/
	/*                                                       Public Members                                                           */
	/**********************************************************************************************************************************/

public:

	AES_GCM();									// Default Constructor
	AES_GCM(const AES_GCM&);					// Copy Constructor
	AES_GCM(AES_GCM&&) noexcept;				// Move Constructor

	AES_GCM& operator=(const AES_GCM&);			// Assignment Operator
	AES_GCM& operator=(AES_GCM&&) noexcept;		// Move Assignment Operator

	virtual ~AES_GCM() = default;				// Destructor


	bool get_is_running() const;
	std::pair<size_t, size_t> get_processed_data_volume() const;


	void load_AES_GCM_Vector_File_to_Buffer(const std::string);
	bool delete_zero_length_data_from_AES_GCM_Vector_Buffer() noexcept;

	// This member function can run as Thread (but 1-thread only, no re-entrance), so it should set m_is_running variable properly
	void run_Benchmark(const long threads_blocks_count = 1L, const long threads_per_block_count = 1L, const long execution_rounds = 1L);

	bool log_write_file(const std::string) const;


	virtual std::string get_platform_name() const = 0;
	virtual std::pair<long, long> get_processing_cores_total() const = 0;


	/**********************************************************************************************************************************/
	/*                                                     Protected Members                                                          */
	/**********************************************************************************************************************************/

protected:

	std::atomic_bool			m_is_running, m_was_thread_running_healthy;

	std::unique_ptr<uint08T[]>	m_buffer_AES_GCM_Vector, m_buffer_AES_GCM_Output;
	size_t						m_buffer_Size; // Length of both of above buffers

	size_t	m_encryption_operations_count, m_dencryption_operations_successful_count, m_authentication_failed_operations_count,
			m_128bit_operations_count, m_192bit_operations_count, m_256bit_operations_count, m_aes_processed_messages_total_length;


	void initilize_object();
	void reset_processed_counters();

	virtual void run_Benchmark_core(const long threads_blocks_count = 1L, const long threads_per_block_count = 1L, const long execution_rounds = 1L) = 0;
};



/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                           Helper                                                               */
/*                                                       Inline Functions                                                         */
/*                                                                                                                                */
/**********************************************************************************************************************************/


template<typename T> __device__ inline uint08T* getOneRecordofData(uint08T* bufVectorData, AES_GCM_PARAMS<T>& aes_gcm_params, uint08T& RecordType)
{
	RecordType = *bufVectorData++;

	if (0 != RecordType)
	{
		aes_gcm_params.keyLength = *bufVectorData++;
		aes_gcm_params.key = (T*)bufVectorData;
		bufVectorData += aes_gcm_params.keyLength;

		aes_gcm_params.initVectorLength = *bufVectorData++;
		aes_gcm_params.initVector = (T*)bufVectorData;
		bufVectorData += aes_gcm_params.initVectorLength;

		aes_gcm_params.assocAuthLength = *bufVectorData++;
		aes_gcm_params.assocAuth = (T*)bufVectorData;
		bufVectorData += aes_gcm_params.assocAuthLength;

		aes_gcm_params.plainTextLength = *bufVectorData++;
		aes_gcm_params.plainText = (T*)bufVectorData;
		bufVectorData += aes_gcm_params.plainTextLength;

		aes_gcm_params.CipherTextLength = *bufVectorData++;
		aes_gcm_params.CipherText = (T*)bufVectorData;
		bufVectorData += aes_gcm_params.CipherTextLength;

		aes_gcm_params.authTagLength = *bufVectorData++;
		aes_gcm_params.authTag = (T*)bufVectorData;
		bufVectorData += aes_gcm_params.authTagLength;
	}

	return bufVectorData;
}


template<typename T> __device__ inline uint08T* setOneRecordofData(uint08T* bufVectorData, const AES_GCM_PARAMS<T>& aes_gcm_params, const uint08T& recordType, uint08T* bufReplacingPlainText = NULL, uint08T* bufReplacingCipherText = NULL)
{
	*bufVectorData++ = recordType;

	if (0 != recordType)
	{
		*bufVectorData++ = (uint08T)aes_gcm_params.keyLength;
		std::memcpy(bufVectorData, (uint08T*)aes_gcm_params.key, aes_gcm_params.keyLength);
		bufVectorData += aes_gcm_params.keyLength;

		*bufVectorData++ = (uint08T)aes_gcm_params.initVectorLength;
		std::memcpy(bufVectorData, (uint08T*)aes_gcm_params.initVector, aes_gcm_params.initVectorLength);
		bufVectorData += aes_gcm_params.initVectorLength;

		*bufVectorData++ = (uint08T)aes_gcm_params.assocAuthLength;
		std::memcpy(bufVectorData, (uint08T*)aes_gcm_params.assocAuth, aes_gcm_params.assocAuthLength);
		bufVectorData += aes_gcm_params.assocAuthLength;

		*bufVectorData++ = (uint08T)aes_gcm_params.plainTextLength;
		if(NULL == bufReplacingPlainText)
			std::memcpy(bufVectorData, (uint08T*)aes_gcm_params.plainText, aes_gcm_params.plainTextLength);
		else
			std::memcpy(bufVectorData, (uint08T*)bufReplacingPlainText, aes_gcm_params.plainTextLength);

		bufVectorData += aes_gcm_params.plainTextLength;

		*bufVectorData++ = (uint08T)aes_gcm_params.CipherTextLength;
		if (NULL == bufReplacingCipherText)
			std::memcpy(bufVectorData, (uint08T*)aes_gcm_params.CipherText, aes_gcm_params.CipherTextLength);
		else
			std::memcpy(bufVectorData, (uint08T*)bufReplacingCipherText, aes_gcm_params.CipherTextLength);
		bufVectorData += aes_gcm_params.CipherTextLength;

		*bufVectorData++ = (uint08T)aes_gcm_params.authTagLength;
		std::memcpy(bufVectorData, (uint08T*)aes_gcm_params.authTag, aes_gcm_params.authTagLength);
		bufVectorData += aes_gcm_params.authTagLength;
	}

	return bufVectorData;
}
