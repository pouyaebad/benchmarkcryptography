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

#include "pch.h"

#include "AES_GCM_CPU.h"

#include <windows.h> // only for getting CPU cores number in get_processing_cores_total() & CPU model in get_platform_name()

#include <exception>
#include <thread>

#include "AES_GCM_IMPL.cuh"
#include "utility.h"


/**********************************************************************************************************************************/
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       AES_GCM_CPU                                                              */
/*                                                                                                                                */
/*                                                   Class Member Functions                                                       */
/*                                                                                                                                */
/* Inherited from AES_GCM and contains copies of AES_GCM_IMPL so it can run AES-GCM on CPU                                        */
/*                                                                                                                                */
/**********************************************************************************************************************************/


AES_GCM_CPU::AES_GCM_CPU() : AES_GCM()  // Default Constructor
{
}


AES_GCM_CPU::AES_GCM_CPU(const AES_GCM_CPU& aes_gcm) : AES_GCM(aes_gcm) // Copy Constructor
{
}


AES_GCM_CPU& AES_GCM_CPU::operator=(const AES_GCM_CPU& rhs)  // Assignment operator
{
	if (this != &rhs)
		AES_GCM::operator=(rhs);

	return *this;
}


AES_GCM_CPU::AES_GCM_CPU(AES_GCM_CPU&& aes_gcm) noexcept : AES_GCM(std::move(aes_gcm))  // Move Constructor
{
}


AES_GCM_CPU& AES_GCM_CPU::operator=(AES_GCM_CPU&& rhs) noexcept  // Move Assignment operator
{
	if (this != &rhs)
		AES_GCM::operator=(std::move(rhs));

	return *this;
}


std::string AES_GCM_CPU::get_platform_name() const
{
	return "CPU, " + get_cpu_name();
}



std::pair<long, long> AES_GCM_CPU::get_processing_cores_total() const
{
	return std::make_pair(1L, get_cpu_cores_count());
}



void AES_GCM_CPU::run_Benchmark_core(const long threads_blocks_count, const long threads_per_block_count, const long execution_rounds)
{
	std::vector<std::thread*> thread_ptrs;
	std::vector<std::unique_ptr<std::thread>> thread_smart_ptr_magazine;    // just to keep objects in the scope, so they won't be deleted
	std::unique_ptr<std::thread> ptrThreadTemp;

	long index{};
	for (; index < threads_blocks_count * threads_per_block_count; index++) // Creating All AES-GCM Threads & Initilizing Them
	{
		if (!(ptrThreadTemp = std::make_unique<std::thread>()))
		{
			std::exception e("Error #AGC-01: Thread Creation Failed...");
			throw e;
		}

		thread_smart_ptr_magazine.push_back(std::move(ptrThreadTemp));
		thread_ptrs.push_back(thread_smart_ptr_magazine[index].get());
	}


	m_was_thread_running_healthy.store(true);


	*(thread_ptrs[0]) = std::thread(&AES_GCM_CPU::run_Encyption_Decryption_Auth_on_Vector, this, execution_rounds, true); // log enabled

	for (index = 1L; index < threads_blocks_count * threads_per_block_count; index++) // Start Running Threads
		*(thread_ptrs[index]) = std::thread(&AES_GCM_CPU::run_Encyption_Decryption_Auth_on_Vector, this, execution_rounds, false);


	for (index = 0L; index < threads_blocks_count * threads_per_block_count; index++) // Wait Till Threads Finish and Join Here
		thread_ptrs[index]->join();



	if (false == m_was_thread_running_healthy.load())
	{
		std::exception e("Error #AGC-02: Execution of Threads for AES-GCM on CPU, Operation Encountered some Errors");
		throw e;
	}
}



// this function is designed to run multi-threaded BUT log_enabled should be enabled ONLY for 1 thread
void AES_GCM_CPU::run_Encyption_Decryption_Auth_on_Vector(const long execution_rounds, const bool log_enabled)
{
	uint08T ct_buf[256], pt_buf[256], tag_buf[256]; // 16 bytes is enough for TAG but I considered 256 bytes for robustness
	GCM_CNTX		ctx;
	AES_GCM_IMPL	aes_gcm_impl;

	size_t	gcm_context_size{ sizeof(GCM_CNTX) };


	// Starting Actual AES-GCM Operations on Test Data ......
	AES_GCM_PARAMS<uint08T>	aes_gcm_params;
	uint08T					recordType, * bufDataVector, * bufDataOutput;

	bufDataOutput = m_buffer_AES_GCM_Output.get();

	for (long execution_index = 0L; execution_index < execution_rounds; execution_index++)
	{
		bufDataVector = m_buffer_AES_GCM_Vector.get();

		// Running for the whole Test-Data_Buffer (vector) Once
		// vector has multiple recrds, each records starts with "Record Type" Byte and then the record itself
		while (true)
		{
			bufDataVector = getOneRecordofData(bufDataVector, aes_gcm_params, recordType);

			if (0 == recordType) // Record Type 0 means end of file
			{
				if (true == log_enabled)
					if (0L == execution_index)
						*bufDataOutput = 0;
				break;
			}


			aes_gcm_impl.gcm_setkey(&ctx, aes_gcm_params.key, (const uint32T)aes_gcm_params.keyLength);// returns false if key length is not 128, 192 or 256 bit


			switch (recordType)   // based upon our record type, run a test...
			{
			case 1:     // Encryption
				aes_gcm_impl.gcm_start(&ctx, MODE_ENCRYPT, aes_gcm_params.initVector, aes_gcm_params.initVectorLength, aes_gcm_params.assocAuth, aes_gcm_params.assocAuthLength);
				aes_gcm_impl.gcm_process(&ctx, aes_gcm_params.plainTextLength, aes_gcm_params.plainText, ct_buf);
				aes_gcm_impl.gcm_finish(&ctx, tag_buf, aes_gcm_params.authTagLength);
				memset(&ctx, 0, gcm_context_size);


				if (true == log_enabled)
					if (0L == execution_index)
					{
						m_encryption_operations_count++;
						m_aes_processed_messages_total_length += (size_t)aes_gcm_params.plainTextLength;

						if (16 == (size_t)aes_gcm_params.keyLength)
							m_128bit_operations_count++;
						else if (24 == (size_t)aes_gcm_params.keyLength)
							m_192bit_operations_count++;
						else if (32 == (size_t)aes_gcm_params.keyLength)
							m_256bit_operations_count++;

						// writing output buffer but replacing ciphered text with our own calculated one
						bufDataOutput = setOneRecordofData(bufDataOutput, aes_gcm_params, recordType, NULL, ct_buf);
					}
				break;

			case 2:   // Decryption OK
			case 3:   // Decryption Failed Because of Authetication (as per Plan)
				aes_gcm_impl.gcm_start(&ctx, MODE_DECRYPT, aes_gcm_params.initVector, aes_gcm_params.initVectorLength, aes_gcm_params.assocAuth, aes_gcm_params.assocAuthLength);
				aes_gcm_impl.gcm_process(&ctx, aes_gcm_params.CipherTextLength, aes_gcm_params.CipherText, pt_buf);
				aes_gcm_impl.gcm_finish(&ctx, tag_buf, aes_gcm_params.authTagLength);
				memset(&ctx, 0, gcm_context_size);


				if (true == log_enabled)
					if (0L == execution_index)
					{
						m_aes_processed_messages_total_length += (size_t)aes_gcm_params.CipherTextLength;

						if (2 == recordType)  // Decryption OK
							m_dencryption_operations_successful_count++;
						else
							m_authentication_failed_operations_count++;


						if (16 == (size_t)aes_gcm_params.keyLength)
							m_128bit_operations_count++;
						else if (24 == (size_t)aes_gcm_params.keyLength)
							m_192bit_operations_count++;
						else if (32 == (size_t)aes_gcm_params.keyLength)
							m_256bit_operations_count++;

						// writing output buffer but replacing plain text with our own calculated one
						bufDataOutput = setOneRecordofData(bufDataOutput, aes_gcm_params, recordType, pt_buf, NULL);


						// Checking authentication result
						/*
						int index{}, diff{};
						for (; index < aes_gcm_params.authTagLength; index++) // now we verify the authentication tag with generated tag
							diff |= (tag_buf[index] ^ aes_gcm_params.authTag[index]);


						if (((0 != diff) && (2 == recordType)) || ((0 == diff) && (3 == recordType)))
						{
							returnedStatParameters[8] = 0x7FFF;
							return;
						}
						*/
					}
				break;

			default: // we should not have any other record type
				m_was_thread_running_healthy.store(false);
				return;

				break;
			}
		}
	}
}
