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

#include "AES_GCM_IPP.h"

#include <exception>
#include <thread>

#include "utility.h"


/**********************************************************************************************************************************/
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       AES_GCM_IPP                                                              */
/*                                                                                                                                */
/*                                                   Class Member Functions                                                       */
/*                                                                                                                                */
/* Inherited from AES_GCM and implements IPP implementation of AES-GCM                                                            */
/*                                                                                                                                */
/**********************************************************************************************************************************/


AES_GCM_IPP::AES_GCM_IPP() : AES_GCM()  // Default Constructor
{
	static_assert(std::is_same_v<Ipp8u, uint08T>, "Only For Logging Purpose, we consider IPP Returned Messages Format as unsigned char");
}


AES_GCM_IPP::AES_GCM_IPP(const AES_GCM_IPP& aes_gcm) : AES_GCM(aes_gcm) // Copy Constructor
{
}


AES_GCM_IPP& AES_GCM_IPP::operator=(const AES_GCM_IPP& rhs)  // Assignment operator
{
	if (this != &rhs)
		AES_GCM::operator=(rhs);

	return *this;
}


AES_GCM_IPP::AES_GCM_IPP(AES_GCM_IPP&& aes_gcm) noexcept : AES_GCM(std::move(aes_gcm))  // Move Constructor
{
}


AES_GCM_IPP& AES_GCM_IPP::operator=(AES_GCM_IPP&& rhs) noexcept  // Move Assignment operator
{
	if (this != &rhs)
		AES_GCM::operator=(std::move(rhs));

	return *this;
}


std::string AES_GCM_IPP::get_platform_name() const
{
	IPP_Features ippfeatures;

	return ("CPU,  Intel oneAPI IPP  " + ippfeatures.IPP_GetLibNameVersion().second);
}



std::pair<long, long> AES_GCM_IPP::get_processing_cores_total() const
{
	return std::make_pair(1L, get_cpu_cores_count());
}



void AES_GCM_IPP::run_Benchmark_core(const long threads_blocks_count, const long threads_per_block_count, const long execution_rounds)
{
	std::vector<std::thread*> thread_ptrs;
	std::vector<std::unique_ptr<std::thread>> thread_smart_ptr_magazine;    // just to keep objects in the scope, so they won't be deleted
	std::unique_ptr<std::thread> ptrThreadTemp;

	long index{};
	for (; index < threads_blocks_count * threads_per_block_count; index++) // Creating All AES-GCM Threads & Initilizing Them
	{
		if (!(ptrThreadTemp = std::make_unique<std::thread>()))
		{
			std::exception e("Error #AGI-01: Thread Creation Failed...");
			throw e;
		}

		thread_smart_ptr_magazine.push_back(std::move(ptrThreadTemp));
		thread_ptrs.push_back(thread_smart_ptr_magazine[index].get());
	}


	m_was_thread_running_healthy.store(true);


	*(thread_ptrs[0]) = std::thread(&AES_GCM_IPP::run_Encyption_Decryption_Auth_on_Vector, this, execution_rounds, true); // log enabled
	
	for (index = 1L; index < threads_blocks_count * threads_per_block_count; index++) // Start Running Threads
		*(thread_ptrs[index]) = std::thread(&AES_GCM_IPP::run_Encyption_Decryption_Auth_on_Vector, this, execution_rounds, false);


	for (index = 0L; index < threads_blocks_count * threads_per_block_count; index++) // Wait Till Threads Finish and Join Here
		thread_ptrs[index]->join();



	if (false == m_was_thread_running_healthy.load())
	{
		std::exception e("Error #AGI-02: Execution of Threads for AES-GCM IPP Operation Encountered some Errors");
		throw e;
	}
}



// this function is designed to run multi-threaded BUT log_enabled should be enabled ONLY for 1 thread
void AES_GCM_IPP::run_Encyption_Decryption_Auth_on_Vector(const long execution_rounds, const bool log_enabled)
{
	int ippCtxSize;
	std::unique_ptr<Ipp8u[]> ptr_AES_Status;
	

	if (ippStsNoErr != ippsAES_GCMGetSize(&ippCtxSize)) {
		m_was_thread_running_healthy.store(false);
		return;
	}

	try {
		ptr_AES_Status = std::make_unique<Ipp8u[]>(ippCtxSize);
	}
	catch (...) {
		m_was_thread_running_healthy.store(false);
		return;
	}

	IppsAES_GCMState* ippGCMState{ (IppsAES_GCMState*)ptr_AES_Status.get() };

	
	// Starting Actual AES-GCM Operations on Test Data ......
	AES_GCM_PARAMS<Ipp8u>	aes_gcm_params;
	Ipp8u					outputBufferMessage[256];	// size of a Record is stored in "1 Byte" so it is maximum 255 bytes
	uint08T					recordType, * bufDataVector, *bufDataOutput;

	bufDataOutput= m_buffer_AES_GCM_Output.get();


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
					if(0L == execution_index)
						*bufDataOutput = 0;
				break;
			}


			if (ippStsNoErr != ippsAES_GCMInit(aes_gcm_params.key, aes_gcm_params.keyLength, ippGCMState, ippCtxSize))
			{
				m_was_thread_running_healthy.store(false);
				return;
			}


			if (ippStsNoErr != ippsAES_GCMStart(aes_gcm_params.initVector, aes_gcm_params.initVectorLength, aes_gcm_params.assocAuth, aes_gcm_params.assocAuthLength, ippGCMState))
			{
				m_was_thread_running_healthy.store(false);
				return;
			}

			switch (recordType)   // based upon our record type, run a test...
			{
			case 1:     // Encryption
				if (ippStsNoErr != ippsAES_GCMEncrypt(aes_gcm_params.plainText, outputBufferMessage, aes_gcm_params.plainTextLength, ippGCMState))
				{
					m_was_thread_running_healthy.store(false);
					return;
				}


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
						bufDataOutput = setOneRecordofData(bufDataOutput, aes_gcm_params, recordType, NULL, outputBufferMessage);
					}

				break;

			case 2:   // Decryption OK
			case 3:   // Decryption Failed Because of Authetication (as per Plan)
				if (ippStsNoErr != ippsAES_GCMDecrypt(aes_gcm_params.CipherText, outputBufferMessage, aes_gcm_params.CipherTextLength, ippGCMState))
				{
					m_was_thread_running_healthy.store(false);
					return;
				}


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
						bufDataOutput = setOneRecordofData(bufDataOutput, aes_gcm_params, recordType, outputBufferMessage, NULL);
					}

				break;

			default: // wes should not have any other record type
				m_was_thread_running_healthy.store(false);
				return;

				break;
			}

			ippsAES_GCMReset(ippGCMState);
		}
	}
}
