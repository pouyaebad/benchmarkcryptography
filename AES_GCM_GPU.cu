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

#include "AES_GCM_GPU.cuh"
#include "AES_GCM_IMPL.cuh"


/**********************************************************************************************************************************/
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                    CUDA Kernel Function                                                        */
/*                                                                                                                                */
/*                                              Called from Host but Runs on Device                                               */
/*                                                        Multi-Threaded                                                          */
/*                                                                                                                                */
/* CUDA kernel creates copies of AES_GCM_IMPL so it can run AES-GCM on GPU                                                        */
/*                                                                                                                                */
/**********************************************************************************************************************************/

__global__ void run_Encyption_Decryption_on_Vector_GPU_Kernel(uint08T* bufDataVectorMaster, uint08T* bufDataOutput, size_t* returnedStatParameters)
{
	bool log_enabled{ false };
	long execution_rounds{ (long)returnedStatParameters[7] };

	uint08T*		bufDataVector, recordType, ct_buf[256], pt_buf[256], tag_buf[256]; // 16 bytes is enough for TAG but I considered 256 bytes for robustness
	GCM_CNTX		ctx;
	AES_GCM_IMPL	aes_gcm_impl;

	AES_GCM_PARAMS<uint08T>	aes_gcm_params;

	size_t	v_encryption_operations_count{}, v_dencryption_operations_successful_count{}, v_authentication_failed_operations_count{},
		v_128bit_operations_count{}, v_192bit_operations_count{}, v_256bit_operations_count{}, v_aes_processed_messages_total_length{};

	size_t	gcm_context_size{ sizeof(GCM_CNTX) };

	if ((0 == blockIdx.x) && (0 == threadIdx.x) && (NULL != bufDataOutput) && (NULL != returnedStatParameters))
			log_enabled = true;


	for (long execution_index = 0L; execution_index < execution_rounds; execution_index++)
	{
		bufDataVector = bufDataVectorMaster;

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
						v_encryption_operations_count++;
						v_aes_processed_messages_total_length += (size_t)aes_gcm_params.plainTextLength;

						if (16 == (size_t)aes_gcm_params.keyLength)
							v_128bit_operations_count++;
						else if (24 == (size_t)aes_gcm_params.keyLength)
							v_192bit_operations_count++;
						else if (32 == (size_t)aes_gcm_params.keyLength)
							v_256bit_operations_count++;

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
						v_aes_processed_messages_total_length += (size_t)aes_gcm_params.CipherTextLength;

						if (2 == recordType)  // Decryption OK
							v_dencryption_operations_successful_count++;
						else
							v_authentication_failed_operations_count++;


						if (16 == (size_t)aes_gcm_params.keyLength)
							v_128bit_operations_count++;
						else if (24 == (size_t)aes_gcm_params.keyLength)
							v_192bit_operations_count++;
						else if (32 == (size_t)aes_gcm_params.keyLength)
							v_256bit_operations_count++;

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
				returnedStatParameters[8] = 0x7FFF;
				return;

				break;
			}
		}
	}


	if (true == log_enabled)
	{
		returnedStatParameters[0] = v_encryption_operations_count;
		returnedStatParameters[1] = v_dencryption_operations_successful_count;
		returnedStatParameters[2] = v_authentication_failed_operations_count;
		returnedStatParameters[3] = v_128bit_operations_count;
		returnedStatParameters[4] = v_192bit_operations_count;
		returnedStatParameters[5] = v_256bit_operations_count;
		returnedStatParameters[6] = v_aes_processed_messages_total_length;
	}
}


/**********************************************************************************************************************************/
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       AES_GCM_GPU                                                              */
/*                                                                                                                                */
/*                                                   Class Member Functions                                                       */
/*                                                                                                                                */
/* Inherited from AES_GCM, runs CUDA kernel. CUDA kernel creates copies of AES_GCM_IMPL so it can run AES-GCM on GPU              */
/*                                                                                                                                */
/**********************************************************************************************************************************/


AES_GCM_GPU::AES_GCM_GPU() : AES_GCM()  // Default Constructor
{
}


AES_GCM_GPU::AES_GCM_GPU(const AES_GCM_GPU& aes_gcm) : AES_GCM(aes_gcm) // Copy Constructor
{
}


AES_GCM_GPU& AES_GCM_GPU::operator=(const AES_GCM_GPU& rhs)  // Assignment operator
{
	if (this != &rhs)
		AES_GCM::operator=(rhs);

	return *this;
}


AES_GCM_GPU::AES_GCM_GPU(AES_GCM_GPU&& aes_gcm) noexcept : AES_GCM(std::move(aes_gcm))  // Move Constructor
{
}


AES_GCM_GPU& AES_GCM_GPU::operator=(AES_GCM_GPU&& rhs) noexcept  // Move Assignment operator
{
	if (this != &rhs)
		AES_GCM::operator=(std::move(rhs));

	return *this;
}



std::string AES_GCM_GPU::get_platform_name() const
{
	int device_count{};
	std::string res{ "GPU (not Detected)" };

	if (cudaSuccess != cudaGetDeviceCount(&device_count))
		return res;


	cudaDeviceProp cudaProp;
	if (cudaSuccess != cudaGetDeviceProperties(&cudaProp, m_gpu_number_to_run))
		return res;

	res = "GPU, ";
	res += cudaProp.name;

	return res;
}



std::pair<long, long> AES_GCM_GPU::get_processing_cores_total() const
{
	int device_count{};

	if (cudaSuccess != cudaGetDeviceCount(&device_count))
		return std::make_pair(0L, 0L);

	cudaDeviceProp cudaProp;
	if (cudaSuccess != cudaGetDeviceProperties(&cudaProp, m_gpu_number_to_run))
		return std::make_pair(0L, 0L);


	int iCores = CUDA_Get_CUDA_Cores_Count(cudaProp.major, cudaProp.minor);

	if (iCores <= 0)
		iCores = 128; // for any reason if CUDA cannot determine correct cores per SM, I assume 128 cores per SM which is very common one


	cudaDeviceReset(); // cudaDeviceReset must be called before exiting in order for profiling and tracing tools such as Nsight and Visual Profiler to show complete traces.

	return std::make_pair((long)(cudaProp.multiProcessorCount), (long)iCores);
}



int AES_GCM_GPU::get_active_gpu_number() const
{
	return m_gpu_number_to_run;
}



bool AES_GCM_GPU::set_active_gpu_number(const int gpu_number)
{
	if (cudaSuccess != cudaSetDevice(gpu_number))
		return false;

	m_gpu_number_to_run = gpu_number;

	cudaDeviceReset();

	return true;
}



void AES_GCM_GPU::run_Benchmark_core(const long threads_blocks_count, const long threads_per_block_count, const long execution_rounds)
{
	cudaError_t	cudaStatus;
	uint08T*	bufDataVector, * bufDataOutput, * dev_bufDataVector, * dev_bufDataOutput;
	size_t		returnedStatParameters[9]{}, * dev_returnedStatParameters; // to see definition of each element of this array, go to end of this function

	returnedStatParameters[7] = execution_rounds;

	bufDataVector = m_buffer_AES_GCM_Vector.get();
	bufDataOutput = m_buffer_AES_GCM_Output.get();


	// Since CUDA 12, calling cudaSetDevice() is enough for the whole CUDA initilization
	if (cudaSuccess != (cudaStatus = cudaSetDevice(m_gpu_number_to_run)))
	{
		std::exception e("Error #AGG-01: CUDA Compatible GPU / Device is not Found");
		throw e;
	}

	if (cudaSuccess != (cudaStatus = cudaMalloc((void**)&dev_bufDataVector, m_buffer_Size * sizeof(uint08T))))
	{
		std::exception e("Error #AGG-02: CUDA Memory Allocation is Failed for Vector Data");
		throw e;
	}

	if (cudaSuccess != (cudaStatus = cudaMemcpy(dev_bufDataVector, bufDataVector, m_buffer_Size * sizeof(uint08T), cudaMemcpyHostToDevice)))
	{
		cudaFree(dev_bufDataVector);

		std::exception e("Error #AGG-03: Copy From System Memory to CUDA Memory is Failed");
		throw e;
	}

	if (cudaSuccess != (cudaStatus = cudaMalloc((void**)&dev_bufDataOutput, m_buffer_Size * sizeof(uint08T))))
	{
		cudaFree(dev_bufDataVector);

		std::exception e("Error #AGG-04: CUDA Memory Allocation is Failed for Output Result Data");
		throw e;
	}

	if (cudaSuccess != (cudaStatus = cudaMalloc((void**)&dev_returnedStatParameters,  sizeof(returnedStatParameters))))
	{
		cudaFree(dev_bufDataVector);
		cudaFree(dev_bufDataOutput);

		std::exception e("Error #AGG-05: CUDA Memory Allocation is Failed for Result Data");
		throw e;
	}

	if (cudaSuccess != (cudaStatus = cudaMemcpy(dev_returnedStatParameters, returnedStatParameters, sizeof(returnedStatParameters), cudaMemcpyHostToDevice)))
	{
		cudaFree(dev_bufDataVector);
		cudaFree(dev_bufDataOutput);
		cudaFree(dev_returnedStatParameters);

		std::exception e("Error #AGG-06: Copy From System Memory to CUDA Memory is Failed");
		throw e;
	}



	// ============================================================
	// Creating CUDA Threads & Running AES-GCM operations on them
	// ============================================================

	run_Encyption_Decryption_on_Vector_GPU_Kernel << < threads_blocks_count, threads_per_block_count >> > (dev_bufDataVector, dev_bufDataOutput, dev_returnedStatParameters);

	if (cudaSuccess != (cudaStatus = cudaGetLastError()))  // Check for any errors launching the kernel
	{
		cudaFree(dev_bufDataVector);
		cudaFree(dev_bufDataOutput);
		cudaFree(dev_returnedStatParameters);

		std::string s = "Error #AGG-07: CUDA Threads Running Failed: ";
		s += cudaGetErrorString(cudaStatus);
		std::exception e(s.data());
		throw e;
	}

	if (cudaSuccess != (cudaStatus = cudaDeviceSynchronize())) // waiting for the kernel (threads) to finish
	{
		cudaFree(dev_bufDataVector);
		cudaFree(dev_bufDataOutput);
		cudaFree(dev_returnedStatParameters);

		std::string s = "Error #AGG-08: CUDA Threads Running Failed: ";
		s += cudaGetErrorString(cudaStatus);
		std::exception e(s.data());
		throw e;
	}

	cudaFree(dev_bufDataVector);


	if (cudaSuccess != (cudaStatus = cudaMemcpy(bufDataOutput, dev_bufDataOutput, m_buffer_Size * sizeof(uint08T), cudaMemcpyDeviceToHost)))
	{
		cudaFree(dev_bufDataOutput);
		cudaFree(dev_returnedStatParameters);

		std::exception e("Error #AGG-09: Copy From CUDA Memory to System Memory is Failed");
		throw e;
	}

	cudaFree(dev_bufDataOutput);


	if (cudaSuccess != (cudaStatus = cudaMemcpy(returnedStatParameters, dev_returnedStatParameters, sizeof(returnedStatParameters), cudaMemcpyDeviceToHost)))
	{
		cudaFree(dev_returnedStatParameters);

		std::exception e("Error #AGG-10: Copy From CUDA Memory to System Memory is Failed");
		throw e;
	}

	cudaFree(dev_returnedStatParameters);


	m_encryption_operations_count = returnedStatParameters[0];
	m_dencryption_operations_successful_count = returnedStatParameters[1];
	m_authentication_failed_operations_count = returnedStatParameters[2];
	m_128bit_operations_count = returnedStatParameters[3];
	m_192bit_operations_count = returnedStatParameters[4];
	m_256bit_operations_count = returnedStatParameters[5];
	m_aes_processed_messages_total_length = returnedStatParameters[6];
	//returnedStatParameters[7], it is input to kernel function. it is execution_rounds
	//returnedStatParameters[8], it is set to 0 here and any kernel thread can set it to nonzero if it cannot run properly


	// cudaDeviceReset must be called before exiting in order for profiling and tracing tools such as Nsight and Visual Profiler to show complete traces.
	if (cudaSuccess != (cudaStatus = cudaDeviceReset()))
	{
		std::exception e("Error #AGG-11: Resetting CUDA Device is Failed");
		throw e;
	}

	if (0 != returnedStatParameters[8])
	{
		std::exception e("Error #AGG-12: Execution of Threads for AES-GCM GPU Operation Encountered some Errors");
		throw e;
	}
}
