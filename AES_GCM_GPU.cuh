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

#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#include "cuda_main.cuh"
#include "AES_GCM.h"


/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       AES_GCM_GPU                                                              */
/*                                                          Class                                                                 */
/*                                                                                                                                */
/* Inherited from AES_GCM, runs CUDA kernel. CUDA kernel creates copies of AES_GCM_IMPL so it can run AES-GCM on GPU              */
/*                                                                                                                                */
/**********************************************************************************************************************************/

class AES_GCM_GPU final : public AES_GCM
{

public:
	
	AES_GCM_GPU(); 									// Default Constructor

	AES_GCM_GPU(const AES_GCM_GPU&);				// Copy Constructor
	AES_GCM_GPU(AES_GCM_GPU&&) noexcept;			// Move Constructor

	AES_GCM_GPU& operator=(const AES_GCM_GPU&);		// Assignment operator
	AES_GCM_GPU& operator=(AES_GCM_GPU&&) noexcept;	// Move Assignment operator

	virtual ~AES_GCM_GPU() = default;

	int get_active_gpu_number() const;
	bool set_active_gpu_number(const int gpu_number);

	virtual std::string get_platform_name() const override;
	virtual std::pair<long, long> get_processing_cores_total() const override;


protected:
	
	int m_gpu_number_to_run{}; // first GPU

	void run_Benchmark_core(const long threads_blocks_count = 1L, const long threads_per_block_count = 1L, const long execution_rounds = 1L) override;
};
