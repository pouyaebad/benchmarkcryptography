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

#include "AES_GCM.h"


/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       AES_GCM_CPU                                                              */
/*                                                          Class                                                                 */
/*                                                                                                                                */
/* Inherited from AES_GCM and contains copies of AES_GCM_IMPL so it can run AES-GCM on CPU                                        */
/*                                                                                                                                */
/**********************************************************************************************************************************/

class AES_GCM_CPU final : public AES_GCM
{

public:
	
	AES_GCM_CPU(); 									// Default Constructor

	AES_GCM_CPU(const AES_GCM_CPU&);				// Copy Constructor
	AES_GCM_CPU(AES_GCM_CPU&&) noexcept;			// Move Constructor

	AES_GCM_CPU& operator=(const AES_GCM_CPU&);		// Assignment operator
	AES_GCM_CPU& operator=(AES_GCM_CPU&&) noexcept;	// Move Assignment operator

	virtual ~AES_GCM_CPU() = default;

	virtual std::string get_platform_name() const override;
	virtual std::pair<long, long> get_processing_cores_total() const override;


private:
	
	void run_Benchmark_core(const long threads_blocks_count = 1L, const long threads_per_block_count = 1L, const long execution_rounds = 1L) override;

	// this function is designed to run multi-threaded BUT log_enabled should be enabled ONLY for 1 thread
	void run_Encyption_Decryption_Auth_on_Vector(const long execution_rounds = 1L, const bool log_enabled = false);
};
