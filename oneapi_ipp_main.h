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

#include "ippcp.h"

#include <bitset>
#include <array>


/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       IPP_Features                                                             */
/*                                                          Class                                                                 */
/*                                                                                                                                */
/* A helper class to get Intel IPP Lib’s information                                                                              */
/*                                                                                                                                */
/**********************************************************************************************************************************/


class IPP_Features
{

public:
	
	static const int IPP_Features_Count = 23;

	IPP_Features();

	const std::pair<std::string, std::string> IPP_GetLibNameVersion() const;
	bool IPP_Get_Features_CPU(std::bitset<IPP_Features::IPP_Features_Count>&) const;
	bool IPP_Get_Features_IPPLib(std::bitset<IPP_Features::IPP_Features_Count>&) const;


private:
	
	std::string m_ippLibName{}, m_ippLibVersion{};

	const std::array<Ipp64u, IPP_Features_Count> Features{ ippCPUID_AES, ippCPUID_SHA, ippCPUID_F16C, ippCPUID_MMX, ippCPUID_SSE, ippCPUID_SSE2,
															ippCPUID_SSE3, ippCPUID_SSE41, ippCPUID_SSE42, ippCPUID_SSSE3, ippCPUID_MOVBE,
															ippCPUID_CLMUL, ippCPUID_RDRAND, ippCPUID_AVX, ippAVX_ENABLEDBYOS, ippCPUID_AVX2,
															ippCPUID_AVX512F, ippCPUID_AVX512CD, ippCPUID_AVX512ER, ippCPUID_ADCOX,
															ippCPUID_RDSEED, ippCPUID_PREFETCHW, ippCPUID_KNC };
};
