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

#include "oneapi_ipp_main.h"


/**********************************************************************************************************************************/
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       IPP_Features                                                             */
/*                                                                                                                                */
/*                                                   Class Member Functions                                                       */
/*                                                                                                                                */
/* A helper class to get Intel IPP Lib’s information                                                                              */
/*                                                                                                                                */
/**********************************************************************************************************************************/



IPP_Features::IPP_Features() : m_ippLibName{ "" }, m_ippLibVersion{ "" }
{
	const CryptoLibraryVersion* ippLibVer;
	ippLibVer = cryptoGetLibVersion();

	if (NULL != ippLibVer)
	{
		m_ippLibName = ippLibVer->name;
		m_ippLibVersion = ippLibVer->strVersion;
	}
}


const std::pair<std::string, std::string> IPP_Features::IPP_GetLibNameVersion() const
{
	return std::make_pair(m_ippLibName, m_ippLibVersion);
}


 bool IPP_Features::IPP_Get_Features_CPU(std::bitset<IPP_Features::IPP_Features_Count>& features) const
{
	 features.reset();

	if (m_ippLibName.size() <= 1)
		return false;


	Ipp64u ippCPUFeatures;

	if (ippStsNoErr != ippcpGetCpuFeatures(&ippCPUFeatures))
		return false;


	for (int index = 0; index < IPP_Features_Count; ++index)
		if (0 != (ippCPUFeatures & Features[index]))
			features.set(index);

	return true;
}


bool IPP_Features::IPP_Get_Features_IPPLib(std::bitset<IPP_Features::IPP_Features_Count>& features) const
{
	features.reset();

	if (m_ippLibName.size() <= 1)
		return false;


	Ipp64u ippCPUSupportedFeatures{ ippcpGetEnabledCpuFeatures() };

	for (int index = 0; index < IPP_Features_Count; ++index)
		if (0 != (ippCPUSupportedFeatures & Features[index]))
			features.set(index);

	return true;
}
