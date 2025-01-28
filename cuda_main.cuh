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

#include <map>
#include <string>
#include <vector>

/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                      ACUDA_Features                                                            */
/*                                                          Class                                                                 */
/*                                                                                                                                */
/* A helper class to get GPU’s hardware information                                                                               */
/*                                                                                                                                */
/**********************************************************************************************************************************/


class CUDA_Features
{

public:
	
    CUDA_Features();

	int CUDA_Get_Total_GPUs_Count() const;
	std::vector<std::string> CUDA_Get_GPU_Information(const int) const;


private:
	
    int m_device_count{};
};



/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                           Helper                                                               */
/*                                                       Inline Functions                                                         */
/*                                                                                                                                */
/**********************************************************************************************************************************/

inline int CUDA_Get_CUDA_Cores_Count(const int version_major, const int version_minor)
{
    std::map<int, int> nGpuArchCoresPerSM
    {
        { 0x30, 192 },
        { 0x32, 192 },
        { 0x35, 192 },
        { 0x37, 192 },
        { 0x50, 128 },
        { 0x52, 128 },
        { 0x53, 128 },
        { 0x60,  64 },
        { 0x61, 128 },
        { 0x62, 128 },
        { 0x70,  64 },
        { 0x72,  64 },
        { 0x75,  64 },
        { 0x80,  64 },
        { 0x86, 128 },
        { 0x87, 128 },
        { 0x89, 128 },
        { 0x90, 128 },
    };

    auto res = nGpuArchCoresPerSM.find((version_major << 4) + version_minor);

    if (res != nGpuArchCoresPerSM.end())
        return res->second;

    return -1;
}
