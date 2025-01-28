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

#include <cassert>

#include "utility.h"
#include "cuda_main.cuh"

/**********************************************************************************************************************************/
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                      CUDA_Features                                                             */
/*                                                                                                                                */
/*                                                   Class Member Functions                                                       */
/*                                                                                                                                */
/* A helper class to get GPU’s hardware information                                                                               */
/*                                                                                                                                */
/**********************************************************************************************************************************/


CUDA_Features::CUDA_Features() : m_device_count{ }
{
    if (cudaSuccess != cudaGetDeviceCount(&m_device_count))
        m_device_count = 0;
}


int CUDA_Features::CUDA_Get_Total_GPUs_Count() const
{
    return m_device_count;
}


std::vector<std::string> CUDA_Features::CUDA_Get_GPU_Information(const int deviceNo) const
{
    const int info_field_count = 12;

    std::vector<std::string> ret;


    if (deviceNo >= m_device_count)  // updating the member variable
        return ret;


    cudaDeviceProp cudaProp;
    if (cudaSuccess != cudaGetDeviceProperties(&cudaProp, deviceNo))
    {
        ret.push_back(" CUDA Device Query Failed");               // Alternative #1

        for (int i = 0; i < info_field_count - 1; i++)
            ret.push_back("-");

        return ret;
    }


    std::string sData{ cudaProp.name };
    if (m_device_count > 1)
        sData += "  ( + " + std::to_string(m_device_count - 1) + " More Devices )";

    ret.push_back(sData);                                                                                // Item #1
    ret.push_back(format_number_3digits_n_suffix(cudaProp.totalGlobalMem, 1024LL) + "B");                // Item #2


    sData = std::to_string(cudaProp.multiProcessorCount);
    int iCores = CUDA_Get_CUDA_Cores_Count(cudaProp.major, cudaProp.minor);

    if (iCores > 0)
        sData += "  ( " + std::to_string(iCores * cudaProp.multiProcessorCount) + " Cores or Thread/Stream Processor)";

    ret.push_back(sData);                                                                               // Item #3


    ret.push_back(format_number_3digits_n_suffix(1000LL * (size_t)cudaProp.clockRate) + "Hz");          // Item #4
    ret.push_back(format_number_3digits_n_suffix(1000LL * (size_t)cudaProp.memoryClockRate) + "Hz");    // Item #5
    ret.push_back(std::to_string(cudaProp.regsPerMultiprocessor));                                      // Item #6
    ret.push_back(std::to_string(cudaProp.regsPerBlock));                                               // Item #7
    ret.push_back(std::to_string(cudaProp.maxGridSize[0]) + ", " + std::to_string(cudaProp.maxGridSize[1]) + ", " + std::to_string(cudaProp.maxGridSize[2]));               // Item #8 
    ret.push_back(std::to_string(cudaProp.maxBlocksPerMultiProcessor));                                 // Item #9
    ret.push_back(std::to_string(cudaProp.maxThreadsPerBlock));                                         // Item #10
    ret.push_back(std::to_string(cudaProp.maxThreadsDim[0]) + ", " + std::to_string(cudaProp.maxThreadsDim[1]) + ", " + std::to_string(cudaProp.maxThreadsDim[2]));         // Item #11
    ret.push_back(std::to_string(cudaProp.maxThreadsPerMultiProcessor));                                // Item #12

    assert(ret.size() == info_field_count);

    // cudaDeviceReset must be called before exiting in order for profiling and tracing tools such as Nsight and Visual Profiler to show complete traces.
    if (cudaSuccess != cudaDeviceReset())
        ret.clear();

    return ret;
}
