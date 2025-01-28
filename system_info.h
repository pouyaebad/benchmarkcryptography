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

#include <string>
#include <vector>


using DiskInfoTuple = std::tuple<std::string, std::string, std::string, std::string, std::string>;
using NICInfoTuple  = std::tuple<std::string, std::string>;


/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                    System_Information                                                          */
/*                                                          Class                                                                 */
/*                                                                                                                                */
/* A helper class to get machine’s hardware information                                                                           */
/*                                                                                                                                */
/**********************************************************************************************************************************/


class System_Information
{

public:
	
	std::string getMachineName() const;
	std::string getCPUName() const;
	long		getCPUCores() const;
	std::string getRAMSize() const;
	bool getNICInfo(std::vector<NICInfoTuple>&) const;
	bool getDiskPartitionsInfo(std::vector<DiskInfoTuple>&) const;


private:
	
	bool getDiskVolumeSize(const std::string&, size_t&, size_t&) const;
	bool getDiskVolumeRootPath(LPCWSTR, std::string&) const;
};
