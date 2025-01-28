
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
#include <sstream>
#include <vector>
#include <algorithm>
#include <iomanip>  
#include <chrono>
#include <ratio>

#include <windows.h> // only for getting CPU model in get_cpu_name() & CPU cores numbers in get_cpu_cores_count()
#include <intrin.h>  // only for getting CPU model in get_cpu_name()


/**********************************************************************************************************************************/
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       This File Contains                                                       */
/*                                                                                                                                */
/*                                                        Helper Functions                                                        */
/*                                                                                                                                */
/*                                                For String Formatting & some others                                             */
/*                                                                                                                                */
/**********************************************************************************************************************************/


inline long get_cpu_cores_count()
{
	SYSTEM_INFO sysInfo;
	GetNativeSystemInfo(&sysInfo); // no return value

	if (sysInfo.dwNumberOfProcessors < 1LL)
		return 1L;

	return (long)sysInfo.dwNumberOfProcessors;
}



inline std::string get_cpu_name()
{
	int32_t CPUInfo[4], nExIds;
	char    cpuNameParted[0x31];

	__cpuid(CPUInfo, 0x80000000);
	nExIds = (CPUInfo[0] < 0x80000004) ? CPUInfo[0] : 0x80000004;

	for (int32_t i = 0x80000000; i <= nExIds; ++i)
	{
		__cpuid(CPUInfo, i);

		if (i >= 0x80000002)
			memcpy(cpuNameParted + (i - 0x80000002) * 0x10, CPUInfo, sizeof(CPUInfo));
	}

	cpuNameParted[0x30] = 0;

	return cpuNameParted;
}



//
// output will be like: D5 DE 42 B4 61 64 6C 25    5C 87 BD 29 62 D3 B9 A2
//
inline int format_binary_buffer_as_hex_string(const unsigned char* buffer, const int length, char* output, const bool isBufferLittleEndianNumber = false)
{
	const char symbols[]{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	int indexIn, indexOut = -1; // will be 0 in the first operation

	if (false == isBufferLittleEndianNumber)
	{
		for (indexIn = 0; indexIn < length; indexIn++)
		{
			if (0 == (indexIn & 7))
			{
				output[++indexOut] = ' ';
				output[++indexOut] = ' ';
				output[++indexOut] = ' ';
			}

			output[++indexOut] = symbols[buffer[indexIn] >> 4];
			output[++indexOut] = symbols[buffer[indexIn] & 0xF];
			output[++indexOut] = ' ';
		}
	}
	else
	{
		bool start = false;
		for (indexIn = length - 1; indexIn >= 0; indexIn--)
		{
			if (false == start)
				if (0 != buffer[indexIn])
					start = true;

			if (true == start)
			{
				output[++indexOut] = symbols[buffer[indexIn] >> 4];
				output[++indexOut] = symbols[buffer[indexIn] & 0xF];
			}
		}

		output[++indexOut] = ' ';
		output[++indexOut] = 'H';
		++indexOut;
	}

	output[indexOut] = '\n';
	output[++indexOut] = 0;

	return indexOut;
}



//
// output will be like: 13'456'942
//
inline std::string format_number_comma_seperated(const size_t number, const char seperator = '\'')
{
	size_t num = number;

	if (num < 1000LL)
		return std::to_string(num);

	std::vector<short> num_parts;

	for (; 0 != num; num /= 1000LL)
		num_parts.push_back((short)(num % 1000LL));

	std::reverse(num_parts.begin(), num_parts.end());


	std::ostringstream ss;
	bool start = true;
	for (auto const& e : num_parts)
	{
		if (true == start)
			start = false;
		else
			ss << std::setw(3) << std::setfill('0');

		ss << e << seperator;
	}

	std::string ret{ ss.str() };
	ret.pop_back();

	return ret;
}




//
// output will be like: 123.4 G
//

inline std::string format_number_3digits_n_suffix(const size_t number, const size_t divider = 1000LL)
{
	size_t                   iAfterPoint, index, num = number;
	std::string              ret{ std::to_string(num) + " " };
	std::vector<std::string> suffixes{ " K", " M", " G", " T", " P", " E", " Z", " Y" }; // Long Long cannot be greater than this


	if (num > 1000LL)
	{
		for (index = 0; num >= 1000LL; index++)
		{
			iAfterPoint = num;
			num /= divider;
		}

		if (index < suffixes.size())
		{
			iAfterPoint = (iAfterPoint - num * 1000LL) / 100LL;
			if (iAfterPoint > 9LL)
			{
				iAfterPoint = 0LL;
				num++;
			}

			ret = std::to_string(num) + "." + std::to_string(iAfterPoint) + suffixes[index - 1];
		}
		else
			ret = "Too Big Number...";
	}

	return ret;
}



//
// output will be like: 23 h 42 m 12.345 s
//

inline std::string format_number_as_Time_Duration(const size_t number, const int divider = 3)
{
	std::vector<std::string> parts;
	std::ostringstream ss;

	size_t divider_coeff{ 1L };

	for (int i = 0; i < divider; i++)
		divider_coeff *= 10LL;


	// after arithmetic point
	size_t num = number % divider_coeff;

	if (0 == num)
		ss << ".0 s";
	else
		ss << "." << std::setw(divider) << std::setfill('0') << num << std::setfill(' ') << " s";

	parts.push_back(ss.str());



	ss.str("");
	num = number / divider_coeff;
	if (0 == num)
	{
		ss << "0";
		parts.push_back(ss.str());
	}
	else
	{
		ss << num % 60LL;
		parts.push_back(ss.str()); // seconds

		num /= 60;
		if (0 != num)
		{
			ss.str("");
			ss << num % 60LL << " m ";
			parts.push_back(ss.str()); // minutes

			num /= 60;
			if (0 != num)
			{
				ss.str("");
				ss << num << " h ";
				parts.push_back(ss.str());  // hours
			}
		}
	}


	std::reverse(parts.begin(), parts.end());

	std::string ret;
	for (auto const& e : parts)
		ret += e;

	return ret;
}
