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
#include "system_info.h"

#include <windows.h>      
#include <intrin.h>

#include <cassert>
#include <sstream>
#include <algorithm>
#include <functional>
#include <cstdint>

#pragma comment(lib, "WS2_32")  
#include <iphlpapi.h>  
#pragma comment(lib, "iphlpapi")

#include "utility.h"



/**********************************************************************************************************************************/
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                     System_Information                                                         */
/*                                                                                                                                */
/*                                                   Class Member Functions                                                       */
/*                                                                                                                                */
/* A helper class to get machine’s hardware information                                                                           */
/*                                                                                                                                */
/**********************************************************************************************************************************/


std::string System_Information::getMachineName() const
{
	TCHAR computerName[256];
	DWORD size = 256;

	if (0 == GetComputerName(computerName, &size))
		return "";


	std::string name = CW2A(computerName);
	return (name);
}



std::string System_Information::getCPUName() const
{
	return get_cpu_name();
}


long  System_Information::getCPUCores() const
{
	return get_cpu_cores_count();
}




std::string System_Information::getRAMSize() const
{
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	
	if (0 == GlobalMemoryStatusEx(&statex))
		return "";

	return format_number_3digits_n_suffix((std::size_t)statex.ullTotalPhys, 1024LL) + "B";
}




bool System_Information::getNICInfo(std::vector<NICInfoTuple>& infoNIC) const
{
	PIP_ADAPTER_INFO pAdapterInfoFirst = NULL;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);


	// Make an initial call to GetAdaptersInfo to get the CORRECT size into the dwBufLen variable
	for (;;)
	{
		if (NULL != pAdapterInfoFirst)
			delete[] pAdapterInfoFirst;


		try {
			pAdapterInfoFirst = (PIP_ADAPTER_INFO) new char[dwBufLen];
		}
		catch (...) {
			return false;
		}

		if (!pAdapterInfoFirst)
			return false;


		ULONG res = GetAdaptersInfo(pAdapterInfoFirst, &dwBufLen);

		if (ERROR_SUCCESS == res)
			break;

		if (ERROR_BUFFER_OVERFLOW != res)
		{
			delete[] pAdapterInfoFirst;
			return false;
		}
	}


	if (NO_ERROR == GetAdaptersInfo(pAdapterInfoFirst, &dwBufLen))
	{
		std::string       MAC;
		std::ostringstream ss;
		PIP_ADAPTER_INFO  pAdapterInfoCurrent = pAdapterInfoFirst;  // Contains pointer to current adapter info

		do {
			ss.str("");
			ss << std::hex << std::noshowbase << std::uppercase;

			for (unsigned int index = 0; index < pAdapterInfoCurrent->AddressLength; index++)
				ss << " : " << (int)pAdapterInfoCurrent->Address[index];

			MAC = ss.str();
			MAC.erase(0, 3);
			//transform(MAC.begin(), MAC.end(), MAC.begin(), ::toupper);

			infoNIC.push_back(std::make_tuple(pAdapterInfoCurrent->IpAddressList.IpAddress.String, MAC));

		} while (pAdapterInfoCurrent = pAdapterInfoCurrent->Next);


		std::sort(infoNIC.begin(), infoNIC.end(), [](const auto& left, const auto& right) {return std::get<0>(left) > std::get<0>(right); });
	}

	delete[] pAdapterInfoFirst;

	return true;
}



bool System_Information::getDiskPartitionsInfo(std::vector<DiskInfoTuple>& infoDisk) const
{
	WCHAR  DeviceName[MAX_PATH] = L"", VolumeName[MAX_PATH] = L"";
	HANDLE FindHandle = INVALID_HANDLE_VALUE;
	size_t Index = 0;


	FindHandle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName)); //  Enumerate all volumes in the system

	if (INVALID_HANDLE_VALUE == FindHandle)
		return false;  // FindFirstVolumeW failed with error code  GetLastError();


	for (;;)
	{
		//  Skip the \\?\ prefix and remove the trailing backslash.
		Index = wcslen(VolumeName) - 1;

		if (VolumeName[0] != L'\\' || VolumeName[1] != L'\\' || VolumeName[2] != L'?' || VolumeName[3] != L'\\' || VolumeName[Index] != L'\\')
		{
			FindVolumeClose(FindHandle);
			return false;  //FindFirstVolumeW/FindNextVolumeW returned a bad path: for "VolumeName"
		}


		VolumeName[Index] = L'\0'; // QueryDosDeviceW does not allow a trailing backslash, so temporarily remove it


		if (0 == QueryDosDeviceW(&VolumeName[4], DeviceName, ARRAYSIZE(DeviceName)))
		{
			FindVolumeClose(FindHandle);
			return false;  //QueryDosDeviceW failed with error code  GetLastError();
		}

		VolumeName[Index] = L'\\';



		{  // putting the result in the result vector
			std::string paths, sizeTotalStr{ }, sizeAvailableStr{ };
			size_t      sizeTotal, sizeAvailable;

			if (false == getDiskVolumeRootPath((LPCWSTR)VolumeName, paths))
				paths = "";

			if (true == getDiskVolumeSize(paths, sizeTotal, sizeAvailable))
			{
				sizeTotalStr = format_number_3digits_n_suffix(sizeTotal, 1024LL) + "B";
				sizeAvailableStr = format_number_3digits_n_suffix(sizeAvailable, 1024LL) + "B";
			}


			std::string strDevice = CW2A(DeviceName);
			std::string strVolumeID = CW2A(VolumeName);

			size_t volNameStartLoc = strVolumeID.find("{");
			if ((std::string::npos != volNameStartLoc) && (std::string::npos != strVolumeID.find("}")))
				strVolumeID = strVolumeID.substr(volNameStartLoc + 1, strVolumeID.find("}") - volNameStartLoc - 1);

			infoDisk.push_back(std::make_tuple(paths, sizeTotalStr, sizeAvailableStr, strDevice, strVolumeID));
		}




		if (FALSE == FindNextVolumeW(FindHandle, VolumeName, ARRAYSIZE(VolumeName))) //  Move on to the next volume
		{
			if (ERROR_NO_MORE_FILES != GetLastError())
			{
				FindVolumeClose(FindHandle);
				return false;  //FindNextVolumeW failed with error code Error;
			}

			break; // Finished iterating through all the volumes
		}
	}

	FindVolumeClose(FindHandle);

	std::sort(infoDisk.begin(), infoDisk.end(), [](const auto& left, const auto& right) {return std::get<0>(left).size() > std::get<0>(right).size(); });

	return true;
}





bool System_Information::getDiskVolumeSize(const std::string& PartitionName, size_t& sizeTotal, size_t& sizeAvailable) const
{
	DISK_SPACE_INFORMATION info;

	if (S_OK != GetDiskSpaceInformationA(PartitionName.c_str(), &info))
		return false;

	sizeTotal     = (size_t)info.SectorsPerAllocationUnit * (size_t)info.BytesPerSector * (size_t)info.ActualTotalAllocationUnits;
	sizeAvailable = (size_t)info.SectorsPerAllocationUnit * (size_t)info.BytesPerSector * (size_t)info.ActualAvailableAllocationUnits;

	return true;
}


bool System_Information::getDiskVolumeRootPath(LPCWSTR VolumeName, std::string& paths) const
{
	DWORD  CharCount = MAX_PATH + 1;
	PWCHAR Names     = NULL;
	BOOL   Success   = FALSE;

	for (;;)
	{
		try {
			Names = new WCHAR[CharCount + 1]; //  Allocate a buffer to hold the paths.
		}
		catch (...) {
			return false;
		}

		if (!Names)
			return false;

		
		Success = GetVolumePathNamesForVolumeNameW(VolumeName, Names, CharCount, &CharCount); //  Obtain all of the paths for this volume

		if (Success)
			break;

		if (ERROR_MORE_DATA != GetLastError())
			break;

		//  Try again with the new suggested size.
		delete[] Names;
	}

	if (Success)
		for (PWCHAR NameIdx = Names; NameIdx[0] != L'\0'; NameIdx += wcslen(NameIdx) + 1)
		{
			std::string s{ CW2A(NameIdx) };
			paths += s;
		}

	if (NULL != Names)
		delete[] Names;

	if (Success)
		return true;

	return false;
}
