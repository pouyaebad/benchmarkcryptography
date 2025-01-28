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

#include <fstream>
#include <exception>
#include <chrono>
#include <time.h>
#include <cassert>

#include "utility.h"
#include "AES_GCM.h"


/**********************************************************************************************************************************/
/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                         AES_GCM                                                                */
/*                                                                                                                                */
/*                                                   Class Member Functions                                                       */
/*                                                                                                                                */
/* Abstract polymorphic class, contains functions to write logs, loads test data file into buffer and so on                       */
/*                                                                                                                                */
/**********************************************************************************************************************************/

void AES_GCM::initilize_object()
{
	reset_processed_counters();
	m_buffer_Size = 0LL;

	m_is_running.store(false);
	m_was_thread_running_healthy.store(true);
}


void AES_GCM::reset_processed_counters()
{
	m_encryption_operations_count				= 0LL;
	m_dencryption_operations_successful_count	= 0LL;
	m_authentication_failed_operations_count	= 0LL;
	m_128bit_operations_count					= 0LL;
	m_192bit_operations_count					= 0LL;
	m_256bit_operations_count					= 0LL;
	m_aes_processed_messages_total_length		= 0LL;
}


AES_GCM::AES_GCM() // Default Constructor
{
	initilize_object();
}


AES_GCM::AES_GCM(const AES_GCM& aes_gcm) // Copy Constructor
{
	this->operator=(aes_gcm);
}


AES_GCM& AES_GCM::operator=(const AES_GCM& rhs) // Assignment Operator
{
	if (this == &rhs)
		return *this;

	if ((true == m_is_running.load()) || (true == rhs.m_is_running.load()))
	{
		std::exception e("Error #AGM-01: Running Objects Cannot be Assigned, Copied or Moved");
		throw e;
	}

	m_was_thread_running_healthy.store(rhs.m_was_thread_running_healthy.load());

	m_encryption_operations_count = rhs.m_encryption_operations_count;
	m_dencryption_operations_successful_count = rhs.m_dencryption_operations_successful_count;
	m_authentication_failed_operations_count = rhs.m_authentication_failed_operations_count;
	m_128bit_operations_count = rhs.m_128bit_operations_count;
	m_192bit_operations_count = rhs.m_192bit_operations_count;
	m_256bit_operations_count = rhs.m_256bit_operations_count;
	m_aes_processed_messages_total_length = rhs.m_aes_processed_messages_total_length;


	if (m_buffer_Size != rhs.m_buffer_Size)
	{
		m_buffer_Size = rhs.m_buffer_Size;


		if (m_buffer_AES_GCM_Vector)
			delete[] m_buffer_AES_GCM_Vector.release();

		if (m_buffer_AES_GCM_Output)
			delete[] m_buffer_AES_GCM_Output.release();


		try {
			m_buffer_AES_GCM_Vector = std::make_unique<uint08T[]>(m_buffer_Size);
			m_buffer_AES_GCM_Output = std::make_unique<uint08T[]>(m_buffer_Size);
		}
		catch (...) {
			std::exception e("Error #AGM-02: Buffer Allocation in the Memory for AES-GCM Data Failed!");
			throw e;
		}
	}

	std::memcpy(m_buffer_AES_GCM_Vector.get(), rhs.m_buffer_AES_GCM_Vector.get(), m_buffer_Size);
	std::memcpy(m_buffer_AES_GCM_Output.get(), rhs.m_buffer_AES_GCM_Output.get(), m_buffer_Size);

	return *this;
}



AES_GCM::AES_GCM(AES_GCM&& aes_gcm) noexcept // Move Constructor
{
	this->operator=(std::move(aes_gcm));
}


AES_GCM& AES_GCM::operator=(AES_GCM&& rhs) noexcept // Move Assignment Operator
{
	if (this == &rhs)
		return *this;

	if ((true == m_is_running.load()) || (true == rhs.m_is_running.load()))
		return *this;


	m_buffer_AES_GCM_Vector = std::move(rhs.m_buffer_AES_GCM_Vector);
	m_buffer_AES_GCM_Output = std::move(rhs.m_buffer_AES_GCM_Output);

	m_was_thread_running_healthy.store(rhs.m_was_thread_running_healthy.load());

	m_buffer_Size = rhs.m_buffer_Size;

	m_encryption_operations_count = rhs.m_encryption_operations_count;
	m_dencryption_operations_successful_count = rhs.m_dencryption_operations_successful_count;
	m_authentication_failed_operations_count = rhs.m_authentication_failed_operations_count;
	m_128bit_operations_count = rhs.m_128bit_operations_count;
	m_192bit_operations_count = rhs.m_192bit_operations_count;
	m_256bit_operations_count = rhs.m_256bit_operations_count;
	m_aes_processed_messages_total_length = rhs.m_aes_processed_messages_total_length;

	rhs.initilize_object();

	return *this;
}


/**********************************************************************************************************************************/
/*                                                 Class Ordinary Functions                                                       */
/**********************************************************************************************************************************/


bool AES_GCM::get_is_running() const
{
	return m_is_running.load();
}


std::pair<size_t, size_t> AES_GCM::get_processed_data_volume() const
{
	size_t	totalOperations = m_encryption_operations_count + m_dencryption_operations_successful_count + m_authentication_failed_operations_count;

	return std::make_pair(m_aes_processed_messages_total_length, totalOperations);
}


/**********************************************************************************************************************************/
/*                                                   Class Main Functions                                                         */
/**********************************************************************************************************************************/


void AES_GCM::load_AES_GCM_Vector_File_to_Buffer(const std::string filePath)
{
	if (true == m_is_running.load())
	{
		std::exception e("Error #AGM-03: Buffer Data of a Running Object cannnot be Changed");
		throw e;
	}

	if (m_buffer_AES_GCM_Vector) {
		m_buffer_Size = 0LL;
		delete[] m_buffer_AES_GCM_Vector.release();
		delete[] m_buffer_AES_GCM_Output.release();
	}


	std::ifstream fileInputStream;
	fileInputStream.open(filePath, std::ios::in | std::ios::binary);

	if (!fileInputStream.is_open())
	{
		std::exception e("Error #AGM-04: AES-GCM Vector File Cannot be Opened");
		throw e;
	}


	fileInputStream.seekg(0, std::ios::end);
	m_buffer_Size = fileInputStream.tellg();
	fileInputStream.seekg(0, std::ios::beg);

	if (fileInputStream.bad()) // file operation was not successful
	{
		m_buffer_Size = 0LL;
		fileInputStream.close();

		std::exception e("Error #AGM-05: AES-GCM Vector File Cannot be Read");
		throw e;
	}


	try {
		m_buffer_AES_GCM_Vector = std::make_unique<uint08T[]>(m_buffer_Size);
		m_buffer_AES_GCM_Output = std::make_unique<uint08T[]>(m_buffer_Size);
	}
	catch (...) {
		m_buffer_Size = 0LL;
		fileInputStream.close();

		std::exception e("Error #AGM-06: uffer Allocation in the Memory for AES-GCM Data is Failed!");
		throw e;
	}

	m_buffer_AES_GCM_Output.get()[0] = 0;


	char* pBuffer = (char*)m_buffer_AES_GCM_Vector.get();

	fileInputStream.read(pBuffer, m_buffer_Size);
	fileInputStream.close();


	if (fileInputStream.bad()) // file operation was not successful
	{
		delete[] m_buffer_AES_GCM_Vector.release();
		delete[] m_buffer_AES_GCM_Output.release();
		m_buffer_Size = 0LL;
		fileInputStream.close();

		std::exception e("Error #AGM-07: AES-GCM Vector File Cannot be Read (2)");
		throw e;
	}
}




bool AES_GCM::delete_zero_length_data_from_AES_GCM_Vector_Buffer() noexcept
{
	if (true == m_is_running.load())
		return false;

	if ((0LL == m_buffer_Size) || (!m_buffer_AES_GCM_Vector))
		return false;



	AES_GCM_PARAMS<uint08T>	aes_gcm_params;
	uint08T					recordType, * bufVectorData = m_buffer_AES_GCM_Vector.get();
	size_t					newBufferActualSize{ 2LL }; // we reserve some more space for "EOF" record type at the end


	while (true)
	{
		bufVectorData = getOneRecordofData(bufVectorData, aes_gcm_params, recordType);

		if (0 == recordType)
			break;
		
		if (1 == recordType) // Encryption
			if (0 == aes_gcm_params.plainTextLength)
				continue;

		if ((2 == recordType) || (3 == recordType)) // Decryption OK OR Failed Because of Authetication (as per Plan)
			if (0 == aes_gcm_params.CipherTextLength)
				continue;

		if (recordType > 3)
			return false;

		newBufferActualSize += 7LL;  // record type + length of all following fields (length field has 1 byte only)
		newBufferActualSize += aes_gcm_params.keyLength;
		newBufferActualSize += aes_gcm_params.initVectorLength;
		newBufferActualSize += aes_gcm_params.assocAuthLength;
		newBufferActualSize += aes_gcm_params.plainTextLength;
		newBufferActualSize += aes_gcm_params.CipherTextLength;
		newBufferActualSize += aes_gcm_params.authTagLength;
	}


	std::unique_ptr<uint08T[]> m_buffer_temp, m_buffer_temp_output;
	try {
		m_buffer_temp		= std::make_unique<uint08T[]>(newBufferActualSize);
		m_buffer_temp_output= std::make_unique<uint08T[]>(newBufferActualSize);
	}
	catch (...) {
		return false;
	}


	uint08T* bufTempData = m_buffer_temp.get();
	bufVectorData = m_buffer_AES_GCM_Vector.get();

	while (true)
	{
		bufVectorData = getOneRecordofData(bufVectorData, aes_gcm_params, recordType);

		if (0 == recordType)
			break;

		if (1 == recordType) // Encryption
			if (0 == aes_gcm_params.plainTextLength)
				continue;

		if ((2 == recordType) || (3 == recordType)) // Decryption OK OR Failed Because of Authetication (as per Plan)
			if (0 == aes_gcm_params.CipherTextLength)
				continue;

		bufTempData = setOneRecordofData(bufTempData, aes_gcm_params, recordType);
	}

	*bufTempData++ = 0;
	*bufTempData = 0;

	m_buffer_temp_output.get()[0] = 0;


	m_buffer_Size = newBufferActualSize;

	delete[] m_buffer_AES_GCM_Vector.release();
	m_buffer_AES_GCM_Vector = std::move(m_buffer_temp);

	delete[] m_buffer_AES_GCM_Output.release();
	m_buffer_AES_GCM_Output= std::move(m_buffer_temp_output);

	return true;
}


/**********************************************************************************************************************************/
/*                                                   Class Core Functions                                                         */
/**********************************************************************************************************************************/


void AES_GCM::run_Benchmark(const long threads_blocks_count, const long threads_per_block_count, const long execution_rounds)
{
	if (true == m_is_running.load())
		return;


	if ((0LL == m_buffer_Size) || (!m_buffer_AES_GCM_Vector))
	{
		std::exception e("Error #AGM-08: No Data is Loaded for Encryption, Decryption and Authetication");
		throw e;
	}

	m_is_running.store(true);

	reset_processed_counters();


	try {
		run_Benchmark_core(threads_blocks_count, threads_per_block_count, execution_rounds);
	}
	catch (...) {
		m_is_running.store(false);
		throw;
	}



	size_t threads{ (size_t)threads_blocks_count * (size_t)threads_per_block_count * (size_t)execution_rounds };

	m_aes_processed_messages_total_length *= threads; // because only 1 thread (first one) does the logging

	m_encryption_operations_count *= threads;
	m_dencryption_operations_successful_count *= threads;
	m_authentication_failed_operations_count *= threads;

	m_128bit_operations_count *= threads;
	m_192bit_operations_count *= threads;
	m_256bit_operations_count *= threads;


	m_is_running.store(false);
}



/**********************************************************************************************************************************/
/*                                                    Class Log Functions                                                         */
/**********************************************************************************************************************************/


bool AES_GCM::log_write_file(const std::string filePath) const
{
	if ((!m_buffer_AES_GCM_Vector) || (!m_buffer_AES_GCM_Output) || (0 == m_buffer_Size) || (0 == filePath.size()))
		return false;



	// Step 1 of 3: Opening the Log File and Writing the Header
	//

	std::ofstream fileStreamOut;
	fileStreamOut.open(filePath, std::ios::out | std::ios::trunc);

	if (!fileStreamOut.is_open())
		return false;

	fileStreamOut << "Cryptography Benchmarking App, Log File\n\n";
	fileStreamOut << "Algorithm               : AES-GCM\n";
	fileStreamOut << "Operations              : Encryption, Decryption and Authentication\n";
	fileStreamOut << "Input Vector File Size  : " << format_number_comma_seperated(m_buffer_Size) << " B\n\n";
	fileStreamOut << "Executed Platform       : " << get_platform_name() << "\n";
	                 
	char timeNowString[256];
	std::time_t timeNow = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	if (0 == ctime_s(timeNowString, sizeof(timeNowString), &timeNow))
		fileStreamOut << "Logging Time            : " << timeNowString;


	fileStreamOut << "\n\n\n";
	fileStreamOut << "\n Total Number of Encryption Operations                                   : " << format_number_3digits_n_suffix(m_encryption_operations_count);
	fileStreamOut << "\n Total Number of Decryption Operations with Successful Authentication    : " << format_number_3digits_n_suffix(m_dencryption_operations_successful_count);
	fileStreamOut << "\n Total Number of Decryption Operations with Planned Failed Authentication: " << format_number_3digits_n_suffix(m_authentication_failed_operations_count);
	fileStreamOut << "\n Total Number of            Operations with  128-bit  key                : " << format_number_3digits_n_suffix(m_128bit_operations_count);
	fileStreamOut << "\n Total Number of            Operations with  192-bit  key                : " << format_number_3digits_n_suffix(m_192bit_operations_count);
	fileStreamOut << "\n Total Number of            Operations with  256-bit  key                : " << format_number_3digits_n_suffix(m_256bit_operations_count);
	fileStreamOut << "\n Total Volume of Messages Processed                                      : " << format_number_3digits_n_suffix(m_aes_processed_messages_total_length, 1024LL) << "B\n";

	fileStreamOut << "\n\n\nOperations Details:\n\n";

	fileStreamOut.flush();

	if (fileStreamOut.bad())
	{
		fileStreamOut.close();
		return false;
	}



	// Step 2 of 3: Preparing Message Templates for the Body of the Log
	//

	const int log_messages_count = 11;
	const size_t output_buffer_each_size = 1024LL; // length of each line of Message in Characters... since length of information like plain_text, cipher_text and key is maximum 256 bytes, 1KB for each line should be sufficient

	std::vector<int>		log_msg_titles_lengths;
	std::unique_ptr<char[]> output_buffer_raw;
	char* log_messages_buffer[log_messages_count];

	std::vector<std::string> titles{
	"Operation Encryption; Sequence No # ",
	"\tPlain Text                 : ",
	"\tKey                        : ",
	"\tInitial Vector             : ",
	"\tEncrypted Text (Reference) : ",
	"\tEncrypted Text (Calculated): ",
	"Operation Decryption + Authentication Successful; Sequence No # ",
	"Operation Decryption + Authentication Failed per Plan; Sequence No # ",
	"\tEncrypted Text             : ",
	"\tPlain Text (Reference)     : ",
	"\tPlain Text (Calculated)    : " };


	assert(log_messages_count == titles.size());

	try
	{
		output_buffer_raw = std::make_unique<char[]>(1LL + log_messages_count * output_buffer_each_size);

		char* ptrOneBuffer = output_buffer_raw.get();

		for (int i = 0; i < log_messages_count; i++)
		{
			log_msg_titles_lengths.push_back((int)titles[i].length());

			log_messages_buffer[i] = ptrOneBuffer + ((size_t)i * output_buffer_each_size);

			std::memcpy(log_messages_buffer[i], titles[i].data(), titles[i].length());
		}
	}
	catch (...)
	{
		fileStreamOut.close();
		return false;
	}




	// Step 3 of 3: Writing Body of the Log
	//

	AES_GCM_PARAMS<uint08T>	aes_gcm_params_TstData, aes_gcm_params_Output;
	uint08T					recordTypeTstData, recordTypeOutput, * bufDataVector, * bufDataOutput;
	size_t					encryption_operations_no{}, dencryption_operations_successful_no{}, authentication_failed_operations_no{};
	int						logBufferLengthActual;

	bufDataVector = m_buffer_AES_GCM_Vector.get();
	bufDataOutput = m_buffer_AES_GCM_Output.get();

	while (true)
	{
		bufDataVector = getOneRecordofData(bufDataVector, aes_gcm_params_TstData, recordTypeTstData);
		bufDataOutput = getOneRecordofData(bufDataOutput, aes_gcm_params_Output, recordTypeOutput);

		if (recordTypeOutput != recordTypeTstData)
		{
			fileStreamOut.close();
			return false;
		}

		if (0 == recordTypeTstData) // Record Type 0 means end of file
			break;


		switch (recordTypeTstData)   // based upon our record type, run a test...
		{
		case 1:     // Encryption
			encryption_operations_no++;

			logBufferLengthActual = format_binary_buffer_as_hex_string((unsigned char*)&encryption_operations_no, sizeof(encryption_operations_no), log_messages_buffer[0] + log_msg_titles_lengths[0], true);
			fileStreamOut.write(log_messages_buffer[0], logBufferLengthActual + log_msg_titles_lengths[0]);

			logBufferLengthActual = format_binary_buffer_as_hex_string(aes_gcm_params_TstData.plainText, aes_gcm_params_TstData.plainTextLength, log_messages_buffer[1] + log_msg_titles_lengths[1]);
			fileStreamOut.write(log_messages_buffer[1], logBufferLengthActual + log_msg_titles_lengths[1]);

			logBufferLengthActual = format_binary_buffer_as_hex_string(aes_gcm_params_TstData.key, aes_gcm_params_TstData.keyLength, log_messages_buffer[2] + log_msg_titles_lengths[2]);
			fileStreamOut.write(log_messages_buffer[2], logBufferLengthActual + log_msg_titles_lengths[2]);

			logBufferLengthActual = format_binary_buffer_as_hex_string(aes_gcm_params_TstData.initVector, aes_gcm_params_TstData.initVectorLength, log_messages_buffer[3] + log_msg_titles_lengths[3]);
			fileStreamOut.write(log_messages_buffer[3], logBufferLengthActual + log_msg_titles_lengths[3]);

			logBufferLengthActual = format_binary_buffer_as_hex_string(aes_gcm_params_TstData.CipherText, aes_gcm_params_TstData.CipherTextLength, log_messages_buffer[4] + log_msg_titles_lengths[4]);
			fileStreamOut.write(log_messages_buffer[4], logBufferLengthActual + log_msg_titles_lengths[4]);

			logBufferLengthActual = format_binary_buffer_as_hex_string(aes_gcm_params_Output.CipherText, aes_gcm_params_Output.CipherTextLength, log_messages_buffer[5] + log_msg_titles_lengths[5]);
			fileStreamOut.write(log_messages_buffer[5], logBufferLengthActual + log_msg_titles_lengths[5]);

			fileStreamOut.write("\n", 1);
			break;

		case 2:   // Decryption OK
		case 3:   // Decryption Failed Because of Authetication (as per Plan)
			if (2 == recordTypeTstData)  // Decryption OK
			{
				dencryption_operations_successful_no++;

				logBufferLengthActual = format_binary_buffer_as_hex_string((unsigned char*)&dencryption_operations_successful_no, sizeof(dencryption_operations_successful_no), log_messages_buffer[6] + log_msg_titles_lengths[6], true);
				fileStreamOut.write(log_messages_buffer[6], logBufferLengthActual + log_msg_titles_lengths[6]);
			}
			else
			{
				authentication_failed_operations_no++;

				logBufferLengthActual = format_binary_buffer_as_hex_string((unsigned char*)&authentication_failed_operations_no, sizeof(authentication_failed_operations_no), log_messages_buffer[7] + log_msg_titles_lengths[7], true);
				fileStreamOut.write(log_messages_buffer[7], logBufferLengthActual + log_msg_titles_lengths[7]);
			}


			logBufferLengthActual = format_binary_buffer_as_hex_string(aes_gcm_params_TstData.CipherText, aes_gcm_params_TstData.CipherTextLength, log_messages_buffer[8] + log_msg_titles_lengths[8]);
			fileStreamOut.write(log_messages_buffer[8], logBufferLengthActual + log_msg_titles_lengths[8]);

			logBufferLengthActual = format_binary_buffer_as_hex_string(aes_gcm_params_TstData.key, aes_gcm_params_TstData.keyLength, log_messages_buffer[2] + log_msg_titles_lengths[2]);
			fileStreamOut.write(log_messages_buffer[2], logBufferLengthActual + log_msg_titles_lengths[2]);

			logBufferLengthActual = format_binary_buffer_as_hex_string(aes_gcm_params_TstData.initVector, aes_gcm_params_TstData.initVectorLength, log_messages_buffer[3] + log_msg_titles_lengths[3]);
			fileStreamOut.write(log_messages_buffer[3], logBufferLengthActual + log_msg_titles_lengths[3]);

			if (2 == recordTypeTstData)  // Decryption OK
			{
				logBufferLengthActual = format_binary_buffer_as_hex_string(aes_gcm_params_TstData.plainText, aes_gcm_params_TstData.plainTextLength, log_messages_buffer[9] + log_msg_titles_lengths[9]);
				fileStreamOut.write(log_messages_buffer[9], logBufferLengthActual + log_msg_titles_lengths[9]);

				logBufferLengthActual = format_binary_buffer_as_hex_string(aes_gcm_params_Output.plainText, aes_gcm_params_Output.plainTextLength, log_messages_buffer[10] + log_msg_titles_lengths[10]);
				fileStreamOut.write(log_messages_buffer[10], logBufferLengthActual + log_msg_titles_lengths[10]);
			}

			fileStreamOut.write("\n", 1);
			break;
		}
	}


	fileStreamOut.write("\n", 1);


	if (fileStreamOut.bad())
	{
		fileStreamOut.close();
		return false;
	}

	fileStreamOut.close();
	return true;
}
