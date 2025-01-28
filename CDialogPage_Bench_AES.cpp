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

// CDialogPage_Bench_AES.cpp : implementation file
//

#include "pch.h"
#include "afxdialogex.h"
#include "EncryptionBenchmark.h"
#include "CDialogPage_Bench_AES.h"

#include <chrono>
#include <filesystem>
#include <sstream>
#include <type_traits>
#include <thread>


#include "utility.h"
#include "system_info.h"
#include "AES_GCM_IPP.h"
#include "AES_GCM_CPU.h"
#include "AES_GCM_GPU.cuh"


/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                          General                                                               */
/*                                                         Functions                                                              */
/*                                                                                                                                */
/**********************************************************************************************************************************/

// CDialogPage_Bench_AES dialog

IMPLEMENT_DYNAMIC(CDialogPage_Bench_AES, CMFCPropertyPage)

CDialogPage_Bench_AES::CDialogPage_Bench_AES(CWnd* pParent /*=nullptr*/)
	: CMFCPropertyPage(IDD_PROPPAGE_BENCH_AES)
{
	m_psp.dwFlags &= ~PSP_HASHELP;
	m_psp.dwFlags |= PSH_NOAPPLYNOW;

	m_bIsAESTasksRunning = false;


	for (int index = 0; index < 3; index++) // for CPU, GPU and IPP
	{
		m_calibration_param_timeExecutionOneRound_ms[index] = 0.0;
		m_calibration_param_messageLengthOneRound_bytes[index] = 0LL;
	}
}

CDialogPage_Bench_AES::~CDialogPage_Bench_AES()
{
}

void CDialogPage_Bench_AES::DoDataExchange(CDataExchange* pDX)
{
	CMFCPropertyPage::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_TEST_DATA_FILES, m_ListTestDataFiles);
}


BEGIN_MESSAGE_MAP(CDialogPage_Bench_AES, CMFCPropertyPage)
	ON_BN_CLICKED(IDC_BUTTON_SET_DEFAULTS, &CDialogPage_Bench_AES::OnClickedButtonSetDefaults)
	ON_BN_CLICKED(IDC_BUTTON_CLEAR_RESULTS, &CDialogPage_Bench_AES::OnClickedButtonClearResults)
	ON_BN_CLICKED(IDC_BUTTON_RUN, &CDialogPage_Bench_AES::OnClickedButtonRun)
	ON_LBN_SELCHANGE(IDC_LIST_TEST_DATA_FILES, &CDialogPage_Bench_AES::OnSelchangeListTestDataFiles)
END_MESSAGE_MAP()


// CDialogPage_Bench_AES message handlers

/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       OnSetActive()                                                            */
/*                                                         Functions                                                              */
/*                                                                                                                                */
/**********************************************************************************************************************************/

BOOL CDialogPage_Bench_AES::OnSetActive()
{
	// TODO: Add your specialized code here and/or call the base class
	CString msg;

	CMFCPropertySheet* psheet = (CMFCPropertySheet*)GetParent();
	psheet->GetDlgItem(IDCANCEL)->ShowWindow(SW_HIDE);

	std::filesystem::path pathCurrent = std::filesystem::current_path();

	msg = pathCurrent.string().data();
	SetDlgItemTextW(IDC_EDIT_CURRENT_DIRECTORY, msg);


	while (m_ListTestDataFiles.GetCount())
		m_ListTestDataFiles.DeleteString(0);


	for (auto e : std::filesystem::directory_iterator(pathCurrent))
	{
		if (e.is_regular_file())
		{
			std::string fileExtension = e.path().extension().string();
			std::transform(fileExtension.begin(), fileExtension.end(), fileExtension.begin(), ::tolower);

			if (0 == fileExtension.compare(getDefaultExtentionForAESTestDataFiles()))
			{
				msg = e.path().filename().string().data();
				m_ListTestDataFiles.AddString(msg);
			}
		}
	}

	if (m_ListTestDataFiles.GetCount() > 0)
		m_ListTestDataFiles.SetCurSel(0);


	return CMFCPropertyPage::OnSetActive();
}


/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       OnInitDialog()                                                           */
/*                                                         Functions                                                              */
/*                                                                                                                                */
/**********************************************************************************************************************************/

BOOL CDialogPage_Bench_AES::OnInitDialog()
{
	CMFCPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here

	((CButton*)GetDlgItem(IDC_RADIO_ON_CPU))->SetCheck(0);
	((CButton*)GetDlgItem(IDC_RADIO_ON_IPP))->SetCheck(0);
	((CButton*)GetDlgItem(IDC_RADIO_ON_GPU))->SetCheck(1);


	CString cmsg;
	cmsg.Format(L"%d", (int)APDU_SIZE);
	SetDlgItemTextW(IDC_EDIT_APDU_SIZE, cmsg);
	

	OnClickedButtonSetDefaults();


	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}



/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       Read & Return Parameters                                                 */
/*                                                       From UI (+ Boundry Check)                                                */
/*                                                                                                                                */
/**********************************************************************************************************************************/


bool CDialogPage_Bench_AES::RetriveRunningParamsFromUI(RUNNIN_PLATFORM& platform, std::string& strFileNameInput, std::string& strFileNameLog, bool& runBasedonTime, std::vector<long>& runningParams)
{
	// TODO: Add your control notification handler code here
	CString			cStr;
	std::wstring	wideStr;
	std::string		strTmp, strInputFileName, strLogFileName;

	int				index = 0;
	bool            isEditBoxValuesAdjusted = false;


	if (m_ListTestDataFiles.GetCount() <= 0)
	{
		AfxMessageBox(L"Please Choose a Test Data File as Input Source");
		return false;
	}
	else
	{
		m_ListTestDataFiles.GetText(m_ListTestDataFiles.GetCurSel(), cStr);
		strFileNameInput = CW2A(cStr);
	}


	GetDlgItemTextW(IDC_EDIT_LOG_FILENAME, cStr);
	strFileNameLog = CW2A(cStr);


	std::vector<int>  editBoxIDs{ IDC_EDIT_THREAD_BLOCKS_COUNT , IDC_EDIT_THREADS_PER_BLOCK_COUNT, IDC_EDIT_DATA_RUN_TIME , IDC_EDIT_DATA_RUN_SIZE };
	std::vector<long> editBoxValuesMax{ 20'000L, 10'000, 86'400L, 4'096'000L };  // Thread_Blocks * Threads_per_Block must be < MAX_LONG
	std::vector<long> editBoxValuesMin{ 1L     , 1L    , 1L     , 1L };


	long editBoxValue;
	for (auto e : editBoxIDs)
	{
		GetDlgItemTextW(e, cStr);
		wideStr = cStr.GetBuffer();
		try {
			editBoxValue = std::stol(wideStr);
		}
		catch (...)
		{
			editBoxValue = 0x7FFFFFFF;  // a big number so later it can be adjusted to the specified maximum (ceil)
		}

		if (editBoxValue > editBoxValuesMax[index])
		{
			isEditBoxValuesAdjusted = true;
			editBoxValue = editBoxValuesMax[index];
		}

		if (editBoxValue < editBoxValuesMin[index])
		{
			isEditBoxValuesAdjusted = true;
			editBoxValue = editBoxValuesMin[index];
		}


		runningParams.push_back(editBoxValue);
		++index;
	}

	if (true == isEditBoxValuesAdjusted)
	{
		for (index = 0; index < editBoxIDs.size(); index++)
		{
			cStr.Format(L"%ld", runningParams[index]);
			SetDlgItemTextW(editBoxIDs[index], cStr);
		}

		AfxMessageBox(L"Running Parameters are Adjusted to be within Meaningful Range");
	}

	if (0 != ((CButton*)GetDlgItem(IDC_RADIO_FIXED_TIME))->GetCheck())
		runBasedonTime = true;
	else
		runBasedonTime = false;


	platform = RUNNIN_PLATFORM::CPU;

	if (0 != ((CButton*)GetDlgItem(IDC_RADIO_ON_GPU))->GetCheck())
		platform = RUNNIN_PLATFORM::GPU;

	if (0 != ((CButton*)GetDlgItem(IDC_RADIO_ON_IPP))->GetCheck())
		platform = RUNNIN_PLATFORM::IPP;

	return true;
}



/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       Event Handlers                                                           */
/*                                                         Functions                                                              */
/*                                                                                                                                */
/**********************************************************************************************************************************/

void CDialogPage_Bench_AES::OnClickedButtonSetDefaults()
{
	// TODO: Add your control notification handler code here
	CString msg;

	AES_GCM_CPU aes_gcm_cpu;
	AES_GCM_GPU aes_gcm_gpu;
	AES_GCM_IPP aes_gcm_ipp;
	AES_GCM* p_aes_gcm{ dynamic_cast<AES_GCM*>(&aes_gcm_cpu) };

	if (0 != ((CButton*)GetDlgItem(IDC_RADIO_ON_IPP))->GetCheck())
		p_aes_gcm = dynamic_cast<AES_GCM*>(&aes_gcm_ipp);

	if (0 != ((CButton*)GetDlgItem(IDC_RADIO_ON_GPU))->GetCheck())
		p_aes_gcm = dynamic_cast<AES_GCM*>(&aes_gcm_gpu);



	auto [SMCount, Cores_per_SM_Count] = p_aes_gcm->get_processing_cores_total();

	msg.Format(L"%ld", SMCount);
	SetDlgItemTextW(IDC_EDIT_THREAD_BLOCKS_COUNT, msg);

	msg.Format(L"%ld", Cores_per_SM_Count);
	SetDlgItemTextW(IDC_EDIT_THREADS_PER_BLOCK_COUNT, msg);

	
	SetDlgItemTextW(IDC_EDIT_DATA_RUN_TIME, L"10");
	SetDlgItemTextW(IDC_EDIT_DATA_RUN_SIZE, L"100");
	SetDlgItemTextW(IDC_EDIT_LOG_FILENAME , L"_log_aes.txt");

	((CButton*)GetDlgItem(IDC_RADIO_DATA_SIZE))->SetCheck(0);
	((CButton*)GetDlgItem(IDC_RADIO_FIXED_TIME))->SetCheck(1);
}



void CDialogPage_Bench_AES::OnClickedButtonClearResults()
{
	// TODO: Add your control notification handler code here
	SetDlgItemTextW(IDC_EDIT_STATUS, L"");
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_TIME, L"");
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_DATA_SIZE, L"");
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_OPER_COUNT, L"");
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_APDUPERS, L"");
}


void CDialogPage_Bench_AES::OnSelchangeListTestDataFiles()
{
	// TODO: Add your control notification handler code here
	for (int index = 0; index < 3; index++) // for CPU, GPU and IPP
	{
		m_calibration_param_timeExecutionOneRound_ms[index] = 0.0;
		m_calibration_param_messageLengthOneRound_bytes[index] = 0LL;
	}
}


void CDialogPage_Bench_AES::OnClickedButtonRun()
{
	std::vector<long>	runningParams;
	std::string			fileNameInput, fileNameLog;
	bool				runBasedonTime;
	RUNNIN_PLATFORM     runningplatform;
		

	if(true == m_bIsAESTasksRunning)
		return;


	if (false == RetriveRunningParamsFromUI(runningplatform, fileNameInput, fileNameLog, runBasedonTime, runningParams))
		return;

	OnClickedButtonClearResults();


	std::thread aesRunningThread;

	aesRunningThread = std::thread(&CDialogPage_Bench_AES::calibrate_and_runAES_benchmark, this, runningplatform, fileNameInput, fileNameLog, runBasedonTime, runningParams);

	aesRunningThread.detach();
}



/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       Starts AES-GCM Benchmarking                                              */
/*                                                        Runs as a Parallel Thread,                                              */
/*                                             Calibrates & Calculates Number of Executions Rounds                                */
/*                                        Then Calls    runAESTasks()  Function to Actually Runs AES Tasks                        */
/*                                                                                                                                */
/**********************************************************************************************************************************/

void CDialogPage_Bench_AES::calibrate_and_runAES_benchmark(const RUNNIN_PLATFORM runningplatform, const std::string fileNameInput, const std::string fileNameLog, const bool runBasedonTime, const std::vector<long> runningParams)
{
	const size_t MIN_totalOperations_oneRound = 10LL, MIN_messageLengthOneRound_bytes = 1024LL;  // setting some minimums by my common-sense
	const double MIN_timeExecutionOneRound_ms = 10.0;											 // setting some minimums by my common-sense

	CString msg;


	if (true == m_bIsAESTasksRunning)
		return;

	m_bIsAESTasksRunning = true;
	((CButton*)GetDlgItem(IDC_BUTTON_RUN))->EnableWindow(FALSE);


	// Size of following AES_GCM_XXX ojects are very small (if their test data buffer is not filled out)	
	AES_GCM_CPU aes_gcm_cpu;
	AES_GCM_IPP aes_gcm_ipp;
	AES_GCM_GPU aes_gcm_gpu;

	AES_GCM* p_aes_gcm{ dynamic_cast<AES_GCM*>(&aes_gcm_cpu) }; // Polymorphic Object

	if (RUNNIN_PLATFORM::IPP == runningplatform)
		p_aes_gcm = dynamic_cast<AES_GCM*>(&aes_gcm_ipp);

	if (RUNNIN_PLATFORM::GPU == runningplatform)
		p_aes_gcm = dynamic_cast<AES_GCM*>(&aes_gcm_gpu);



	SetDlgItemTextW(IDC_EDIT_STATUS, L"Loading Test Data File....");
	try {
		p_aes_gcm->load_AES_GCM_Vector_File_to_Buffer(fileNameInput);
	}
	catch (std::exception& e) {
		msg = e.what();
		AfxMessageBox(msg);
		SetDlgItemTextW(IDC_EDIT_STATUS, msg);

		m_bIsAESTasksRunning = false;
		((CButton*)GetDlgItem(IDC_BUTTON_RUN))->EnableWindow(TRUE);

		return;
	}

	p_aes_gcm->delete_zero_length_data_from_AES_GCM_Vector_Buffer();


	/*
	*  Start of Calibration Process
	*/

	double	timeExecutionOneRound_ms{ }; // ms
	size_t messageLengthOneRound_bytes{ }, totalOperations_oneRound{ }; // Bytes, Rounds

	// if calibration parameters are zero then, it is the first time calibration for this platform, so let's calculate calibration parameters
	if ((m_calibration_param_timeExecutionOneRound_ms[runningplatform] < 1.0) || (m_calibration_param_messageLengthOneRound_bytes[runningplatform] < 1LL))
	{
		SetDlgItemTextW(IDC_EDIT_STATUS, L"Calibrating Processing Parameters for the Execution.....");


		long executionrounds{ 1L };

		try {
			for (; executionrounds <= 1'000'000L; executionrounds *= 10L)
			{
				auto tStart = std::chrono::high_resolution_clock::now();

				p_aes_gcm->run_Benchmark(1L, 1L, executionrounds);

				auto tEnd = std::chrono::high_resolution_clock::now();

				const std::chrono::duration<double, std::milli> passed = tEnd - tStart;
				timeExecutionOneRound_ms = passed.count();

				if (timeExecutionOneRound_ms > (25.0 * MIN_timeExecutionOneRound_ms))  // 25.0 is just a common sense, we want the calibration process runs long enough
					break;
			}
		}
		catch (std::exception& e) {
			msg = e.what();
			AfxMessageBox(msg);
			SetDlgItemTextW(IDC_EDIT_STATUS, msg);

			m_bIsAESTasksRunning = false;
			((CButton*)GetDlgItem(IDC_BUTTON_RUN))->EnableWindow(TRUE);

			return;
		}

		if (timeExecutionOneRound_ms < MIN_timeExecutionOneRound_ms) //ms
		{
			msg = L"Error #DBA-01: Processing Calibration is Failed Because Processor Over-performed";
			AfxMessageBox(msg);
			SetDlgItemTextW(IDC_EDIT_STATUS, msg);

			m_bIsAESTasksRunning = false;
			((CButton*)GetDlgItem(IDC_BUTTON_RUN))->EnableWindow(TRUE);

			return;
		}

		std::tie(messageLengthOneRound_bytes, totalOperations_oneRound) = p_aes_gcm->get_processed_data_volume();

		timeExecutionOneRound_ms /= (double)executionrounds;	// ms
		messageLengthOneRound_bytes /= (size_t)executionrounds;	// Bytes
		totalOperations_oneRound /= (size_t)executionrounds;


		if ((totalOperations_oneRound < MIN_totalOperations_oneRound) || (messageLengthOneRound_bytes < MIN_messageLengthOneRound_bytes))  // these numbers has root in my common-sense only
		{
			msg = L"Error #DBA-02: Test Data File is too Small, It has Less than 10 Operations or Total Data Size is Less than 1KB";
			AfxMessageBox(msg);
			SetDlgItemTextW(IDC_EDIT_STATUS, msg);

			m_bIsAESTasksRunning = false;
			((CButton*)GetDlgItem(IDC_BUTTON_RUN))->EnableWindow(TRUE);

			return;
		}



		m_calibration_param_timeExecutionOneRound_ms[runningplatform] = timeExecutionOneRound_ms;
		m_calibration_param_messageLengthOneRound_bytes[runningplatform] = messageLengthOneRound_bytes;
	}
	else // calibration has been done before, so just use those parameters
	{
		timeExecutionOneRound_ms = m_calibration_param_timeExecutionOneRound_ms[runningplatform];
		messageLengthOneRound_bytes = m_calibration_param_messageLengthOneRound_bytes[runningplatform];
	}

	/*
	*  End of Calibration Process 
	*/



	// Now calculating each thread should calculate how many rounds (times) of AES_GCM::run_Encyption_Decryption_on_Vector()
	long calculationsRoundPerThread{};
	if (runBasedonTime) // running based on time
	{
		//runningParams[2] is total run time (s)
		double roundsPerCore{ ((1000.0 * (double)runningParams[2]) / timeExecutionOneRound_ms) };

		if (roundsPerCore < 1.0)
			roundsPerCore = 1.0;

		//runningParams[0] is number of thread-blocks and runningParams[1] is number of threads per block 
		auto [SMCount, Cores_per_SM_Count] = p_aes_gcm->get_processing_cores_total();

		if (SMCount < 1L)
			SMCount = 1L;

		if (Cores_per_SM_Count < 1L)
			Cores_per_SM_Count = 1L;

		double threadsPerCore{ std::ceil((double)(runningParams[0] * runningParams[1]) / (double)(SMCount * Cores_per_SM_Count)) };

		if (threadsPerCore < 1.0)
			threadsPerCore = 1.0;

		calculationsRoundPerThread = (long)(roundsPerCore /= threadsPerCore);
	}
	else // running based on data volume size,  runningParams[3] = data size per thread (MB)
		calculationsRoundPerThread = (long)(((1024LL * 1024LL * (size_t)runningParams[3]) / messageLengthOneRound_bytes));


	if (0L == calculationsRoundPerThread)
		calculationsRoundPerThread = 1L; // minimum value



	if (RUNNIN_PLATFORM::CPU == runningplatform) //runningParams[0] is number of thread-blocks and runningParams[1] is number of threads per block 
		runAESTasks<AES_GCM_CPU>(runningParams[0], runningParams[1], calculationsRoundPerThread, fileNameInput, fileNameLog);


	if (RUNNIN_PLATFORM::IPP == runningplatform)
		runAESTasks<AES_GCM_IPP>(runningParams[0], runningParams[1], calculationsRoundPerThread, fileNameInput, fileNameLog);


	if (RUNNIN_PLATFORM::GPU == runningplatform)
		runAESTasks<AES_GCM_GPU>(runningParams[0], runningParams[1], calculationsRoundPerThread, fileNameInput, fileNameLog);



	m_bIsAESTasksRunning = false;
	((CButton*)GetDlgItem(IDC_BUTTON_RUN))->EnableWindow(TRUE);
}



/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                      Actually RUNs AES-GCM Tasks                                               */
/*                                                                                                                                */
/**********************************************************************************************************************************/

template<typename AES_TYPE> void CDialogPage_Bench_AES::runAESTasks(const long threadBlocksCount, const long threadsPerBlockCount, const long executionCount, const std::string& fileNameInput, const std::string& fileNameLog)
{
	static_assert(std::is_base_of_v<AES_GCM, AES_TYPE>, "Function Template Type is NOT a Derived Type of AES_GCM Class");

	if constexpr (!std::is_base_of_v<AES_GCM, AES_TYPE>) // just for test here, above line is sufficient
		return;


	if ((threadBlocksCount < 1L) || (threadsPerBlockCount < 1L) || (executionCount < 1L))
		return;


	CString msg;
	std::stringstream ss;


	if ((1L == threadBlocksCount) && (1L == threadsPerBlockCount))
		ss << "Creating and Running a Single Thread....";
	else
		ss << "Creating and Running " << threadBlocksCount  << " * " << threadsPerBlockCount << " Threads...";

	msg = ss.str().data();
	SetDlgItemTextW(IDC_EDIT_STATUS, msg);
	ss.str("");


	AES_TYPE obj_aes_gcm;

	try {
		obj_aes_gcm.load_AES_GCM_Vector_File_to_Buffer(fileNameInput);
	}
	catch (std::exception& e) {
		msg = e.what();
		SetDlgItemTextW(IDC_EDIT_STATUS, msg);
		AfxMessageBox(msg);

		return;
	}

	obj_aes_gcm.delete_zero_length_data_from_AES_GCM_Vector_Buffer();




	auto tStart = std::chrono::high_resolution_clock::now();

	try
	{
		obj_aes_gcm.run_Benchmark(threadBlocksCount, threadsPerBlockCount, executionCount);
	}
	catch (std::exception& e) {
		msg = e.what();
		SetDlgItemTextW(IDC_EDIT_STATUS, msg);
		AfxMessageBox(msg);

		return;
	}

	auto tEnd = std::chrono::high_resolution_clock::now();


	const std::chrono::duration<double, std::milli> passed = tEnd - tStart;
	size_t timeElapsedProcessingTotal_ms{ (size_t)passed.count() };

	if (timeElapsedProcessingTotal_ms < 1LL)
		timeElapsedProcessingTotal_ms = 1LL;


	SetDlgItemTextW(IDC_EDIT_STATUS, L"Main Process has been Finished, Logging Has Been Started......");

	std::string logMsg{""};
	
	if (false == obj_aes_gcm.log_write_file(fileNameLog))
		logMsg = "Logging Failed but ";

	

	auto [messageLengthTotal, operationsCountTotal] = obj_aes_gcm.get_processed_data_volume();


	size_t Throughput = (messageLengthTotal / timeElapsedProcessingTotal_ms) * 1000LL; // convery ms -> s
	size_t APDUperSec = ((messageLengthTotal / timeElapsedProcessingTotal_ms) * 1000LL) / APDU_SIZE;

	ss << logMsg << "AES-GCM Operations is Done Successfully by Running " << threadBlocksCount << " * " << threadsPerBlockCount << " Threads";
	ss << ", Measured Throughput:  " << format_number_3digits_n_suffix(Throughput) << "B/s";
	msg = ss.str().data();
	SetDlgItemTextW(IDC_EDIT_STATUS, msg);

	msg = format_number_as_Time_Duration(timeElapsedProcessingTotal_ms).data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_TIME, msg);

	msg = (format_number_3digits_n_suffix(messageLengthTotal, 1024LL) + "B").data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_DATA_SIZE, msg);

	msg = format_number_3digits_n_suffix(operationsCountTotal).data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_OPER_COUNT, msg);

	msg = (format_number_comma_seperated(APDUperSec)).data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_APDUPERS, msg);
}
