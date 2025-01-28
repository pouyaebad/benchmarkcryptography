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

// CDialogPage_Bench_ECC_SHA.cpp : implementation file
//

#include "pch.h"
#include "EncryptionBenchmark.h"
#include "afxdialogex.h"
#include "CDialogPage_Bench_ECC_SHA.h"

#include <thread>

#include "utility.h"

#include "SHA256.h"

#include "ECDSA256.h"
#include "ECDSA256_Examples.h"

/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                          General                                                               */
/*                                                         Functions                                                              */
/*                                                                                                                                */
/**********************************************************************************************************************************/

// CDialogPage_Bench_ECC_SHA dialog

IMPLEMENT_DYNAMIC(CDialogPage_Bench_ECC_SHA, CMFCPropertyPage)

CDialogPage_Bench_ECC_SHA::CDialogPage_Bench_ECC_SHA(CWnd* pParent /*=nullptr*/)
	: CMFCPropertyPage(IDD_PROPPAGE_BENCH_ECC)
{
	m_psp.dwFlags &= ~PSP_HASHELP;
	m_psp.dwFlags |= PSH_NOAPPLYNOW;
}

CDialogPage_Bench_ECC_SHA::~CDialogPage_Bench_ECC_SHA()
{
}

void CDialogPage_Bench_ECC_SHA::DoDataExchange(CDataExchange* pDX)
{
	CMFCPropertyPage::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO_SAMPLE_ECDSA, m_combo_SamplesList);
}


BEGIN_MESSAGE_MAP(CDialogPage_Bench_ECC_SHA, CMFCPropertyPage)
	ON_BN_CLICKED(IDC_BUTTON_RUN_SHA, &CDialogPage_Bench_ECC_SHA::OnBnClickedButtonRunSha)
	ON_BN_CLICKED(IDC_BUTTON_RUN_ECDSA, &CDialogPage_Bench_ECC_SHA::OnBnClickedButtonRunEcdsa)
	ON_BN_CLICKED(IDC_BUTTON_CLEAR_RESULTS, &CDialogPage_Bench_ECC_SHA::OnBnClickedButtonClearResults)
	ON_CBN_SELCHANGE(IDC_COMBO_SAMPLE_ECDSA, &CDialogPage_Bench_ECC_SHA::OnSelchangeComboSampleEcdsa)
	ON_COMMAND(IDC_RADIO_MSG_RANDOM, &CDialogPage_Bench_ECC_SHA::OnRadioMsgRandom)
	ON_COMMAND(IDC_RADIO_MSG_MANUAL, &CDialogPage_Bench_ECC_SHA::OnRadioMsgManual)
END_MESSAGE_MAP()


// CDialogPage_Bench_ECC_SHA message handlers

/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       OnSetActive()                                                            */
/*                                                         Functions                                                              */
/*                                                                                                                                */
/**********************************************************************************************************************************/


BOOL CDialogPage_Bench_ECC_SHA::OnSetActive()
{
	// TODO: Add your specialized code here and/or call the base class
	CMFCPropertySheet* psheet = (CMFCPropertySheet*)GetParent();
	psheet->GetDlgItem(IDCANCEL)->ShowWindow(SW_HIDE);

	return CMFCPropertyPage::OnSetActive();
}


/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       OnInitDialog()                                                           */
/*                                                         Functions                                                              */
/*                                                                                                                                */
/**********************************************************************************************************************************/


BOOL CDialogPage_Bench_ECC_SHA::OnInitDialog()
{
	CMFCPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here
	((CButton*)GetDlgItem(IDC_RADIO_MSG_RANDOM))->SetCheck(0);
	((CButton*)GetDlgItem(IDC_RADIO_MSG_MANUAL))->SetCheck(1);

	SetDlgItemTextW(IDC_EDIT_DATA_RUN_TIME, L"10");


	m_combo_SamplesList.AddString(L"NIST - 1");
	m_combo_SamplesList.AddString(L"NIST - 2");

	m_combo_SamplesList.SetCurSel(0);

	OnSelchangeComboSampleEcdsa();


	CString cmsg;
	cmsg.Format(L"%d", (int)APDU_SIZE);
	SetDlgItemTextW(IDC_EDIT_APDU_SIZE, cmsg);


	auto tNow = std::chrono::high_resolution_clock::now();
	m_RNG_engine.discard((tNow.time_since_epoch().count()) % 237);

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       General Helper Functions                                                 */
/*                                                                                                                                */
/**********************************************************************************************************************************/


void CDialogPage_Bench_ECC_SHA::RetriveRunningParamsFromUI(long& executionTime)
{
	bool isEditBoxValuesAdjusted{ false };
	CString cmsg;
	std::wstring wideStr;


	GetDlgItemTextW(IDC_EDIT_DATA_RUN_TIME, cmsg);
	wideStr = cmsg.GetBuffer();
	try {
		executionTime = std::stol(wideStr);
	}
	catch (...)
	{
		executionTime = 0x7FFFFFFF;  // a big number so later it can be adjusted to the specified maximum (ceil)
	}

	if (executionTime > 86'400L) // it is one day
	{
		isEditBoxValuesAdjusted = true;
		executionTime = 86'400L;
	}

	if (executionTime < 1L)
	{
		isEditBoxValuesAdjusted = true;
		executionTime = 1L;
	}

	if (true == isEditBoxValuesAdjusted)
	{
		cmsg.Format(L"%ld", executionTime);
		SetDlgItemTextW(IDC_EDIT_DATA_RUN_TIME, cmsg);

		AfxMessageBox(L"Running Parameters are Adjusted to be within Meaningful Range");
	}
}



CString CDialogPage_Bench_ECC_SHA::fomattedHexBufferOnScreen(const unsigned char* msg, const int len) const
{
	constexpr int MAX_BUF_SIZE = 2048;
	char textOnScrBuf[MAX_BUF_SIZE];
	CString retVal = L"";

	if (len > MAX_BUF_SIZE / 4) // generated text message will take up to 4 times space in the buffer, see following implementation
		return retVal;


	format_binary_buffer_as_hex_string(msg, len, textOnScrBuf);

	for (int i = 1; i < len / 32; i++)
	{
		// each line comprises of 4 blocks of 8 hex byte-numbers (each has 2 digits and space) plus 3 more spaces between blocks and an extra in the begining
		textOnScrBuf[i * 4 * (8 * 3 + 3) + 1] = '\r';
		textOnScrBuf[i * 4 * (8 * 3 + 3) + 2] = '\n';
	}

	retVal = &(textOnScrBuf[3]);

	return retVal;
}



/**********************************************************************************************************************************/
/*                                                                                                                                */
/*                                                       Event Handlers                                                           */
/*                                                         Functions                                                              */
/*                                                                                                                                */
/**********************************************************************************************************************************/


void CDialogPage_Bench_ECC_SHA::OnBnClickedButtonClearResults()
{
	// TODO: Add your control notification handler code here
	SetDlgItemTextW(IDC_EDIT_STATUS, L"");
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_TIME, L"");
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_DATA_SIZE, L"");
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_OPER_COUNT, L"");
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_APDUPERS, L"");
}



void CDialogPage_Bench_ECC_SHA::OnRadioMsgManual()
{
	// TODO: Add your command handler code here
	SetDlgItemTextW(IDC_EDIT_INPUT_MSG_SHA256, L"");
	((CEdit*)GetDlgItem(IDC_EDIT_INPUT_MSG_SHA256))->SetReadOnly(0);
}



void CDialogPage_Bench_ECC_SHA::OnRadioMsgRandom()
{
	// TODO: Add your command handler code here
	for (size_t index = 0; index < m_random_message_size; index++)
		m_message_random_128B[index] = (unsigned char)m_RNG_dist(m_RNG_engine);

	CString msg = fomattedHexBufferOnScreen(m_message_random_128B, m_random_message_size);

	if (msg.GetLength() > 0)
	{
		((CEdit*)GetDlgItem(IDC_EDIT_INPUT_MSG_SHA256))->SetReadOnly(1);
		SetDlgItemTextW(IDC_EDIT_INPUT_MSG_SHA256, msg);
	}
}



void CDialogPage_Bench_ECC_SHA::OnSelchangeComboSampleEcdsa()
{
	// TODO: Add your control notification handler code here

	const unsigned char* msg, * sig, * pk;
	switch (m_combo_SamplesList.GetCurSel())
	{
	case 0:
		msg = ECDSA_Example_1_Message;
		sig = ECDSA_Example_1_Signature;
		pk = ECDSA_Example_1_PublicKey;
		break;

	case 1:
		msg = ECDSA_Example_2_Message;
		sig = ECDSA_Example_2_Signature;
		pk = ECDSA_Example_2_PublicKey;
		break;

	default:
		return;
		break;
	}

	
	CString tetextOnScr= fomattedHexBufferOnScreen(msg, ECDSA_EXAMPLE_MESSAGE_LENGTH);
	SetDlgItemTextW(IDC_EDIT_MSG_ECDSA, tetextOnScr);

	tetextOnScr = fomattedHexBufferOnScreen(sig, 64);
	SetDlgItemTextW(IDC_EDIT_SIG_ECDSA, tetextOnScr);

	tetextOnScr = fomattedHexBufferOnScreen(&(pk[1]), 64);
	SetDlgItemTextW(IDC_EDIT_PK_ECDSA, tetextOnScr);
}


/**********************************************************************************************************************************/
/*                                                         Run SHA - 256                                                          */
/**********************************************************************************************************************************/

void CDialogPage_Bench_ECC_SHA::OnBnClickedButtonRunSha()
{
	// TODO: Add your control notification handler code here
	
	if (true == m_bIsTasksRunning)
		return;


	if (0 != ((CButton*)GetDlgItem(IDC_RADIO_MSG_MANUAL))->GetCheck()) // use user input message
	{
		CString cmsg;
		GetDlgItemTextW(IDC_EDIT_INPUT_MSG_SHA256, cmsg);

		if (cmsg.GetLength() < 1)
		{
			AfxMessageBox(L"Error #DBS-01: No Message is Provided for Hashing Input");
			return;
		}
	}


	long executionTime;
	RetriveRunningParamsFromUI(executionTime);

	OnBnClickedButtonClearResults();



	std::thread ThreadtoRun;

	ThreadtoRun = std::thread(&CDialogPage_Bench_ECC_SHA::calibrate_and_runSHA256_benchmark, this, executionTime);

	ThreadtoRun.detach();
}



/**********************************************************************************************************************************/
/*                                                           Run ECDSA                                                            */
/**********************************************************************************************************************************/

void CDialogPage_Bench_ECC_SHA::OnBnClickedButtonRunEcdsa()
{
	// TODO: Add your control notification handler code here

	if (true == m_bIsTasksRunning)
		return;


	long executionTime;
	RetriveRunningParamsFromUI(executionTime);

	OnBnClickedButtonClearResults();



	std::thread ThreadtoRun;

	ThreadtoRun = std::thread(&CDialogPage_Bench_ECC_SHA::calibrate_and_runECDSA_benchmark, this, executionTime);

	ThreadtoRun.detach();
}



/**********************************************************************************************************************************/
/*																																  */
/*                                                      Actual Benchmarking Functions                                             */
/*                                                Each Function Runs as a Parallel Thread,                                        */
/*                                           Calibrates & Calculates Number of Executions Rounds                                  */
/*                                    Then Runs Related Hashing/Digital Signature Verification Function                           */
/*                                            and Reports Brnchmarking Result on the Screen                                       */
/*                                                                                                                                */
/**********************************************************************************************************************************/

/**********************************************************************************************************************************/
/*                                                           Run ECDSA                                                            */
/**********************************************************************************************************************************/

void CDialogPage_Bench_ECC_SHA::calibrate_and_runECDSA_benchmark(const long executionTime)
{
	CString				cmsg;
	std::stringstream	ss;
	size_t				messageLengthTotal{}, Throughput{}, operationsCountTotal{}, APDUperSec{};
	const double		MIN_timeExecutionOneRound_ms = 10.0;	// setting some minimums by my common-sense
	const unsigned char *msg, * sig, * pk;


	switch (m_combo_SamplesList.GetCurSel())
	{
	case 0:
		msg = ECDSA_Example_1_Message;
		sig = ECDSA_Example_1_Signature;
		pk = ECDSA_Example_1_PublicKey;
		break;

	case 1:
		msg = ECDSA_Example_2_Message;
		sig = ECDSA_Example_2_Signature;
		pk = ECDSA_Example_2_PublicKey;
		break;

	default:
		AfxMessageBox(L"Error #DBS-02: Selected ECDSA Example Data Not Found");
		return;

		break;
	}


	m_bIsTasksRunning = true;
	((CButton*)GetDlgItem(IDC_BUTTON_RUN_SHA))->EnableWindow(FALSE);
	((CButton*)GetDlgItem(IDC_BUTTON_RUN_ECDSA))->EnableWindow(FALSE);




	/*
	*  Start of Calibration Process
	*/
	
	double	timeExecutionOneRound_ms{ }; // ms

	SetDlgItemTextW(IDC_EDIT_STATUS, L"Calibrating Processing Parameters for the Execution.....");


	long executionrounds{ 1L };

	for (; executionrounds <= 100'000L; executionrounds *= 10L)
	{
		auto tStart = std::chrono::high_resolution_clock::now();

		for (size_t index = 0LL; index < executionrounds; index++)
		{
			if (p256_verify((uint8_t*)msg, ECDSA_EXAMPLE_MESSAGE_LENGTH, (uint8_t*)sig, (uint8_t*)pk) != P256_SUCCESS)
			{
				AfxMessageBox(L"Error #DBS-03: ECDSA Signature Verification Failed, It is not Matching");

				m_bIsTasksRunning = false;

				((CButton*)GetDlgItem(IDC_BUTTON_RUN_SHA))->EnableWindow(TRUE);
				((CButton*)GetDlgItem(IDC_BUTTON_RUN_ECDSA))->EnableWindow(TRUE);

				return;
			}
		}

		auto tEnd = std::chrono::high_resolution_clock::now();

		const std::chrono::duration<double, std::milli> passed = tEnd - tStart;
		timeExecutionOneRound_ms = passed.count();

		if (timeExecutionOneRound_ms > (25.0 * MIN_timeExecutionOneRound_ms))  // 25.0 is just a common sense, we want the calibration process runs long enough
			break;
	}

	if (timeExecutionOneRound_ms < MIN_timeExecutionOneRound_ms) //ms
	{
		cmsg = L"Error #DBS-04: Processing Calibration is Failed Because Processor Over-performed";
		AfxMessageBox(cmsg);
		SetDlgItemTextW(IDC_EDIT_STATUS, cmsg);

		m_bIsTasksRunning = false;
		((CButton*)GetDlgItem(IDC_BUTTON_RUN_SHA))->EnableWindow(TRUE);
		((CButton*)GetDlgItem(IDC_BUTTON_RUN_ECDSA))->EnableWindow(TRUE);

		return;
	}


	timeExecutionOneRound_ms /= (double)executionrounds;	// ms

	operationsCountTotal = (size_t)((((double)executionTime) * 1000.0) / timeExecutionOneRound_ms);  // convert ms to s
	
	/*
	*  End of Calibration Process
	*/





	SetDlgItemTextW(IDC_EDIT_STATUS, L"Running Single Thread for Message Signature Verification Based on ECDSA P-256.....");


	auto tStart = std::chrono::high_resolution_clock::now();


	for (size_t index = 0LL; index < operationsCountTotal; index++)
		p256_verify((uint8_t*)msg, ECDSA_EXAMPLE_MESSAGE_LENGTH, (uint8_t*)sig, (uint8_t*)pk);


	auto tEnd = std::chrono::high_resolution_clock::now();


	const std::chrono::duration<double, std::milli> passed = tEnd - tStart;
	size_t timeElapsedProcessingTotal_ms{ (size_t)passed.count() };

	if (timeElapsedProcessingTotal_ms < 1LL)
		timeElapsedProcessingTotal_ms = 1LL;



	messageLengthTotal = (size_t)(ECDSA_EXAMPLE_MESSAGE_LENGTH) * operationsCountTotal;
	Throughput = (messageLengthTotal / timeElapsedProcessingTotal_ms) * 1000LL; // convert ms to s
	APDUperSec = Throughput / APDU_SIZE;



	ss << "ECDSA P-256 Signature Verification is Done Successfully by Running Single Thread";
	ss << ", Measured Throughput:  " << format_number_3digits_n_suffix(Throughput) << "B/s";
	cmsg = ss.str().data();
	SetDlgItemTextW(IDC_EDIT_STATUS, cmsg);

	cmsg = format_number_as_Time_Duration(timeElapsedProcessingTotal_ms).data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_TIME, cmsg);

	
	cmsg = (format_number_3digits_n_suffix(messageLengthTotal, 1024LL) + "B").data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_DATA_SIZE, cmsg);

	cmsg = format_number_3digits_n_suffix(operationsCountTotal).data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_OPER_COUNT, cmsg);

	cmsg = (format_number_comma_seperated(APDUperSec)).data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_APDUPERS, cmsg);



	m_bIsTasksRunning = false;
	((CButton*)GetDlgItem(IDC_BUTTON_RUN_SHA))->EnableWindow(TRUE);
	((CButton*)GetDlgItem(IDC_BUTTON_RUN_ECDSA))->EnableWindow(TRUE);
}




/**********************************************************************************************************************************/
/*                                                         Run SHA - 256                                                          */
/**********************************************************************************************************************************/


void CDialogPage_Bench_ECC_SHA::calibrate_and_runSHA256_benchmark(const long executionTime)
{
	SHA256				sha256Obj;
	BYTE				bufOutputHash[sha256Obj.get_hash_size_bytes()];
	CString				cmsg;
	std::string			msgInputforHash;
	std::stringstream	ss;
	size_t				msgLength, messageLengthTotal{}, Throughput{}, operationsCountTotal{}, APDUperSec{};
	const double		MIN_timeExecutionOneRound_ms = 10.0;	// setting some minimums by my common-sense
	BYTE* pMsg;


	m_bIsTasksRunning = true;
	((CButton*)GetDlgItem(IDC_BUTTON_RUN_SHA))->EnableWindow(FALSE);
	((CButton*)GetDlgItem(IDC_BUTTON_RUN_ECDSA))->EnableWindow(FALSE);



	if (0 != ((CButton*)GetDlgItem(IDC_RADIO_MSG_RANDOM))->GetCheck()) // use randomly generated message
	{
		pMsg = (BYTE*)m_message_random_128B;
		msgLength = m_random_message_size;
	}
	else // use user input message
	{
		GetDlgItemTextW(IDC_EDIT_INPUT_MSG_SHA256, cmsg);
		msgInputforHash = CW2A(cmsg);

		pMsg = (BYTE*)msgInputforHash.data();
		msgLength = msgInputforHash.size();
	}



	/*
	*  Start of Calibration Process
	*/

	double	timeExecutionOneRound_ms{ }; // ms

	SetDlgItemTextW(IDC_EDIT_STATUS, L"Calibrating Processing Parameters for the Execution.....");


	long executionrounds{ 1L };

	for (; executionrounds <= 100'000'000L; executionrounds *= 10L)
	{
		auto tStart = std::chrono::high_resolution_clock::now();

		for (size_t index = 0LL; index < executionrounds; index++)
		{
			sha256Obj.get_input(pMsg, msgLength);
			sha256Obj.calculate_hash(bufOutputHash);
		}

		auto tEnd = std::chrono::high_resolution_clock::now();

		const std::chrono::duration<double, std::milli> passed = tEnd - tStart;
		timeExecutionOneRound_ms = passed.count();

		if (timeExecutionOneRound_ms > (25.0 * MIN_timeExecutionOneRound_ms))  // 25.0 is just a common sense, we want the calibration process runs long enough
			break;
	}

	if (timeExecutionOneRound_ms < MIN_timeExecutionOneRound_ms) //ms
	{
		cmsg = L"Error #DBS-05: Processing Calibration is Failed Because Processor Over-performed";
		AfxMessageBox(cmsg);
		SetDlgItemTextW(IDC_EDIT_STATUS, cmsg);

		m_bIsTasksRunning = false;
		((CButton*)GetDlgItem(IDC_BUTTON_RUN_SHA))->EnableWindow(TRUE);
		((CButton*)GetDlgItem(IDC_BUTTON_RUN_ECDSA))->EnableWindow(TRUE);

		return;
	}


	timeExecutionOneRound_ms /= (double)executionrounds;	// ms

	operationsCountTotal = (size_t)((((double)executionTime) * 1000.0) / timeExecutionOneRound_ms);  // convert ms to s

	/*
	*  End of Calibration Process
	*/





	SetDlgItemTextW(IDC_EDIT_STATUS, L"Running Single Thread for Hashing Proccess Based on SHA - 256.....");


	auto tStart = std::chrono::high_resolution_clock::now();

	for (size_t index = 0LL; index < operationsCountTotal; index++)
	{
		sha256Obj.get_input(pMsg, msgLength);
		sha256Obj.calculate_hash(bufOutputHash);
	}

	auto tEnd = std::chrono::high_resolution_clock::now();


	const std::chrono::duration<double, std::milli> passed = tEnd - tStart;
	size_t timeElapsedProcessingTotal_ms{ (size_t)passed.count() };

	if (timeElapsedProcessingTotal_ms < 1LL)
		timeElapsedProcessingTotal_ms = 1LL;


	char msgOnScreen[sha256Obj.get_hash_size_bytes() * 4];  // each byte occupies 2 digits + 1 white space, also between every 8 bytes we have 3 white spaces
	format_binary_buffer_as_hex_string(bufOutputHash, sha256Obj.get_hash_size_bytes(), msgOnScreen);
	cmsg = &(msgOnScreen[3]);
	SetDlgItemTextW(IDC_EDIT_OUTPUT_SHA256, cmsg);




	messageLengthTotal = msgLength * operationsCountTotal;
	Throughput = (messageLengthTotal / timeElapsedProcessingTotal_ms) * 1000LL; // convert ms to s
	APDUperSec = Throughput / APDU_SIZE;



	ss << "SHA - 256  Operations is Done Successfully by Running Single Thread";
	ss << ", Measured Throughput:  " << format_number_3digits_n_suffix(Throughput) << "B/s";
	cmsg = ss.str().data();
	SetDlgItemTextW(IDC_EDIT_STATUS, cmsg);

	cmsg = format_number_as_Time_Duration(timeElapsedProcessingTotal_ms).data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_TIME, cmsg);


	cmsg = (format_number_3digits_n_suffix(messageLengthTotal, 1024LL) + "B").data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_DATA_SIZE, cmsg);

	cmsg = format_number_3digits_n_suffix(operationsCountTotal).data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_OPER_COUNT, cmsg);

	cmsg = (format_number_comma_seperated(APDUperSec)).data();
	SetDlgItemTextW(IDC_EDIT_PERFORMANCE_APDUPERS, cmsg);



	m_bIsTasksRunning = false;
	((CButton*)GetDlgItem(IDC_BUTTON_RUN_SHA))->EnableWindow(TRUE);
	((CButton*)GetDlgItem(IDC_BUTTON_RUN_ECDSA))->EnableWindow(TRUE);
}
