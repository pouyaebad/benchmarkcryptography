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
#include "afxdialogex.h"

#include <random>

// CDialogPage_Bench_ECC_SHA dialog

class CDialogPage_Bench_ECC_SHA : public CMFCPropertyPage
{
	DECLARE_DYNAMIC(CDialogPage_Bench_ECC_SHA)

public:
	CDialogPage_Bench_ECC_SHA(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CDialogPage_Bench_ECC_SHA();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PROPPAGE_BENCH_ECC };
#endif

protected:
	static constexpr size_t m_random_message_size = 128LL;

	unsigned char m_message_random_128B[m_random_message_size]{ };
	std::uniform_int_distribution<>  m_RNG_dist{ 0x00, 0xFF };// random numbers between 0 to 255 
	std::shuffle_order_engine<std::mt19937, 31> m_RNG_engine{ };

	bool m_bIsTasksRunning{ false };



	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	CString fomattedHexBufferOnScreen(const unsigned char *msg, const int len) const;

	void RetriveRunningParamsFromUI(long& executionTime);
	void calibrate_and_runSHA256_benchmark(const long executionTime);
	void calibrate_and_runECDSA_benchmark(const long executionTime);



	DECLARE_MESSAGE_MAP()

public:
	CComboBox m_combo_SamplesList;

	virtual BOOL OnSetActive();
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedButtonRunSha();
	afx_msg void OnBnClickedButtonRunEcdsa();
	afx_msg void OnBnClickedButtonClearResults();
	afx_msg void OnSelchangeComboSampleEcdsa();
	afx_msg void OnRadioMsgRandom();
	afx_msg void OnRadioMsgManual();
};

