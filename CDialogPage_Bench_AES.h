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


enum RUNNIN_PLATFORM { CPU = 0, GPU = 1, IPP = 2 }; // these values are used as array indices so they should start from 0 and then increment


// CDialogPage_Bench_AES dialog

class CDialogPage_Bench_AES : public CMFCPropertyPage
{
	DECLARE_DYNAMIC(CDialogPage_Bench_AES)

public:
	CDialogPage_Bench_AES(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CDialogPage_Bench_AES();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PROPPAGE_BENCH_AES };
#endif

protected:
	bool m_bIsAESTasksRunning{ false };

	double m_calibration_param_timeExecutionOneRound_ms[3];    // for CPU, GPU and IPP
	size_t m_calibration_param_messageLengthOneRound_bytes[3]; // for CPU, GPU and IPP


	std::string getDefaultExtentionForAESTestDataFiles() const { return ".bin"; };


	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	bool RetriveRunningParamsFromUI(RUNNIN_PLATFORM&, std::string&, std::string&, bool& runBasedonTime, std::vector<long>&);

	void CDialogPage_Bench_AES::calibrate_and_runAES_benchmark(const RUNNIN_PLATFORM runningplatform, const std::string fileNameInput, const std::string fileNameLog, const bool runBasedonTime, const std::vector<long> runningParams);

	template<typename AES_TYPE> void runAESTasks(const long, const long, const long, const std::string&, const std::string&);


	DECLARE_MESSAGE_MAP()
public:
	CListBox m_ListTestDataFiles;

	virtual BOOL OnSetActive();
	virtual BOOL OnInitDialog();
	afx_msg void OnClickedButtonSetDefaults();
	afx_msg void OnClickedButtonClearResults();
	afx_msg void OnClickedButtonRun();
	afx_msg void OnSelchangeListTestDataFiles();
};
