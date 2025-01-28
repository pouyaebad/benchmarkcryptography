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

// CDialogPage_Info_IPP.cpp : implementation file
//

#include "pch.h"
#include "EncryptionBenchmark.h"
#include "afxdialogex.h"
#include "CDialogPage_Info_IPP.h"
#include "oneapi_ipp_main.h"

#include <assert.h>

// CDialogPage_Info_IPP dialog

IMPLEMENT_DYNAMIC(CDialogPage_Info_IPP, CMFCPropertyPage)

CDialogPage_Info_IPP::CDialogPage_Info_IPP(CWnd* pParent /*=nullptr*/)
	: CMFCPropertyPage(IDD_PROPPAGE_INFO_IPP)
{
	m_psp.dwFlags &= ~PSP_HASHELP;
	m_psp.dwFlags |= PSH_NOAPPLYNOW;
}

CDialogPage_Info_IPP::~CDialogPage_Info_IPP()
{
}

void CDialogPage_Info_IPP::DoDataExchange(CDataExchange* pDX)
{
	CMFCPropertyPage::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CDialogPage_Info_IPP, CMFCPropertyPage)
END_MESSAGE_MAP()


// CDialogPage_Info_IPP message handlers


BOOL CDialogPage_Info_IPP::OnSetActive()
{
	// TODO: Add your specialized code here and/or call the base class
	CMFCPropertySheet* psheet = (CMFCPropertySheet*)GetParent();
	psheet->GetDlgItem(IDCANCEL)->ShowWindow(SW_HIDE);

	return CMFCPropertyPage::OnSetActive();
}


BOOL CDialogPage_Info_IPP::OnInitDialog()
{
	CMFCPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here
	IPP_Features ippFeatures;

	std::vector<int> check_box_ids{ IDC_CHECK1, IDC_CHECK2, IDC_CHECK3, IDC_CHECK4, IDC_CHECK5, IDC_CHECK6, IDC_CHECK7, IDC_CHECK8, IDC_CHECK9,
									IDC_CHECK10, IDC_CHECK11, IDC_CHECK12, IDC_CHECK13, IDC_CHECK14, IDC_CHECK15, IDC_CHECK16, IDC_CHECK17,
									IDC_CHECK18, IDC_CHECK19, IDC_CHECK20, IDC_CHECK21, IDC_CHECK22, IDC_CHECK23, IDC_CHECK24, IDC_CHECK25,
									IDC_CHECK26, IDC_CHECK27, IDC_CHECK28, IDC_CHECK29, IDC_CHECK30, IDC_CHECK31, IDC_CHECK32, IDC_CHECK33,
									IDC_CHECK34, IDC_CHECK35, IDC_CHECK36, IDC_CHECK37, IDC_CHECK38, IDC_CHECK39, IDC_CHECK40, IDC_CHECK41,
									IDC_CHECK42, IDC_CHECK43, IDC_CHECK44, IDC_CHECK45, IDC_CHECK46	};
	
	assert(IPP_Features::IPP_Features_Count * 2 == check_box_ids.size() );





	auto [ippLibName, ippLibVersion] = ippFeatures.IPP_GetLibNameVersion();


	if (ippLibName.size() >= 1)
	{
		CString valueString;
		valueString = ippLibName.data();
		SetDlgItemTextW(IDC_EDIT_IPP_NAME, valueString);

		valueString = ippLibVersion.data();
		SetDlgItemTextW(IDC_EDIT_IPP_VERSION, valueString);


		std::bitset<IPP_Features::IPP_Features_Count> featuresCPU, featuresLib;
		
		ippFeatures.IPP_Get_Features_CPU(featuresCPU);
		ippFeatures.IPP_Get_Features_IPPLib(featuresLib);

		
		for (int index = 0; index < IPP_Features::IPP_Features_Count; index++)
		{
			if (true == featuresCPU.test(index))
				((CButton*)GetDlgItem(check_box_ids[index * 2]))->SetCheck(1);
			
			if (true == featuresLib.test(index))
				((CButton*)GetDlgItem(check_box_ids[index * 2 + 1]))->SetCheck(1);
		}
	}
	else
	{
		SetDlgItemTextW(IDC_EDIT_IPP_NAME, L" No IPP Library Found");
		SetDlgItemTextW(IDC_EDIT_IPP_VERSION, L" N/A");
	}

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}
