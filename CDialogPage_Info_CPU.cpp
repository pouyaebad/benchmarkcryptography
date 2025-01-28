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

// CDialogPage_Info_CPU.cpp : implementation file
//

#include "pch.h"
#include "EncryptionBenchmark.h"
#include "afxdialogex.h"
#include "CDialogPage_Info_CPU.h"

#include "system_info.h"

#include <vector>


// CDialogPage_Info_CPU dialog

IMPLEMENT_DYNAMIC(CDialogPage_Info_CPU, CMFCPropertyPage)

CDialogPage_Info_CPU::CDialogPage_Info_CPU(CWnd* pParent /*=nullptr*/)
	: CMFCPropertyPage(IDD_PROPPAGE_INFO_CPU)
{
	m_psp.dwFlags &= ~PSP_HASHELP;
	m_psp.dwFlags |= PSH_NOAPPLYNOW;
}

CDialogPage_Info_CPU::~CDialogPage_Info_CPU()
{
}

void CDialogPage_Info_CPU::DoDataExchange(CDataExchange* pDX)
{
	CMFCPropertyPage::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_DISKS, m_list_Disks);
	DDX_Control(pDX, IDC_LIST_NICS, m_list_NICs);
}


BEGIN_MESSAGE_MAP(CDialogPage_Info_CPU, CMFCPropertyPage)
END_MESSAGE_MAP()


// CDialogPage_Info_CPU message handlers


BOOL CDialogPage_Info_CPU::OnSetActive()
{
	// TODO: Add your specialized code here and/or call the base class
	CMFCPropertySheet* psheet = (CMFCPropertySheet*)GetParent();
	psheet->GetDlgItem(IDCANCEL)->ShowWindow(SW_HIDE);

	return CMFCPropertyPage::OnSetActive();
}


BOOL CDialogPage_Info_CPU::OnInitDialog()
{
	CMFCPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here
	CString sTitle;

	std::vector<std::pair<std::string, int>> colLabelsDisk{ { "Drive", 50}, { "Size", 70}, { "Free Space", 90},  { "Device Name", 180}, { "Volume Name", 260} };
	for (int index = 0; index < colLabelsDisk.size(); index++)
	{
		sTitle = colLabelsDisk[index].first.data();
		m_list_Disks.InsertColumn(index, sTitle);
		m_list_Disks.SetColumnWidth(index, colLabelsDisk[index].second);
	}

	std::vector<std::pair<std::string, int>> colLabelsNICs{ { "IP", 100}, { "MAC", 170} };
	for (int index = 0; index < colLabelsNICs.size(); index++)
	{
		sTitle = colLabelsNICs[index].first.data();
		m_list_NICs.InsertColumn(index, sTitle);
		m_list_NICs.SetColumnWidth(index, colLabelsNICs[index].second);
	}


	System_Information system_info;
	CString            valueString;

	valueString = system_info.getMachineName().data();
	SetDlgItemTextW(IDC_EDIT1, valueString);

	valueString = system_info.getCPUName().data();
	
	SetDlgItemTextW(IDC_EDIT2, valueString);
	valueString.Format(L" %ld", system_info.getCPUCores());
	
	SetDlgItemTextW(IDC_EDIT3, valueString);
	
	valueString = system_info.getRAMSize().data();
	SetDlgItemTextW(IDC_EDIT4, valueString);



	int index = 0;
	std::vector<DiskInfoTuple> infoDisk;
	system_info.getDiskPartitionsInfo(infoDisk);

	for (auto e : infoDisk)
	{
		sTitle = std::get<0>(e).data();
		m_list_Disks.InsertItem(index, sTitle);

		sTitle = std::get<1>(e).data();
		m_list_Disks.SetItemText(index, 1, sTitle);

		sTitle = std::get<2>(e).data();
		m_list_Disks.SetItemText(index, 2, sTitle);

		sTitle = std::get<3>(e).data();
		m_list_Disks.SetItemText(index, 3, sTitle);

		sTitle = std::get<4>(e).data();
		m_list_Disks.SetItemText(index, 4, sTitle);

		++index;
	}


	index = 0;
	std::vector<NICInfoTuple> infoNIC;
	system_info.getNICInfo(infoNIC);

	for (auto e : infoNIC)
	{
		sTitle = std::get<0>(e).data();
		m_list_NICs.InsertItem(index, sTitle);

		sTitle = std::get<1>(e).data();
		m_list_NICs.SetItemText(index, 1, sTitle);

		++index;
	}


	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}
