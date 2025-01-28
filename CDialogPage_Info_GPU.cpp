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

// CDialogPage_Info_GPU.cpp : implementation file
//

#include "pch.h"
#include "EncryptionBenchmark.h"
#include "afxdialogex.h"
#include "CDialogPage_Info_GPU.h"

#include "cuda_main.cuh"


// CDialogPage_Info_GPU dialog

IMPLEMENT_DYNAMIC(CDialogPage_Info_GPU, CMFCPropertyPage)

CDialogPage_Info_GPU::CDialogPage_Info_GPU(CWnd* pParent /*=nullptr*/)
	: CMFCPropertyPage(IDD_PROPPAGE_INFO_GPU)
{
	m_psp.dwFlags &= ~PSP_HASHELP;
	m_psp.dwFlags |= PSH_NOAPPLYNOW;
}

CDialogPage_Info_GPU::~CDialogPage_Info_GPU()
{
}

void CDialogPage_Info_GPU::DoDataExchange(CDataExchange* pDX)
{
	CMFCPropertyPage::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_GPU_MT_PARAMS, m_list_GPU_Params);
	DDX_Control(pDX, IDC_COMBO_GPU_LST, m_ComboBox_GPU_Lst);
}


BEGIN_MESSAGE_MAP(CDialogPage_Info_GPU, CMFCPropertyPage)
	ON_CBN_SELCHANGE(IDC_COMBO_GPU_LST, &CDialogPage_Info_GPU::OnSelchangeComboGPULst)
END_MESSAGE_MAP()


// CDialogPage_Info_GPU message handlers


BOOL CDialogPage_Info_GPU::OnSetActive()
{
	// TODO: Add your specialized code here and/or call the base class
	CMFCPropertySheet* psheet = (CMFCPropertySheet*)GetParent();
	psheet->GetDlgItem(IDCANCEL)->ShowWindow(SW_HIDE);

	return CMFCPropertyPage::OnSetActive();
}



BOOL CDialogPage_Info_GPU::OnInitDialog()
{
	CMFCPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here
	CString sTitle;

	m_list_GPU_Params.InsertColumn(0, L"Parameter");
	m_list_GPU_Params.SetColumnWidth(0, 210);
	m_list_GPU_Params.InsertColumn(1, L"Value(s)");
	m_list_GPU_Params.SetColumnWidth(1, 170);


	CUDA_Features cudaFeatures;
	int GPU_Count{ cudaFeatures.CUDA_Get_Total_GPUs_Count() };

	if (GPU_Count < 1)
		m_ComboBox_GPU_Lst.AddString(L" No nvidia Compatible GPUs Found");
	else
		for (int i = 0; i < GPU_Count; i++)
		{
			sTitle.Format(L"GPU #%d", i + 1);

			m_ComboBox_GPU_Lst.AddString(sTitle);
		}

	m_ComboBox_GPU_Lst.SetCurSel(0);

	InitializeScreenControls();

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}


void CDialogPage_Info_GPU::OnSelchangeComboGPULst()
{
	// TODO: Add your control notification handler code here
	InitializeScreenControls();
}


void CDialogPage_Info_GPU::InitializeScreenControls()
{
	CString sTitle;
	std::vector<int> edit_box_ids{ IDC_EDIT_G1, IDC_EDIT_G2, IDC_EDIT_G3, IDC_EDIT_G4, IDC_EDIT_G5 };


	// Deleting all texts from the screen
	m_list_GPU_Params.DeleteAllItems();
	for (auto e: edit_box_ids)
		SetDlgItemTextW(e, L"");




	CUDA_Features cudaFeatures;
	int GPU_Count{ cudaFeatures.CUDA_Get_Total_GPUs_Count() };

	if ((GPU_Count < 1) || (m_ComboBox_GPU_Lst.GetCurSel() > GPU_Count - 1))
		return;



	std::vector<std::string> CUDA_Params{ cudaFeatures.CUDA_Get_GPU_Information(m_ComboBox_GPU_Lst.GetCurSel()) };


	if (CUDA_Params.size() >= edit_box_ids.size())
		for (int i = 0; i < edit_box_ids.size(); i++)
		{
			sTitle = CUDA_Params[i].data();
			SetDlgItemTextW(edit_box_ids[i], sTitle);
		}


	std::vector < std::string> listTitles{ "Reg per Multiprocessor", "Reg per Block", "Max Grid Size", "Max Blocks per MultiProcessor",
										   "Max Threads per Block", "Max Threads Dim", "Max Threads per MultiProcessor" };


	int index = 0;
	if (CUDA_Params.size() >= listTitles.size() + edit_box_ids.size())
		for (auto e : listTitles)
		{
			sTitle = e.data();
			m_list_GPU_Params.InsertItem(index, sTitle);

			sTitle = CUDA_Params[edit_box_ids.size() + index].data();
			m_list_GPU_Params.SetItemText(index, 1, sTitle);

			++index;
		}
}