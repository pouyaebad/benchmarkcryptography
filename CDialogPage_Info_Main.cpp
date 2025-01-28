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

// CDialogPage_Info_Main.cpp : implementation file
//

#include "pch.h"
#include "EncryptionBenchmark.h"
#include "afxdialogex.h"
#include "CDialogPage_Info_Main.h"

// CDialogPage_Info_Main dialog

IMPLEMENT_DYNAMIC(CDialogPage_Info_Main, CMFCPropertyPage)

CDialogPage_Info_Main::CDialogPage_Info_Main(CWnd* pParent /*=nullptr*/)
	: CMFCPropertyPage(IDD_PROPPAGE_INFO_MAIN)
{
	m_psp.dwFlags &= ~PSP_HASHELP;
	m_psp.dwFlags |= PSH_NOAPPLYNOW;
}

CDialogPage_Info_Main::~CDialogPage_Info_Main()
{
}

void CDialogPage_Info_Main::DoDataExchange(CDataExchange* pDX)
{
	CMFCPropertyPage::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_ENCYPT_ALG_TITLES, m_list_Encrypt_Alg_Titles);
	DDX_Control(pDX, IDC_LIST_PLATFORMS, m_list_Platforms);
}


BEGIN_MESSAGE_MAP(CDialogPage_Info_Main, CMFCPropertyPage)
END_MESSAGE_MAP()


// CDialogPage_Info_Main message handlers


BOOL CDialogPage_Info_Main::OnSetActive()
{
	// TODO: Add your specialized code here and/or call the base class
	CMFCPropertySheet* psheet = (CMFCPropertySheet*)GetParent();
	psheet->GetDlgItem(IDCANCEL)->ShowWindow(SW_HIDE);

	return CMFCPropertyPage::OnSetActive();
}


BOOL CDialogPage_Info_Main::OnInitDialog()
{
	CMFCPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here
	CString sTitle;
	int index, columnsCount;


	std::vector<std::pair<std::string, int>> colEncryAlgTitles{ { "Encryption", 80}, { "Size", 60}, { "Type", 90},  { "DLMS / COSEM", 110},  { "Curve", 85} };
	for (index = 0; index < colEncryAlgTitles.size(); index++)
	{
		sTitle = colEncryAlgTitles[index].first.data();
		m_list_Encrypt_Alg_Titles.InsertColumn(index, sTitle);
		m_list_Encrypt_Alg_Titles.SetColumnWidth(index, colEncryAlgTitles[index].second);
	}


	std::vector<std::pair<std::string, int>> colPlatforms{ { "Unit", 60}, { "Library", 120}, { "Threads", 80},  { "Algorithms", 120} };
	for (index = 0; index < colPlatforms.size(); index++)
	{
		sTitle = colPlatforms[index].first.data();
		m_list_Platforms.InsertColumn(index, sTitle);
		m_list_Platforms.SetColumnWidth(index, colPlatforms[index].second);
	}




	std::vector<std::string> encryption_alg_titles{ "AES - GCM", "128 bit", "Symmetric",  "suite 0", "",
													"AES - GCM", "192 bit", "Symmetric",  "-",       "",
													"AES - GCM", "256 bit", "Symmetric",  "suite 2", "",
													"SHA",       "256 bit", "Hashing",    "suite 1", "",
													"ECDSA",     "256 bit", "Asymmetric", "suite 1", "secp256r1" };

	index = 0;
	columnsCount = (int)colEncryAlgTitles.size();
	for (auto e : encryption_alg_titles)
	{
		sTitle = encryption_alg_titles[index].data();

		if (0 == index % columnsCount)
			m_list_Encrypt_Alg_Titles.InsertItem(index / columnsCount, sTitle);
		else
			m_list_Encrypt_Alg_Titles.SetItemText(index / columnsCount, index % columnsCount, sTitle);

		++index;
	}

	
	std::vector<std::string> platform_titles{	"CPU", "-", "1",  "AES, ECC, SHA",
												"CPU", "Intel oneAPI IPP", "N",  "AES",
												"GPU", "CUDA", "N",  "AES" };

	index = 0;
	columnsCount = (int)colPlatforms.size();
	for (auto e : platform_titles)
	{
		sTitle = platform_titles[index].data();

		if (0 == index % columnsCount)
			m_list_Platforms.InsertItem(index / columnsCount, sTitle);
		else
			m_list_Platforms.SetItemText(index / columnsCount, index % columnsCount, sTitle);

		++index;
	}
	
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}
