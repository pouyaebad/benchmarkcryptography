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

// CDialogSheet.cpp : implementation file
//

#include "pch.h"
#include "EncryptionBenchmark.h"
#include "CDialogSheet.h"


// CDialogSheet


int CALLBACK PropSheetProc(HWND hWndDlg, UINT uMsg, LPARAM lParam)
{
	switch (uMsg)
	{
	case PSCB_PRECREATE: // property sheet is being created
	{
		DLGTEMPLATE* pResource = (DLGTEMPLATE*)lParam;

		CDialogTemplate dlgTemplate(pResource);
		dlgTemplate.SetFont(L"Microsoft Sans Serif", 12);
		memmove((void*)lParam, dlgTemplate.m_hTemplate, dlgTemplate.m_dwTemplateSize);
	}
	break;
	}
	return 0;
}


IMPLEMENT_DYNAMIC(CDialogSheet, CMFCPropertySheet)

CDialogSheet::CDialogSheet()
{
	m_psh.dwFlags &= ~PSH_HASHELP;
	m_psh.dwFlags |= PSH_NOAPPLYNOW;

/*
	m_psh.pfnCallback = PropSheetProc;
	m_psh.dwFlags |= PSH_USECALLBACK;
*/
}

CDialogSheet::~CDialogSheet()
{
}


BEGIN_MESSAGE_MAP(CDialogSheet, CMFCPropertySheet)
END_MESSAGE_MAP()



// CDialogSheet message handlers


BOOL CDialogSheet::OnInitDialog()
{
	BOOL bResult = CMFCPropertySheet::OnInitDialog();

	// TODO:  Add your specialized code here
	GetDlgItem(IDCANCEL)->ShowWindow(SW_HIDE);

	SetIcon(AfxGetApp()->LoadIcon(IDI_ICON1), TRUE);
	SetTitle(L"Symmetric and Asymmetric Encryption Benchmarking on CPU & GPU (DLMS / COSEM Suite 0, 1 and 2 APDU Simulation)");


	return bResult;
}
