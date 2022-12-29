//****************************************************************************
//
// Copyright (c) ALTAP, spol. s r.o. All rights reserved.
//
// This is a part of the Altap Salamander SDK library.
//
// The SDK is provided "AS IS" and without warranty of any kind and 
// ALTAP EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS AND IMPLIED, INCLUDING,
// BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE and NON-INFRINGEMENT.
//
//****************************************************************************

#include "precomp.h"
#include <windowsx.h>

#define GET_X_LPARAM(lp) ((int)(short)LOWORD(lp))
#define GET_Y_LPARAM(lp) ((int)(short)HIWORD(lp))

//****************************************************************************
//
// CCommonDialog
//

CCommonDialog::CCommonDialog(HINSTANCE hInstance, int resID, HWND hParent, CObjectOrigin origin) :
	CDialog(hInstance, resID, hParent, origin)
{
}

CCommonDialog::CCommonDialog(HINSTANCE hInstance, int resID, int helpID, HWND hParent, CObjectOrigin origin) :
	CDialog(hInstance, resID, helpID, hParent, origin)
{
}

INT_PTR CCommonDialog::DialogProc(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			// horizontal and vertical dialog centering on top of the parent window
			if (Parent != NULL)
				SalamanderGeneral->MultiMonCenterWindow(HWindow, Parent, TRUE);
			break;
		}
	}
	return CDialog::DialogProc(uMsg, wParam, lParam);
}

void CCommonDialog::NotifDlgJustCreated()
{
  SalamanderGUI->ArrangeHorizontalLines(HWindow);
}


//
// ****************************************************************************
// CPasswordDialog
//

BOOL CPasswordDialog::m_hide = TRUE;

CPasswordDialog::CPasswordDialog(HWND parent, char *buffer, int bufsize) :
	CCommonDialog(HLanguage, IDD_PWDDLG, IDD_PWDDLG, parent),
	m_buffer{buffer}, m_bufsize{bufsize}
{
}

void CPasswordDialog::Transfer(CTransferInfo &ti)
{
  ti.EditLine(IDC_PWDSTRING, m_buffer, m_bufsize);
}

INT_PTR CPasswordDialog::DialogProc(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	CALL_STACK_MESSAGE4("CPasswordDialog::DialogProc(0x%X, 0x%IX, 0x%IX)", uMsg, wParam, lParam);
	switch (uMsg)
	{
	case WM_INITDIALOG:
		HidePassword(m_hide);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_HIDE_PWD:
			m_hide = !m_hide;
			HidePassword(m_hide);
			break;

		case IDC_PWDSTRING:
			if (HIWORD(wParam) == EN_CHANGE)
			{
				// disable OK button if password edit-box is empty
				const auto len = Edit_GetTextLength(GetDlgItem(HWindow, IDC_PWDSTRING));
				Button_Enable(GetDlgItem(HWindow, IDOK), len != 0);
			}
			break;
		}
		break;
	}
	return CCommonDialog::DialogProc(uMsg, wParam, lParam);
}

void CPasswordDialog::HidePassword(BOOL hide)
{
	Button_SetCheck(GetDlgItem(HWindow, IDC_HIDE_PWD), hide);
	HWND HEditBox = GetDlgItem(HWindow, IDC_PWDSTRING);
	Edit_SetPasswordChar(HEditBox, hide ? '*' : 0);
	// edit-box needs explicit redraw
	RedrawWindow(HEditBox, NULL, NULL, RDW_INVALIDATE);
}
