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

#pragma once

//****************************************************************************
//
// CCommonDialog
//
// Dialog centered to the parent
//

class CCommonDialog :
    public CDialog
{
public:
    CCommonDialog(HINSTANCE hInstance, int resID, HWND hParent, CObjectOrigin origin = ooStandard);
    CCommonDialog(HINSTANCE hInstance, int resID, int helpID, HWND hParent, CObjectOrigin origin = ooStandard);
    ~CCommonDialog() override = default;

protected:
    INT_PTR DialogProc(UINT uMsg, WPARAM wParam, LPARAM lParam) override;

    void NotifDlgJustCreated() override;
};

//
// ****************************************************************************
// CPasswordDialog
//

class CPasswordDialog :
    public CCommonDialog
{
public:
    // password buffer and size
    char *m_buffer;
    const int m_bufsize;

public:
    CPasswordDialog(HWND parent, char *buffer, int bufsize);
    ~CPasswordDialog() override = default;

    void Transfer(CTransferInfo &ti) override;

protected:
    INT_PTR DialogProc(UINT uMsg, WPARAM wParam, LPARAM lParam) override;
    void HidePassword(BOOL hide);

    // show/hide password flag in edit box
    static BOOL m_hide;
};
