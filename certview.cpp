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
#include "viewer.h"

// plugin interface instance, its methods are invoked from Salamander
CPluginInterface PluginInterface;
// plugin extension interface for CPluginInterface
CPluginInterfaceForViewer InterfaceForViewer;

// global data
const char *PluginNameEN = "CertView";          // not translated plugin name, used before loading language module + for debug stuff
const char *PluginNameShort = "CERTVIEW";       // plugin name (short form, no spaces)

BOOL CfgSavePosition = FALSE;             // save window position/fits main window
WINDOWPLACEMENT CfgWindowPlacement = {0}; // not valid, if CfgSavePosition != TRUE

DWORD LastCfgPage = 0;   // start page (sheet) in configuration dialog

const char *CONFIG_SAVEPOS = "SavePosition";
const char *CONFIG_WNDPLACEMENT = "WindowPlacement";

// ConfigVersion: 0 - no configuration read from Registry (plugin was just installed),
//                1 - the first version of configuration

int ConfigVersion = 0;            // version of read configuration from registry (version description see above)
#define CURRENT_CONFIG_VERSION 1  // current version of configuration (saved to registry upon plugin unload)
const char *CONFIG_VERSION = "Version";

HINSTANCE DLLInstance = NULL;       // handle to SPL - language independent resources
HINSTANCE HLanguage = NULL;         // handle to SLG - language dependent resources

// Salamander general interface - valid from plugin start to end
CSalamanderGeneralAbstract *SalamanderGeneral = NULL;

// debugging extensions "dbg.h"
CSalamanderDebugAbstract *SalamanderDebug = NULL;

// definition of a variable from "spl_com.h"
int SalamanderVersion = 0;

// interface for modified Windows controls, used in Salamander
CSalamanderGUIAbstract *SalamanderGUI = NULL;


// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DLLInstance = hinstDLL;

		INITCOMMONCONTROLSEX initCtrls;
		initCtrls.dwSize = sizeof(INITCOMMONCONTROLSEX);
		initCtrls.dwICC = ICC_BAR_CLASSES;
		if (!InitCommonControlsEx(&initCtrls))
		{
			MessageBox(NULL, "InitCommonControlsEx failed!", "Error", MB_OK | MB_ICONERROR);
			return FALSE;  // DLL won't start
		}
	}

	return TRUE;    // DLL can be loaded
}

// ****************************************************************************

char *LoadStr(int resID)
{
	return SalamanderGeneral->LoadStr(HLanguage, resID);
}

void OnAbout(HWND hParent)
{
	char buf[1000];
	_snprintf_s(buf, _TRUNCATE, 
				"%s " VERSINFO_VERSION "\n\n"
				VERSINFO_COPYRIGHT "\n\n"
				"%s",
				LoadStr(IDS_PLUGINNAME),
				LoadStr(IDS_PLUGIN_DESCRIPTION));
	SalamanderGeneral->SalMessageBox(hParent, buf, LoadStr(IDS_ABOUT), MB_OK | MB_ICONINFORMATION);
}

//
// ****************************************************************************
// SalamanderPluginGetReqVer
//

int WINAPI SalamanderPluginGetReqVer()
{
	return LAST_VERSION_OF_SALAMANDER;
}

//
// ****************************************************************************
// SalamanderPluginEntry
//

CPluginInterfaceAbstract * WINAPI SalamanderPluginEntry(CSalamanderPluginEntryAbstract *salamander)
{
	// setup SalamanderDebug for "dbg.h"
	SalamanderDebug = salamander->GetSalamanderDebug();
	// setup SalamanderVersion for "spl_com.h"
	SalamanderVersion = salamander->GetVersion();
	HANDLES_CAN_USE_TRACE();
	CALL_STACK_MESSAGE1("SalamanderPluginEntry()");

	// this plugin was made for current version of Salamander or higher
	if (SalamanderVersion < LAST_VERSION_OF_SALAMANDER)
	{  // refuse older version
		MessageBox(salamander->GetParentWindow(),
					REQUIRE_LAST_VERSION_OF_SALAMANDER,
					PluginNameEN, MB_OK | MB_ICONERROR);
		return NULL;
	}

	// load language module (.slg)
	HLanguage = salamander->LoadLanguageModule(salamander->GetParentWindow(), PluginNameEN);
	if (HLanguage == NULL)
		return NULL;

	// get general interface of Salamander
	SalamanderGeneral = salamander->GetSalamanderGeneral();
	// get interface with modified Windows controls used in Salamander
	SalamanderGUI = salamander->GetSalamanderGUI();

	// setup help file name
	SalamanderGeneral->SetHelpFileName("certview.chm");

	if (!InitViewer())
		return NULL;  // error

	// setup basic info about the plugin
	salamander->SetBasicPluginData(LoadStr(IDS_PLUGINNAME), FUNCTION_VIEWER,
								   VERSINFO_VERSION_NO_PLATFORM, VERSINFO_COPYRIGHT, LoadStr(IDS_PLUGIN_DESCRIPTION),
								   PluginNameShort, NULL, NULL);

	// setup plugin home-page URL
	salamander->SetPluginHomePageURL(LoadStr(IDS_PLUGIN_HOME));

	// test SetPluginBugReportInfo
	SalamanderGeneral->SetPluginBugReportInfo(LoadStr(IDS_PLUGIN_BUGREP), LoadStr(IDS_PLUGIN_EMAIL));

	return &PluginInterface;
}

//
// ****************************************************************************
// CPluginInterface
//

void WINAPI
CPluginInterface::About(HWND parent)
{
	OnAbout(parent);
}

BOOL WINAPI
CPluginInterface::Release(HWND parent, BOOL force)
{
	CALL_STACK_MESSAGE2("CPluginInterface::Release(, %d)", force);
	return TRUE;
}

void WINAPI
CPluginInterface::Connect(HWND parent, CSalamanderConnectAbstract *salamander)
{
	CALL_STACK_MESSAGE1("CPluginInterface::Connect(,)");

	// supported file extensions:
	salamander->AddViewer("*.pem;*.key;*.crl;*.csr;*.cer;*.cert;*.crt;*.der;*.pub;*.tsq;*.tsr;*.req;*.res;*.p7b;*.p7s;*.p8;*.pk8", FALSE);
}

void WINAPI
CPluginInterface::ClearHistory(HWND parent)
{
//	ViewerWindowQueue.BroadcastMessage(WM_USER_CLEARHISTORY, 0, 0);
}

void CPluginInterface::Event(int event, DWORD param)
{
}

CPluginInterfaceForViewerAbstract * WINAPI
CPluginInterface::GetInterfaceForViewer()
{
	return &InterfaceForViewer;
}
