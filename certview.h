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

// globalni data
extern const char *PluginNameEN; // neprekladane jmeno pluginu, pouziti pred loadem jazykoveho modulu + pro debug veci
extern HINSTANCE DLLInstance;    // handle k SPL-ku - jazykove nezavisle resourcy
extern HINSTANCE HLanguage;      // handle k SLG-cku - jazykove zavisle resourcy

// obecne rozhrani Salamandera - platne od startu az do ukonceni pluginu
extern CSalamanderGeneralAbstract *SalamanderGeneral;

// rozhrani poskytujici upravene Windows controly pouzivane v Salamanderovi
extern CSalamanderGUIAbstract *SalamanderGUI;

BOOL InitViewer();
void ReleaseViewer();

// globalni data
extern BOOL CfgSavePosition;               // ukladat pozici okna/umistit dle hlavniho okna
extern WINDOWPLACEMENT CfgWindowPlacement; // neplatne, pokud CfgSavePosition != TRUE

extern DWORD LastCfgPage;   // start page (sheet) in configuration dialog

// [0, 0] - pro otevrena okna viewru: je treba podriznou historie
#define WM_USER_CLEARHISTORY WM_APP + 3347


char *LoadStr(int resID);


class CPluginInterface:
      public CPluginInterfaceAbstract
{
  public:
    void WINAPI About(HWND parent) override;

    BOOL WINAPI Release(HWND parent, BOOL force) override;

    void WINAPI LoadConfiguration(HWND parent, HKEY regKey, CSalamanderRegistryAbstract* registry) override {}
    void WINAPI SaveConfiguration(HWND parent, HKEY regKey, CSalamanderRegistryAbstract* registry) override {}
    void WINAPI Configuration(HWND parent) override {}

    void WINAPI Connect(HWND parent, CSalamanderConnectAbstract *salamander) override;

    void WINAPI ReleasePluginDataInterface(CPluginDataInterfaceAbstract *pluginData) override {}

    CPluginInterfaceForArchiverAbstract * WINAPI GetInterfaceForArchiver() override {return NULL;}
    CPluginInterfaceForViewerAbstract * WINAPI GetInterfaceForViewer() override;
    CPluginInterfaceForMenuExtAbstract * WINAPI GetInterfaceForMenuExt() override {return NULL;}
    CPluginInterfaceForFSAbstract * WINAPI GetInterfaceForFS() override {return NULL;}
    CPluginInterfaceForThumbLoaderAbstract * WINAPI GetInterfaceForThumbLoader() override {return NULL;}

    void WINAPI Event(int event, DWORD param) override;
    void WINAPI ClearHistory(HWND parent) override;
    void WINAPI AcceptChangeOnPathNotification(const char *path, BOOL includingSubdirs) override {}

#if defined(SALSDK_COMPATIBLE_WITH_VER) && SALSDK_COMPATIBLE_WITH_VER < 177
    // pre Salamander version 4.0 backup compatibility workaround
    BOOL WINAPI UninstallUnregisteredComponents(HWND parent, char *componentsDescr, BOOL *uninstallSPL,
                                                BOOL *uninstallLangDir, const char *pluginDir,
                                                CDynamicString *deleteFileList) override {return FALSE;}
#endif

    void WINAPI PasswordManagerEvent(HWND parent, int event) override {}
};

// rozhrani pluginu poskytnute Salamanderovi
extern CPluginInterface PluginInterface;

// otevre About okno
void OnAbout(HWND hParent);
