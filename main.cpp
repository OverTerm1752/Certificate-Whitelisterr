#include <windows.h>
#include <iostream>
#include <chrono>
#include <thread>
#include "skStr.h"

#pragma warning(disable : 4996)
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"Wininet.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib,"wininet.lib")
#pragma comment(lib,"Wininet.lib")
#pragma comment(lib, "winmm.lib")
#define _WIN32_WINNT 0x0500

#include <Windows.h>
#include <winternl.h>
#include "xor.h"
#include "auth.hpp"

int anti_dump() //UD anti Dump
{
    const auto peb = (PPEB)__readgsqword(0x60);

    const auto in_load_order_module_list = (PLIST_ENTRY)peb->Ldr->Reserved2[1];
    const auto table_entry = CONTAINING_RECORD(in_load_order_module_list, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
    const auto p_size_of_image = (PULONG)&table_entry->Reserved3[1];
    *p_size_of_image = (ULONG)((INT_PTR)table_entry->DllBase + 0x100000);

    return 0;

};



std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);

using namespace KeyAuth;
using namespace std;






::string name = _xor_("a a a a aaBattleyewhitlister");  
std::string ownerid = _xor_("TRZB87oCO2"); 
std::string secret = _xor_("cfd3687617568a6c2fa729dd06e4a364adc84c775d22bc67d6413ec528e9df30"); 
std::string version = _xor_("1.1"); 
std::string url = _xor_("https://keyauth.win/api/1.2/"); 

api KeyAuthApp(name, ownerid, secret, version, url);

bool SetRegistryValue(HKEY hKeyRoot, LPCSTR subKey, LPCSTR valueName, DWORD data) {
    HKEY hKey;
    LONG result = RegOpenKeyEx(hKeyRoot, subKey, 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        result = RegSetValueEx(hKey, valueName, 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
        RegCloseKey(hKey);
        return result == ERROR_SUCCESS;
    }
    return false;
}

bool GetRegistryValue(HKEY hKeyRoot, LPCSTR subKey, LPCSTR valueName, DWORD& data) {
    HKEY hKey;
    DWORD dataSize = sizeof(data);
    LONG result = RegOpenKeyEx(hKeyRoot, subKey, 0, KEY_QUERY_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        result = RegQueryValueEx(hKey, valueName, NULL, NULL, (LPBYTE)&data, &dataSize);
        RegCloseKey(hKey);
        return result == ERROR_SUCCESS;
    }
    return false;
}

void RestartComputer() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    // Get a token for this process.
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return;
    }

    // Get the LUID for the shutdown privilege.
    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);

    tkp.PrivilegeCount = 1;  // one privilege to set
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Get the shutdown privilege for this process.
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

    if (GetLastError() != ERROR_SUCCESS) {
        return;
    }

    // Shut down the system and force all applications to close.
    ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_INSTALLATION);
}

bool SetSystemTime(int year, int month, int day, int hour, int min, int sec) {
    SYSTEMTIME st;
    st.wYear = year;
    st.wMonth = month;
    st.wDay = day;
    st.wHour = hour;
    st.wMinute = min;
    st.wSecond = sec;
    st.wMilliseconds = 0;

    // Set system time
    return SetSystemTime(&st);
}

int main() {
    SetConsoleTitleA(skCrypt("Battleye Whitelister"));
    std::cout << skCrypt("\n\n Connecting..");
    Sleep(3000);
    KeyAuthApp.init();
    if (!KeyAuthApp.data.success) {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
        Sleep(1500);
        exit(0);
    }

    if (KeyAuthApp.checkblack()) {
        abort();
    }

    std::cout << skCrypt("\n\n [1] License key\n\n Choose option: ");

    int option;
    std::string key;

    std::cin >> option;
    switch (option) {
    case 1:
        std::cout << skCrypt("\n Enter license: ");
        std::cin >> key;
        KeyAuthApp.license(key);
        break;
    default:
        std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
        Sleep(3000);
        exit(0);
    }

    if (!KeyAuthApp.data.success) {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
        Sleep(1500);
        exit(0);
    }

    const char* subKey = "SYSTEM\\CurrentControlSet\\Control\\CI";
    const char* valueName = "FlightSigning";
    DWORD newValue = 0x20;  // hex 0x20 is decimal 32
    DWORD oldValue = 0x22;  // hex 0x22 is decimal 34

   
    if (!SetRegistryValue(HKEY_LOCAL_MACHINE, subKey, valueName, newValue)) {
        MessageBox(NULL, "Failed to change value", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

   
    if (FindWindowA("R6Game", "Rainbow Six")) {
        MessageBox(NULL, "R6Game window found. Waiting 20 seconds.", "Game Found", MB_OK | MB_ICONINFORMATION);

       
        std::this_thread::sleep_for(std::chrono::seconds(20));

     
        SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)2);  
        SYSTEMTIME st;
        st.wYear = 2017;
        st.wMonth = 1;
        st.wDay = 1;
        st.wHour = 0;
        st.wMinute = 0;
        st.wSecond = 0;
        st.wMilliseconds = 0;

       
        if (!SetSystemTime(&st)) {
            std::cerr << "Error setting system time to 2017." << std::endl;
            return 1;
        }

        
        std::this_thread::sleep_for(std::chrono::seconds(10)); 

      
        if (SetRegistryValue(HKEY_LOCAL_MACHINE, subKey, valueName, oldValue)) {
            MessageBox(NULL, "Succefully Changed Value Restart your pc and start loader again", " Revert", MB_OK | MB_ICONINFORMATION);
        }
        else {
            MessageBox(NULL, "Fail Important Error", "Error", MB_OK | MB_ICONERROR);
        }

      
        MessageBox(NULL, "Please sync your time in the settings.", "Time Sync", MB_OK | MB_ICONINFORMATION);
    }
    else {
     
        DWORD value;
        if (GetRegistryValue(HKEY_LOCAL_MACHINE, subKey, valueName, value)) {
            if (value == newValue) {
                MessageBox(NULL, "Start your game!", "Success", MB_OK | MB_ICONINFORMATION);

            
                SYSTEMTIME st;
                st.wYear = 2017;
                st.wMonth = 1;
                st.wDay = 1;
                st.wHour = 0;
                st.wMinute = 0;
                st.wSecond = 0;
                st.wMilliseconds = 0;

                // Set system time to 2017
                if (!SetSystemTime(&st)) {
                    std::cerr << "Error setting system time to 2017." << std::endl;
                    return 1;
                }

              
                std::this_thread::sleep_for(std::chrono::seconds(1));

               
                int result = MessageBox(NULL, "Click OK in the main menu from Siege", "Battleye", MB_OKCANCEL | MB_ICONINFORMATION | MB_TOPMOST);

             
                if (result == IDOK) {
                   
                    for (int i = 0; i < 3; ++i) {
                        HANDLE hW32Time = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
                        if (hW32Time != NULL) {
                            BOOL bResult = SetProcessWorkingSetSize(hW32Time, (SIZE_T)-1, (SIZE_T)-1);
                            if (bResult) {
                                MessageBox(NULL, "Sync successful.", "Battleye", MB_OK | MB_ICONINFORMATION);
                            }
                            CloseHandle(hW32Time);
                        }

                      
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                    }

                   
                    if (SetRegistryValue(HKEY_LOCAL_MACHINE, subKey, valueName, oldValue)) {
                        MessageBox(NULL, "Succefully Injection", "Success", MB_OK | MB_ICONINFORMATION);
                    }
                    else {
                        MessageBox(NULL, "IMPORTANT ERROR MESSAGE OWNER", "IMPORTANT Error", MB_OK | MB_ICONERROR);
                    }
                }
            }
            else {
                if (SetRegistryValue(HKEY_LOCAL_MACHINE, subKey, valueName, newValue)) {
                    RestartComputer();
                }
                else {
                    MessageBox(NULL, "Userid Issue", "Error", MB_OK | MB_ICONERROR);
                }
            }
        }
        else {
            MessageBox(NULL, "Userid Issue", "Error", MB_OK | MB_ICONERROR);
        }
    }

    return 0;
}