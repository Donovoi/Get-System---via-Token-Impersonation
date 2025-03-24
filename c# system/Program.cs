using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace SystemPrivCheck
{
    class Program
    {
        // Constants
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        const uint ERROR_NO_TOKEN = 1008;
        const uint ERROR_PRIVILEGE_NOT_HELD = 1314;
        const string SYSTEM_SID = "S-1-5-18";
        const int MAX_PATH = 260;

        // Token access rights
        const uint TOKEN_QUERY = 0x0008;
        const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        const uint TOKEN_DUPLICATE = 0x0002;
        const uint TOKEN_IMPERSONATE = 0x0004;
        const uint TOKEN_ALL_ACCESS = 0xF01FF;

        // Process access rights
        const uint PROCESS_QUERY_INFORMATION = 0x0400;

        // Creation flags for new process
        const uint CREATE_NEW_CONSOLE = 0x00000010;

        // For CreateProcessWithTokenW
        const uint LOGON_WITH_PROFILE = 0x00000001;

        // Structures

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            public string szExeFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_ELEVATION
        {
            public int TokenIsElevated;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        // Enums for DuplicateTokenEx
        enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        // P/Invoke declarations

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
            IntPtr lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetThreadToken(IntPtr Thread, IntPtr Token);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName,
            string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out string strSid);

        // Helper: Get process ID by name using Toolhelp32Snapshot
        static uint GetProcessIdByName(string processName)
        {
            uint pid = 0;
            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == IntPtr.Zero)
                return 0;

            PROCESSENTRY32 entry = new PROCESSENTRY32();
            entry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
            if (Process32First(snapshot, ref entry))
            {
                do
                {
                    // Compare names ignoring case.
                    if (string.Equals(entry.szExeFile, processName, StringComparison.OrdinalIgnoreCase))
                    {
                        pid = entry.th32ProcessID;
                        break;
                    }
                }
                while (Process32Next(snapshot, ref entry));
            }
            CloseHandle(snapshot);
            return pid;
        }

        // Check if current thread or process token is running as SYSTEM
        static bool IsCurrentProcessSystem()
        {
            IntPtr hToken = IntPtr.Zero;
            bool isSystem = false;

            // Try thread token first (impersonation)
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, out hToken))
            {
                int err = Marshal.GetLastWin32Error();
                if (err != ERROR_NO_TOKEN)
                    Console.WriteLine($"[!] Failed to open thread token: {err}");

                // Fallback to process token
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out hToken))
                {
                    Console.WriteLine($"[!] Failed to open process token: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                Console.WriteLine("[*] Checking process token for SYSTEM privileges...");
            }
            else
            {
                Console.WriteLine("[*] Checking thread token for SYSTEM privileges...");
            }

            // Retrieve token user information
            int tokenInfoLength = 0;
            GetTokenInformation(hToken, 1 /* TokenUser */, IntPtr.Zero, 0, out tokenInfoLength);
            IntPtr tokenInfo = Marshal.AllocHGlobal(tokenInfoLength);
            if (!GetTokenInformation(hToken, 1 /* TokenUser */, tokenInfo, tokenInfoLength, out tokenInfoLength))
            {
                Marshal.FreeHGlobal(tokenInfo);
                CloseHandle(hToken);
                return false;
            }

            TOKEN_USER tokenUser = Marshal.PtrToStructure<TOKEN_USER>(tokenInfo);
            string strSid;
            if (ConvertSidToStringSid(tokenUser.User.Sid, out strSid))
            {
                Console.WriteLine($"[*] Token SID: {strSid}");
                isSystem = (strSid == SYSTEM_SID);
            }
            Marshal.FreeHGlobal(tokenInfo);
            CloseHandle(hToken);
            return isSystem;
        }

        // Enable SeDebugPrivilege
        static bool EnableDebugPrivilege()
        {
            IntPtr hToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            {
                Console.WriteLine($"[!] OpenProcessToken error: {Marshal.GetLastWin32Error()}");
                return false;
            }

            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out LUID luid))
            {
                Console.WriteLine($"[!] LookupPrivilegeValue error: {Marshal.GetLastWin32Error()}");
                CloseHandle(hToken);
                return false;
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = 0x00000002 // SE_PRIVILEGE_ENABLED
            };

            if (!AdjustTokenPrivileges(hToken, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero))
            {
                Console.WriteLine($"[!] AdjustTokenPrivileges error: {Marshal.GetLastWin32Error()}");
                CloseHandle(hToken);
                return false;
            }

            // Check for errors even if AdjustTokenPrivileges returns true
            int err = Marshal.GetLastWin32Error();
            if (err != 0)
            {
                Console.WriteLine($"[!] AdjustTokenPrivileges error: {err}");
                CloseHandle(hToken);
                return false;
            }

            CloseHandle(hToken);
            return true;
        }

        // Impersonate SYSTEM using a token from a SYSTEM process (winlogon.exe or lsass.exe)
        static bool ImpersonateSystem()
        {
            if (!EnableDebugPrivilege())
            {
                Console.WriteLine("[!] Failed to enable debug privilege.");
                return false;
            }

            // Get a SYSTEM process by name
            uint pid = GetProcessIdByName("winlogon.exe");
            if (pid == 0)
            {
                pid = GetProcessIdByName("lsass.exe");
                if (pid == 0)
                {
                    Console.WriteLine("[!] Failed to find a suitable SYSTEM process");
                    return false;
                }
            }

            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[!] Failed to open SYSTEM process (pid: {pid}): {Marshal.GetLastWin32Error()}");
                return false;
            }

            IntPtr hToken;
            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, out hToken))
            {
                Console.WriteLine($"[!] Failed to open process token: {Marshal.GetLastWin32Error()}");
                CloseHandle(hProcess);
                return false;
            }

            // Duplicate the token for impersonation
            IntPtr hDupToken;
            if (!DuplicateTokenEx(hToken, TOKEN_IMPERSONATE | TOKEN_QUERY, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenImpersonation, out hDupToken))
            {
                Console.WriteLine($"[!] Failed to duplicate token: {Marshal.GetLastWin32Error()}");
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return false;
            }

            // Set the thread token to the duplicated token
            if (!SetThreadToken(IntPtr.Zero, hDupToken))
            {
                Console.WriteLine($"[!] Failed to set thread token: {Marshal.GetLastWin32Error()}");
                CloseHandle(hDupToken);
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return false;
            }

            // Display token type and impersonation level (for diagnostic purposes)
            Console.WriteLine("[*] Token information after impersonation:");
            // (Additional token info could be retrieved with GetTokenInformation if needed)

            // Clean up local handles (the thread now holds hDupToken)
            CloseHandle(hDupToken);
            CloseHandle(hToken);
            CloseHandle(hProcess);

            return true;
        }

        // Check if the current process is running elevated (Administrator)
        static bool IsRunningAsAdmin()
        {
            IntPtr hToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out hToken))
            {
                Console.WriteLine($"[!] Failed to open process token: {Marshal.GetLastWin32Error()}");
                return false;
            }

            TOKEN_ELEVATION elevation;
            int size = Marshal.SizeOf(typeof(TOKEN_ELEVATION));
            IntPtr elevationPtr = Marshal.AllocHGlobal(size);
            bool success = GetTokenInformation(hToken, 20 /* TokenElevation */, elevationPtr, size, out int retSize);
            if (!success)
            {
                Console.WriteLine($"[!] GetTokenInformation error: {Marshal.GetLastWin32Error()}");
                Marshal.FreeHGlobal(elevationPtr);
                CloseHandle(hToken);
                return false;
            }
            elevation = Marshal.PtrToStructure<TOKEN_ELEVATION>(elevationPtr);
            Marshal.FreeHGlobal(elevationPtr);
            CloseHandle(hToken);
            return (elevation.TokenIsElevated != 0);
        }

        // Launch a command prompt with the SYSTEM token
        static bool LaunchSystemCommandPrompt()
        {
            uint pid = GetProcessIdByName("winlogon.exe");
            if (pid == 0)
            {
                pid = GetProcessIdByName("lsass.exe");
                if (pid == 0)
                {
                    Console.WriteLine("[!] Failed to find a suitable SYSTEM process");
                    return false;
                }
            }

            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine($"[!] Failed to open SYSTEM process (pid: {pid}): {Marshal.GetLastWin32Error()}");
                return false;
            }

            IntPtr hToken;
            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, out hToken))
            {
                Console.WriteLine($"[!] Failed to open process token: {Marshal.GetLastWin32Error()}");
                CloseHandle(hProcess);
                return false;
            }

            // Duplicate the token as a primary token for process creation
            IntPtr hDupToken;
            if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out hDupToken))
            {
                Console.WriteLine($"[!] Failed to duplicate token: {Marshal.GetLastWin32Error()}");
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return false;
            }

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = "Winsta0\\Default";
            si.dwFlags = 0; // You can add STARTF_USESHOWWINDOW if desired.
            string cmdLine = "cmd.exe";
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // Try CreateProcessWithTokenW
            if (!CreateProcessWithTokenW(hDupToken, 0, null, cmdLine, CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out pi))
            {
                uint err = (uint)Marshal.GetLastWin32Error();
                Console.WriteLine($"[!] Failed to create process with SYSTEM token: {err}");

                // If missing privilege, try to enable SE_ASSIGNPRIMARYTOKEN
                if (err == ERROR_PRIVILEGE_NOT_HELD)
                {
                    Console.WriteLine("[!] Missing required privilege. Trying to enable SeAssignPrimaryTokenPrivilege...");

                    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, out IntPtr hProcToken))
                    {
                        if (LookupPrivilegeValue(null, "SeAssignPrimaryTokenPrivilege", out LUID luidAssign))
                        {
                            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
                            {
                                PrivilegeCount = 1,
                                Luid = luidAssign,
                                Attributes = 0x00000002
                            };
                            AdjustTokenPrivileges(hProcToken, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
                        }
                        CloseHandle(hProcToken);
                    }

                    // Try CreateProcessWithTokenW again
                    if (CreateProcessWithTokenW(hDupToken, 0, null, cmdLine, CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out pi))
                    {
                        Console.WriteLine("[+] Successfully launched cmd.exe with SYSTEM privileges!");
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                        CloseHandle(hDupToken);
                        CloseHandle(hToken);
                        CloseHandle(hProcess);
                        return true;
                    }
                    else
                    {
                        Console.WriteLine($"[!] Alternate attempt with CreateProcessWithTokenW failed: {Marshal.GetLastWin32Error()}");
                    }

                    // Try alternate method: CreateProcessAsUserW
                    Console.WriteLine("[!] Trying alternate method with CreateProcessAsUserW...");
                    if (CreateProcessAsUserW(hDupToken, null, cmdLine, IntPtr.Zero, IntPtr.Zero, false, CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out pi))
                    {
                        Console.WriteLine("[+] Successfully launched cmd.exe with SYSTEM privileges using CreateProcessAsUserW!");
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                        CloseHandle(hDupToken);
                        CloseHandle(hToken);
                        CloseHandle(hProcess);
                        return true;
                    }
                    else
                    {
                        Console.WriteLine($"[!] Failed to create process with CreateProcessAsUserW: {Marshal.GetLastWin32Error()}");
                    }
                }

                CloseHandle(hDupToken);
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return false;
            }

            Console.WriteLine("[+] Successfully launched cmd.exe with SYSTEM privileges!");
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(hDupToken);
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return true;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("System Privilege Check Tool");
            Console.WriteLine("==========================\n");

            // Check if already running as SYSTEM
            if (IsCurrentProcessSystem())
            {
                Console.WriteLine("[+] Already running with SYSTEM privileges!");
                Console.WriteLine("[*] Launching a command prompt with SYSTEM privileges...\n");
                LaunchSystemCommandPrompt();
                return;
            }

            Console.WriteLine("[*] Current process is not running as SYSTEM");

            // Check if running as Administrator
            if (!IsRunningAsAdmin())
            {
                Console.WriteLine("[!] This application requires Administrator privileges.");
                Console.WriteLine("[!] Please restart the application as Administrator.");
                return;
            }

            Console.WriteLine("[+] Running with Administrator privileges");
            Console.WriteLine("[*] Attempting to acquire SYSTEM privileges...\n");

            // Attempt to impersonate SYSTEM
            if (ImpersonateSystem())
            {
                if (IsCurrentProcessSystem())
                {
                    Console.WriteLine("[+] Successfully acquired SYSTEM privileges through impersonation!");
                    Console.WriteLine("[*] Launching a command prompt with SYSTEM privileges...\n");
                    LaunchSystemCommandPrompt();
                    RevertToSelf();
                    return;
                }
                else
                {
                    Console.WriteLine("[!] Impersonation apparently succeeded, but not running as SYSTEM.");
                    RevertToSelf();
                }
            }
            else
            {
                Console.WriteLine("[!] Failed to acquire SYSTEM privileges.");
            }

            Console.WriteLine("[*] Press Enter to exit...");
            Console.ReadLine();
        }
    }
}
