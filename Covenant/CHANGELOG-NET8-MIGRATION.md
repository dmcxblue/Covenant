# Covenant .NET 8 Migration Changelog

This document tracks all changes made during the migration from .NET Core 3.1 to .NET 8.0.

## Summary of Issues Fixed

### 1. ServiceUser Initialization (Covenant.cs:122-130)
**Problem:** ServiceUser was being created every time the server started, causing duplicate user errors.

**Fix:** Check if ServiceUser already exists before creating.
```csharp
// Before: Always created new ServiceUser
// After: Find existing or create if doesn't exist
CovenantUser serviceUser = userManager.FindByNameAsync("ServiceUser").GetAwaiter().GetResult();
if (serviceUser == null)
{
    serviceUser = new CovenantUser { UserName = "ServiceUser" };
    string serviceUserPassword = Utilities.CreateSecretPassword() + "A";
    userManager.CreateAsync(serviceUser, serviceUserPassword).Wait();
    userManager.AddToRoleAsync(serviceUser, "ServiceUser").Wait();
}
```

---

### 2. GruntApiController EditGrunt User Context (GruntApiController.cs:193-226)
**Problem:** `EditGrunt` endpoint failed when called by ServiceUser because it required a user context that didn't exist for service calls.

**Fix:** Handle missing user context gracefully for service user calls.
```csharp
CovenantUser currentUser = null;
try
{
    currentUser = await _service.GetCurrentUser(HttpContext.User);
}
catch (ControllerNotFoundException)
{
    // Service user calls may not have a standard user context - this is OK
    Console.WriteLine("EditGrunt: No user context (likely service user call)");
}
return await _service.EditGrunt(grunt, currentUser);
```

---

### 3. Layout.razor NullReferenceException (Layout.razor:23)
**Problem:** NullReferenceException when User or Theme were null during initial load.

**Fix:** Added null check before rendering.
```razor
@* Before: Only checked UserManager.Users.Count() *@
@* After: Also check if User and Theme are loaded *@
else if (User == null || Theme == null)
{
    <p>Loading...</p>
}
```

---

### 4. GruntHTTPStager Reflection Method Invocation (GruntHTTPStager.cs:214)
**Problem:** `Non-static method requires a target` error. The reflection code `GetTypes()[0].GetMethods()[0]` was returning inherited instance methods (like `ToString()`) instead of the static `Execute` method due to .NET 8 reflection ordering changes.

**Fix:** Use explicit type and method lookup.
```csharp
// Before (unreliable in .NET 8):
gruntAssembly.GetTypes()[0].GetMethods()[0].Invoke(null, new Object[] { ... });

// After (explicit lookup):
gruntAssembly.GetType("GruntExecutor.Grunt").GetMethod("Execute").Invoke(null, new Object[] { ... });
```

---

### 5. GruntTaskAssignForm Empty Task List (GruntTaskAssignForm.razor:92-94)
**Problem:** `Sequence contains no elements` exception when `.First()` was called on an empty task list.

**Fix:** Changed to `.FirstOrDefault()` and added null check in template.
```csharp
// Before:
this.GruntTask = this.GruntTasks.First();

// After:
this.GruntTask = this.GruntTasks.FirstOrDefault();
```

```razor
@* Added null check *@
else if (GruntTask == null)
{
    <p>No tasks available for this grunt.</p>
}
```

---

### 6. CovenantHubService Wrong SignalR Method Name (CovenantHubService.cs:858-861)
**Problem:** `GetGruntTasksForGrunt()` was calling the wrong SignalR hub method `"GetGruntTasks"` instead of `"GetGruntTasksForGrunt"`, causing no tasks to be returned when interacting with grunts.

**Fix:** Corrected the hub method name.
```csharp
// Before (WRONG):
return _connection.InvokeAsync<IEnumerable<GruntTask>>("GetGruntTasks", gruntId);

// After (CORRECT):
return _connection.InvokeAsync<IEnumerable<GruntTask>>("GetGruntTasksForGrunt", gruntId);
```

---

## Files Modified

| File | Line(s) | Issue |
|------|---------|-------|
| `Covenant.cs` | 122-130 | ServiceUser initialization |
| `Controllers/ApiControllers/GruntApiController.cs` | 193-226 | EditGrunt user context |
| `Components/Shared/Layout.razor` | 23 | Null reference check |
| `Data/Grunt/GruntHTTP/GruntHTTPStager.cs` | 214 | Reflection method lookup |
| `Components/Grunts/GruntTaskAssignForm.razor` | 14-16, 92-94 | Empty task list handling |
| `Core/CovenantHubService.cs` | 860 | SignalR method name |

---

## Testing Checklist

- [x] Server starts without errors
- [x] User can create account and login
- [x] Listener can be created and started
- [x] Launcher can be generated
- [x] Grunt stager executes and registers (Stage0 -> Stage1 -> Stage2 -> Active)
- [x] Grunt appears in UI with Active status
- [x] Tasks are available when interacting with grunt
- [ ] Task execution returns output to server
- [ ] Credentials are captured and displayed

---

## Date
December 15-16, 2025

## Migration Target
- From: .NET Core 3.1
- To: .NET 8.0

---

## Lean Implant Refactoring (December 16, 2025)

### Overview
Refactored the Grunt implant to use a minimal footprint with P/Invoke Win32 APIs instead of .NET APIs for reduced detection.

---

### 7. Added .NET Framework 4.8 Support
**Problem:** Covenant only supported Net35, Net40, and NetCore31 targets.

**Fix:** Added Net48 to `DotNetVersion` enum and updated all components:
- `Models/DotNetVersion.cs` - Added Net48 enum value
- `Core/Compiler.cs` - Added Net48 compilation support with assembly references
- `Data/AssemblyReferences/net48/` - Added .NET 4.8 framework assemblies
- All task definitions updated to include Net48 compatibility

---

### 8. P/Invoke Win32 API Implementation (GruntHTTP.cs)
**Problem:** Built-in commands used .NET APIs which are easier to detect and hook.

**Fix:** Added `Native` static class with P/Invoke declarations for Win32 APIs:

```csharp
internal static class Native
{
    // kernel32.dll
    [DllImport("kernel32.dll")] GetCurrentDirectoryW()
    [DllImport("kernel32.dll")] SetCurrentDirectoryW()
    [DllImport("kernel32.dll")] GetComputerNameW()
    [DllImport("kernel32.dll")] CreateToolhelp32Snapshot()
    [DllImport("kernel32.dll")] Process32FirstW() / Process32NextW()
    [DllImport("kernel32.dll")] CreateFileW()
    [DllImport("kernel32.dll")] ReadFile() / WriteFile()
    [DllImport("kernel32.dll")] FindFirstFileW() / FindNextFileW()
    [DllImport("kernel32.dll")] OpenProcess() / TerminateProcess()
    [DllImport("kernel32.dll")] CloseHandle()

    // advapi32.dll
    [DllImport("advapi32.dll")] GetUserNameW()
    [DllImport("advapi32.dll")] OpenProcessToken()
    [DllImport("advapi32.dll")] GetTokenInformation()
    [DllImport("advapi32.dll")] LookupAccountSidW()
}
```

**Updated Handlers to use P/Invoke:**
| Command | .NET API (Before) | Win32 API (After) |
|---------|-------------------|-------------------|
| `whoami` | `WindowsIdentity.GetCurrent()` | `GetUserNameW()`, `OpenProcessToken()`, `LookupAccountSidW()` |
| `hostname` | `Environment.MachineName` | `GetComputerNameW()` |
| `pwd` | `Directory.GetCurrentDirectory()` | `GetCurrentDirectoryW()` |
| `cd` | `Directory.SetCurrentDirectory()` | `SetCurrentDirectoryW()` |
| `ls` | `DirectoryInfo.GetFileSystemInfos()` | `FindFirstFileW()`, `FindNextFileW()` |
| `cat` | `File.ReadAllText()` | `CreateFileW()`, `ReadFile()` |
| `write` | `File.WriteAllText()` | `CreateFileW()`, `WriteFile()` |
| `ps` | `Process.GetProcesses()` | `CreateToolhelp32Snapshot()`, `Process32FirstW()` |
| `kill` | `Process.Kill()` | `OpenProcess()`, `TerminateProcess()` |

---

### 9. Added Built-in GruntTaskingTypes
**Problem:** Commands like `shell`, `powershell`, `ls`, `cat` required runtime compilation as Assembly tasks.

**Fix:** Added new `GruntTaskingType` enum values and handlers in GruntHTTP.cs:

```csharp
// New TaskingTypes added:
Shell, ShellCmd, PowerShell, WhoAmI, Pwd, Cd, ListDirectory,
ReadFile, WriteFile, GetHostname, ProcessList, Kill
```

Each type is handled directly in the implant without requiring compilation.

---

### 10. Minimal Task Definitions (DefaultGruntTasks.yaml)
**Problem:** Covenant loaded 100+ tasks from multiple YAML files, most requiring runtime compilation.

**Fix:** Created minimal `DefaultGruntTasks.yaml` with only 21 essential built-in commands:

**Core Control (9):**
- `Connect`, `Exit`, `Tasks`, `TaskKill`, `Delay`, `Jitter`, `ConnectAttempts`, `KillDate`, `Disconnect`

**Built-in P/Invoke Commands (12):**
- `shell`, `shellcmd`, `powershell`, `whoami`, `pwd`, `cd`, `ls`, `cat`, `write`, `hostname`, `ps`, `kill`

**Removed YAML files (backed up to `Data/Tasks_Backup/`):**
- `DotNetCore.yaml`
- `GhostPack.yaml`
- `SharpSC.yaml`
- `SharpSploit.Credentials.yaml`
- `SharpSploit.Enumeration.yaml`
- `SharpSploit.Evasion.yaml`
- `SharpSploit.Execution.yaml`
- `SharpSploit.LateralMovement.yaml`
- `SharpSploit.Persistence.yaml`
- `SharpSploit.PrivilegeEscalation.yaml`

---

### 11. Lowercase Command Standardization
**Problem:** Commands had inconsistent casing (e.g., `WhoAmI`, `PowerShell`).

**Fix:** All commands converted to lowercase with no aliases for consistency.

---

## Files Modified (Lean Implant)

| File | Changes |
|------|---------|
| `Data/Grunt/GruntHTTP/GruntHTTP.cs` | Added Native P/Invoke class, updated all handlers |
| `Data/Tasks/DefaultGruntTasks.yaml` | Minimal 21-command task list |
| `Models/DotNetVersion.cs` | Added Net48 enum |
| `Core/Compiler.cs` | Added Net48 compilation support |
| `Data/AssemblyReferences/net48/` | Added .NET 4.8 assemblies |
| `Data/Tasks_Backup/` | Backup of all original YAML files |

---

## Benefits of Lean Implant

1. **Reduced Detection Surface** - P/Invoke calls harder to hook than .NET APIs
2. **No Runtime Compilation** - Built-in commands execute directly
3. **Smaller Footprint** - Only essential commands loaded
4. **Consistent Interface** - All lowercase commands
5. **Future Extensibility** - Backed-up tasks can be integrated piece by piece

---

## Additional File Operations (December 16, 2025)

### 12. New Built-in File Operation Commands
**Added 6 new built-in commands with P/Invoke implementations:**

| Command | TaskingType | P/Invoke APIs | Description |
|---------|-------------|---------------|-------------|
| `mkdir` | CreateDirectory | `CreateDirectoryW` | Create directory |
| `rm` | Delete | `GetFileAttributesW`, `DeleteFileW`, `RemoveDirectoryW` | Delete file/directory |
| `cp` | Copy | `CopyFileW` | Copy file |
| `download` | Download | `CreateFileW`, `ReadFile`, `GetFileSize` | Download file from target |
| `upload` | Upload | `CreateFileW`, `WriteFile` | Upload file to target |
| `screenshot` | Screenshot | `GetDesktopWindow`, `GetDC`, `BitBlt`, `GetDIBits` | Capture desktop screenshot |

**GDI32 P/Invoke additions for screenshot:**
```csharp
[DllImport("user32.dll")] GetDesktopWindow()
[DllImport("user32.dll")] GetDC() / ReleaseDC()
[DllImport("user32.dll")] GetWindowRect()
[DllImport("gdi32.dll")] CreateCompatibleDC() / DeleteDC()
[DllImport("gdi32.dll")] CreateCompatibleBitmap()
[DllImport("gdi32.dll")] SelectObject() / DeleteObject()
[DllImport("gdi32.dll")] BitBlt()
[DllImport("gdi32.dll")] GetDIBits()
```

**Current Command Count: 27 built-in commands**

---

### 13. Screenshot Terminal Output Fix (GruntCommandCard.razor)
**Problem:** Screenshot output displayed raw base64 data in terminal, flooding the UI.

**Fix:** Updated `GruntCommandCard.razor` to show confirmation message instead of base64:
- Match both "ScreenShot" and "screenshot" task names (case-insensitive)
- Display: `Screenshot captured (X.XX MB) - View in Data tab`
- Base64 data still sent to server for Data section storage

```razor
// Before: Displayed raw base64 or tried to render inline image
// After: Shows confirmation with file size
double sizeMB = (GruntCommand.CommandOutput.Output.Length * 3.0 / 4.0) / (1024.0 * 1024.0);
<p>Screenshot captured (@sizeMB.ToString("F2") MB) - View in Data tab</p>
```

---

### 14. HttpListenerForm Index Out of Range (HttpListenerForm.razor:46)
**Problem:** `ArgumentOutOfRangeException` when creating listener because `Listener.Urls` could have fewer elements than `Listener.ConnectAddresses` (empty addresses are skipped in Urls getter).

**Fix:** Compute URL directly in the form instead of accessing `Listener.Urls[number]`:
```razor
// Before (crashed on empty addresses):
value="@Listener.Urls[number]"

// After (handles empty addresses):
string connectAddr = Listener.ConnectAddresses[number];
string url = string.IsNullOrWhiteSpace(connectAddr) ? "" :
    (Listener.UseSSL ? "https://" : "http://") + connectAddr + ":" + Listener.ConnectPort;
value="@url"
```

---

### 15. Upload/Copy Parameter Format (InternalListener.cs:245-253)
**Problem:** Upload command failed with "Invalid format. Use: path|base64content" because server joined parameters with comma but implant expected pipe separator.

**Fix:** Use pipe (`|`) separator for Upload and Copy task types:
```csharp
// Before: All non-Assembly tasks used comma
Message = string.Join(",", tasking.Parameters);

// After: Upload and Copy use pipe separator
if (tasking.Type == GruntTaskingType.Upload || tasking.Type == GruntTaskingType.Copy)
{
    Message = string.Join("|", tasking.Parameters);
}
else
{
    Message = string.Join(",", tasking.Parameters);
}
```

---

### 16. Download Task Name Case Sensitivity (GruntCommandCard.razor)
**Problem:** Download task special handling only matched "Download" but task is named "download".

**Fix:** Match both cases:
```razor
(GruntCommand.GruntTasking.GruntTask.Name == "Download" ||
 GruntCommand.GruntTasking.GruntTask.Name == "download")
```

---

## Files Modified (Additional Operations)

| File | Changes |
|------|---------|
| `Data/Grunt/GruntHTTP/GruntHTTP.cs` | Added 6 new handlers, GDI32 P/Invoke for screenshot |
| `Data/Grunt/GruntSMB/GruntSMB.cs` | Updated GruntTaskingType enum |
| `Data/Grunt/GruntBridge/GruntBridge.cs` | Updated GruntTaskingType enum |
| `Data/Grunt/Brute/Brute.cs` | Updated GruntTaskingType enum |
| `Models/Grunts/GruntTasking.cs` | Added new enum values |
| `API/Models/GruntTaskingType.cs` | Added enum values + serialization |
| `Models/Listeners/InternalListener.cs` | Pipe separator for Upload/Copy |
| `Components/Grunts/GruntCommandCard.razor` | Screenshot/Download display fix |
| `Components/Listeners/HttpListenerForm.razor` | URL index fix |
| `Data/Tasks/DefaultGruntTasks.yaml` | Added 6 new task definitions |

---

## Task Re-integration from Backups (December 16, 2025)

### 17. Lean Assembly Task (No SharpSploit Dependency)
**Problem:** Original Assembly task from `SharpSploit.Execution.yaml` had heavy SharpSploit dependency.

**Fix:** Created standalone Assembly task using only `System.Reflection`:

```csharp
public static string Execute(string AssemblyBytes, string AssemblyName, string Parameters = "")
{
    byte[] asmBytes = Convert.FromBase64String(AssemblyBytes);
    Assembly asm = Assembly.Load(asmBytes);
    string[] args = string.IsNullOrEmpty(Parameters) ? new string[0] : SplitArgs(Parameters);

    // Redirect Console output to OutputStream
    TextWriter realStdOut = Console.Out;
    StreamWriter stdOutWriter = new StreamWriter(OutputStream);
    Console.SetOut(stdOutWriter);

    // Invoke entry point
    MethodInfo entryPoint = asm.EntryPoint;
    object[] invokeParams = entryPoint.GetParameters().Length > 0 ? new object[] { args } : null;
    entryPoint.Invoke(null, invokeParams);

    // Restore console
    Console.SetOut(realStdOut);
    return "";
}
```

**Features:**
- Loads .NET assemblies from Base64-encoded bytes
- Redirects Console.Out/Error to task output stream
- Supports command-line arguments parsing with quote handling
- No external dependencies (pure System.Reflection)
- Compatible with Net35, Net40, Net48

**Files Modified:**
| File | Changes |
|------|---------|
| `Data/Tasks/DefaultGruntTasks.yaml` | Added lean assembly task definition |

**Current Command Count: 28 built-in + compiled commands**

---

### 18. Execution Tasks Suite (P/Invoke Implementations)
**Problem:** Original Execution tasks from `SharpSploit.Execution.yaml` had heavy SharpSploit/Rubeus dependencies.

**Fix:** Created standalone execution tasks using pure P/Invoke Win32 APIs:

| Task | P/Invoke APIs | Description |
|------|--------------|-------------|
| `shellrunas` | `CreateProcessWithLogonW`, `CreatePipe`, `ReadFile` | Execute shell command as another user |
| `runas` | `CreateProcessWithLogonW`, `CreatePipe`, `ReadFile` | Execute any program as another user |
| `shellcode` | `VirtualAlloc`, `CreateThread`, `WaitForSingleObject` | Execute shellcode in current process |
| `inject` | `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | Inject shellcode into remote process |
| `bypassamsi` | `GetModuleHandle`, `GetProcAddress`, `VirtualProtect` | Patch AMSI to disable scanning |
| `bypassetw` | `GetModuleHandle`, `GetProcAddress`, `VirtualProtect` | Patch ETW to disable tracing |
| `spawnas` | `CreateProcessWithLogonW` | Spawn new Grunt as another user |
| `impersonate` | `LogonUser`, `ImpersonateLoggedOnUser` | Impersonate user with credentials |
| `maketoken` | `LogonUser`, `ImpersonateLoggedOnUser` | Create token for network access |
| `rev2self` | `RevertToSelf` | Revert to original token |
| `stealtoken` | `OpenProcess`, `OpenProcessToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser` | Steal token from another process |
| `getsystem` | `CreateToolhelp32Snapshot`, `OpenProcessToken`, `DuplicateTokenEx` | Elevate to SYSTEM via token theft |

**Key P/Invoke Structures:**
```csharp
// Process creation
[DllImport("advapi32.dll")] CreateProcessWithLogonW()
[DllImport("kernel32.dll")] CreatePipe(), ReadFile()

// Shellcode execution
[DllImport("kernel32.dll")] VirtualAlloc(), VirtualAllocEx()
[DllImport("kernel32.dll")] WriteProcessMemory(), CreateRemoteThread()

// Token manipulation
[DllImport("advapi32.dll")] LogonUser(), ImpersonateLoggedOnUser()
[DllImport("advapi32.dll")] OpenProcessToken(), DuplicateTokenEx()
[DllImport("advapi32.dll")] RevertToSelf()

// Memory patching
[DllImport("kernel32.dll")] GetModuleHandle(), GetProcAddress()
[DllImport("kernel32.dll")] VirtualProtect()
```

**Features:**
- All 12 tasks use pure P/Invoke (no .NET security APIs)
- AMSI/ETW bypass with x86/x64 patch support
- Token manipulation for impersonation and privilege escalation
- Process injection with classic VirtualAllocEx/CreateRemoteThread
- GetSystem attempts multiple SYSTEM processes (winlogon, lsass, services)

**Files Modified:**
| File | Changes |
|------|---------|
| `Data/Tasks/DefaultGruntTasks.yaml` | Added 12 execution task definitions |

**Current Command Count: 40 built-in + compiled commands**

---

### 19. Built-in ExecuteAssembly Handler (No Server-Side Compilation)
**Problem:** Assembly task required server-side Roslyn compilation which needed complex reference assemblies.

**Fix:** Created built-in `ExecuteAssembly` TaskingType handled directly by the Grunt implant:

```csharp
// In GruntHTTP.cs - handles assembly execution directly
else if (message.Type == GruntTaskingType.ExecuteAssembly)
{
    string[] parts = message.Message.Split(new char[] { '|' }, 2);
    byte[] asmBytes = Convert.FromBase64String(parts[0]);
    string[] args = parts.Length > 1 ? SplitArgs(parts[1]) : new string[0];

    Assembly asm = Assembly.Load(asmBytes);
    // Capture console output, invoke entry point...
}
```

**Simplified Task Definition:**
```yaml
- Name: assembly
  TaskingType: ExecuteAssembly  # Built-in handler, no compilation
  Code: ''                       # No code to compile
  ReferenceAssemblies: []        # No references needed
  Options:
  - Name: AssemblyBytes          # Base64 assembly sent directly
    FileOption: true
  - Name: Parameters             # Optional arguments
```

**Benefits:**
- No server-side Roslyn compilation needed
- No reference assembly dependencies
- Assembly bytes sent directly to grunt and executed
- Same pattern as shell, powershell, upload, etc.

**Files Modified:**
| File | Changes |
|------|---------|
| `API/Models/GruntTaskingType.cs` | Added ExecuteAssembly enum + serialization |
| `Models/Grunts/GruntTasking.cs` | Added ExecuteAssembly enum |
| `Data/Grunt/GruntHTTP/GruntHTTP.cs` | Added ExecuteAssembly handler + SplitArgs |
| `Data/Grunt/GruntBridge/GruntBridge.cs` | Added ExecuteAssembly enum |
| `Data/Grunt/GruntSMB/GruntSMB.cs` | Added ExecuteAssembly enum |
| `Data/Grunt/Brute/Brute.cs` | Added ExecuteAssembly enum |
| `Models/Listeners/InternalListener.cs` | Pipe separator for ExecuteAssembly |
| `Data/Tasks/DefaultGruntTasks.yaml` | Simplified assembly task definition |

---

## Updated Testing Checklist

- [x] Server starts without errors
- [x] User can create account and login
- [x] Listener can be created and started
- [x] Launcher can be generated
- [x] Grunt stager executes and registers
- [x] Grunt appears in UI with Active status
- [x] Tasks are available when interacting with grunt
- [x] Task execution returns output to server
- [x] Screenshot captures and displays in Data section
- [x] Upload transfers files to target
- [x] Download retrieves files from target
- [x] File operations (mkdir, rm, cp) work correctly

### In Progress - Execution Tasks Testing
- [ ] `assembly` - Execute .NET assembly in memory (ExecuteAssembly built-in)
- [ ] `shellrunas` - Execute shell command as another user
- [ ] `runas` - Execute program as another user
- [ ] `shellcode` - Execute shellcode in current process
- [ ] `inject` - Inject shellcode into remote process
- [ ] `bypassamsi` - Patch AMSI
- [ ] `bypassetw` - Patch ETW
- [ ] `spawnas` - Spawn Grunt as another user
- [ ] `impersonate` - Impersonate user token
- [ ] `maketoken` - Create network token
- [ ] `rev2self` - Revert to original token
- [ ] `stealtoken` - Steal token from process
- [ ] `getsystem` - Elevate to SYSTEM
