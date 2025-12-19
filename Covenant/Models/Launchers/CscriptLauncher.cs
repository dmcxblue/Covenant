// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using Covenant.Models.Listeners;

namespace Covenant.Models.Launchers
{
    public class CscriptLauncher : ScriptletLauncher
    {
        public CscriptLauncher()
        {
            this.Name = "Cscript";
            this.Type = LauncherType.Cscript;
            this.Description = "Uses cscript.exe to launch a Grunt using Activation Context (ActCtx) to instantiate .NET objects. This technique bypasses COM restrictions on newer Windows versions.";
            this.ScriptType = ScriptletType.Plain;
            this.OutputKind = OutputKind.DynamicallyLinkedLibrary;
            this.CompressStager = false;
        }

        protected override string GetLauncher()
        {
            string ext = this.ScriptLanguage == ScriptingLanguage.JScript ? ".js" : ".vbs";
            string launcher = "cscript" + " " + "file" + ext;
            this.LauncherString = launcher;
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
                string launcher = "cscript" + " " + hostedFile.Path.Split('/').Last();
                this.LauncherString = launcher;
                return launcher;
            }
            else { return ""; }
        }
    }
}
