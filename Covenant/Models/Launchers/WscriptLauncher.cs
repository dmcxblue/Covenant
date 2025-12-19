// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System.Linq;
using Microsoft.CodeAnalysis;

using Covenant.Models.Listeners;

namespace Covenant.Models.Launchers
{
    public class WscriptLauncher : ScriptletLauncher
    {
        public WscriptLauncher()
        {
            this.Name = "Wscript";
            this.Type = LauncherType.Wscript;
            this.Description = "Uses wscript.exe to launch a Grunt using Activation Context (ActCtx) to instantiate .NET objects. This technique bypasses COM restrictions on newer Windows versions.";
            this.ScriptType = ScriptletType.Plain;
            this.OutputKind = OutputKind.DynamicallyLinkedLibrary;
            this.CompressStager = false;
        }

        protected override string GetLauncher()
        {
            string ext = this.ScriptLanguage == ScriptingLanguage.JScript ? ".js" : ".vbs";
            string launcher = "wscript" + " " + "file" + ext;
            this.LauncherString = launcher;
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
                string launcher = "wscript" + " " + hostedFile.Path.Split('/').Last();
                this.LauncherString = launcher;
                return launcher;
            }
            return "";
        }
    }
}
