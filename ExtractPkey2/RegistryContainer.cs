using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace ExtractPkey
{
    class RegistryContainer : Container
    {
        private readonly string _containerName;

        public RegistryContainer(string containerName, string pin)
            : base(pin)
        {
            _containerName = containerName;
        }

        protected override Container.Data LoadContainerData()
        {
            var keyName = GetCurrentUserKeyName(_containerName);
            using (var key = Registry.LocalMachine.OpenSubKey(keyName)) {
                return new Container.Data
                {
                    Header = (byte[])key.GetValue("header.key"),
                    Masks = (byte[])key.GetValue("masks.key"),
                    Masks2 = (byte[])key.GetValue("masks2.key"),
                    Name = (byte[])key.GetValue("name.key"),
                    Primary = (byte[])key.GetValue("primary.key"),
                    Primary2 = (byte[])key.GetValue("primary2.key")
                };
            }
        }

        private static string GetCurrentUserKeyName(string containerName)
        {
            string sid = WindowsIdentity.GetCurrent().User.Value;
            string node = Environment.Is64BitOperatingSystem ? "Wow6432Node\\" : "";
            return String.Format(@"SOFTWARE\{0}Crypto Pro\Settings\Users\{1}\Keys\{2}", node, sid, containerName);
        }
    }
}
