using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ExtractCert
{
    class FolderContainer : Container
    {
        private readonly string _folderName;

        public FolderContainer(string folderName, string pin)
            : base(pin)
        {
            _folderName = folderName;
        }

        protected override Container.Data LoadContainerData()
        {
            return new Container.Data
            {
                Header = File.ReadAllBytes(Path.Combine(_folderName, "header.key")),
                Masks = File.ReadAllBytes(Path.Combine(_folderName, "masks.key")),
                Masks2 = File.ReadAllBytes(Path.Combine(_folderName, "masks2.key")),
                Name = File.ReadAllBytes(Path.Combine(_folderName, "name.key")),
                Primary = File.ReadAllBytes(Path.Combine(_folderName, "primary.key")),
                Primary2 = File.ReadAllBytes(Path.Combine(_folderName, "primary2.key")),
            };
        }
    }
}
